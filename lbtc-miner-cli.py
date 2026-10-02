#!/usr/bin/env python3

import argparse
import base64
import getpass
import hashlib
import json
import multiprocessing as mp
import os
import sys
import time

import requests
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from ecdsa import SigningKey, SECP256k1


COIN = 100_000_000
BASE_REWARD = 50 * COIN
HALVING_INTERVAL = 210_000
DESIRED_BLOCK_TIME = 180

DATA_DIR = os.path.join(os.path.expanduser("~"), "LBTC")
DEFAULT_NODE = "http://139.59.190.254:8080"
DEFAULT_WALLET = os.path.join(DATA_DIR, "wallet_gui.json")


def next_difficulty_smooth(chain, target_time=180):
    if not chain:
        return format(2 ** 232, "064x")

    tip = chain[-1].get("difficulty", "")
    if not tip:
        return format(2 ** 232, "064x")

    try:
        current = (
            int(tip, 16)
            if len(tip) > 16
            else int(tip + "f" * (64 - len(tip)), 16)
        )
    except Exception:
        current = 2 ** 232

    if len(chain) < 2:
        return format(current, "064x")

    recent = chain[-9:]
    times = []

    for i in range(1, len(recent)):
        dt = recent[i]["timestamp"] - recent[i - 1]["timestamp"]
        if dt > 0:
            times.append(dt)

    if not times:
        return format(current, "064x")

    ema = times[0]

    for dt in times[1:]:
        ema = 0.3 * dt + 0.7 * ema

    age = time.time() - chain[-1].get("timestamp", 0)


    ratio = max(0.90, min(1.10, ema / target_time))
    nt = int(current * ratio)
    nt = max(2 ** 220, min(2 ** 252, nt))

    return format(nt, "064x")


def decrypt_private_key(enc, password):
    salt = base64.b64decode(enc["salt"])
    nonce = base64.b64decode(enc["nonce"])
    ct = base64.b64decode(enc["ct"])

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=600000,
    )

    key = kdf.derive(password.encode())
    return AESGCM(key).decrypt(nonce, ct, None)


def address_from_vk(vk):
    alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

    pub = vk.to_string()
    sha = hashlib.sha256(pub).digest()

    h = hashlib.new("ripemd160")
    h.update(sha)
    ripe = h.digest()

    payload = b"\x00" + ripe
    checksum = hashlib.sha256(
        hashlib.sha256(payload).digest()
    ).digest()[:4]

    data = payload + checksum
    num = int.from_bytes(data, "big")

    result = ""

    while num:
        num, rem = divmod(num, 58)
        result = alphabet[rem] + result

    for byte in data:
        if byte == 0:
            result = "1" + result
        else:
            break

    return result


def load_wallet(wallet_file):
    with open(wallet_file, "r") as f:
        wallet = json.load(f)

    if "encrypted" not in wallet:
        raise RuntimeError("La wallet no contiene una clave cifrada.")

    password = getpass.getpass("Password de la wallet: ")

    private_key = decrypt_private_key(
        wallet["encrypted"],
        password,
    )

    sk = SigningKey.from_string(
        private_key,
        curve=SECP256k1,
    )

    vk = sk.get_verifying_key()
    derived_address = address_from_vk(vk)

    stored_address = wallet.get("address")

    if stored_address != derived_address:
        raise RuntimeError(
            "ERROR: la contraseña o la wallet no coinciden."
        )

    return sk, derived_address


def worker_mine(
    worker_id,
    workers,
    prefix,
    suffix,
    target,
    stop_event,
    result_queue,
    stats_queue,
):
    """
    Worker SHA-256 optimizado.

    Cada proceso trabaja con:
        worker_id, worker_id + workers, ...

    La parte fija del bloque se hashea una sola vez y luego
    se reutiliza mediante hashlib.copy().
    """

    prefix_bytes = prefix.encode()
    suffix_bytes = suffix.encode()
    target = target.lower()

    # Precalcular el estado SHA256 de toda la parte fija
    # anterior al nonce.
    base_hash = hashlib.sha256(prefix_bytes)

    nonce = worker_id
    local_count = 0

    # Reportar pocas veces para no introducir overhead
    REPORT_EVERY = 2_000_000

    # Localizar métodos para reducir búsquedas de atributos
    sha256 = hashlib.sha256
    put_stats = stats_queue.put_nowait
    put_result = result_queue.put
    is_set = stop_event.is_set

    while not is_set():

        # Crear una copia del estado SHA256 ya preparado.
        h = base_hash.copy()

        # Exactamente:
        # prefix + nonce + suffix
        h.update(str(nonce).encode())
        h.update(suffix_bytes)

        block_hash = h.hexdigest()

        local_count += 1

        if block_hash < target:
            if not is_set():
                put_result((nonce, block_hash))
                stop_event.set()

            return

        nonce += workers

        if local_count >= REPORT_EVERY:
            try:
                put_stats(local_count)
            except Exception:
                pass

            local_count = 0

    if local_count:
        try:
            put_stats(local_count)
        except Exception:
            pass

def mine_nonce(block, workers, node):
    stop_event = mp.Event()
    result_queue = mp.Queue()
    stats_queue = mp.Queue()

    # EXACTAMENTE la misma serialización utilizada por LBTC V51.
    base = json.dumps(
        {**block, "nonce": 0},
        sort_keys=True,
    )

    marker = '"nonce": 0'

    if marker not in base:
        raise RuntimeError(
            "No se pudo preparar el bloque para minería."
        )

    head, tail = base.split(marker, 1)

    prefix = head + '"nonce": '
    suffix = tail

    processes = []

    for worker_id in range(workers):
        p = mp.Process(
            target=worker_mine,
            args=(
                worker_id,
                workers,
                prefix,
                suffix,
                block["difficulty"],
                stop_event,
                result_queue,
                stats_queue,
            ),
        )

        p.start()
        processes.append(p)

    start = time.time()
    total_hashes = 0
    last_report = start

    found = None

    while found is None:
        try:
            nonce, block_hash = result_queue.get(timeout=0.5)
            found = (nonce, block_hash)
        except Exception:
            pass

        while True:
            try:
                total_hashes += stats_queue.get_nowait()
            except Exception:
                break

        now = time.time()

        # Comprobar si la red avanzo mientras estamos minando.
        # Si aparece un bloque nuevo, abandonar inmediatamente
        # este trabajo y construir un template nuevo.
        if now - last_report >= 2:
            try:
                r = requests.get(
                    node.rstrip("/") + "/api/chain",
                    timeout=5,
                )
                r.raise_for_status()
                data = r.json()

                if isinstance(data, dict):
                    current_chain = data.get("chain", data)
                else:
                    current_chain = data

                current_chain = list(current_chain)

                if current_chain:
                    current_height = max(
                        b["index"] for b in current_chain
                    )

                    if current_height >= block["index"]:
                        print(
                            f"\n[CAMBIO] La red ya esta en "
                            f"{current_height}; "
                            f"este trabajo era {block['index']}. "
                            f"Actualizando..."
                        )
                        stop_event.set()
                        break

            except Exception:
                pass

        if now - last_report >= 5:
            elapsed = now - start

            if elapsed > 0:
                rate = total_hashes / elapsed

                print(
                    f"\r[MINANDO] "
                    f"{rate / 1000:.2f} KH/s | "
                    f"{total_hashes:,} hashes",
                    end="",
                    flush=True,
                )

            last_report = now

        if stop_event.is_set() and found is None:
            try:
                found = result_queue.get(timeout=1)
            except Exception:
                break

    stop_event.set()

    for p in processes:
        p.join(timeout=2)

    for p in processes:
        if p.is_alive():
            p.terminate()
            p.join()

    print()

    if found is None:
        return None

    nonce, block_hash = found

    elapsed = time.time() - start

    print(
        f"[ENCONTRADO] nonce={nonce} "
        f"hash={block_hash}"
    )

    if elapsed > 0:
        print(
            f"[RENDIMIENTO] "
            f"{total_hashes / elapsed / 1000:.2f} KH/s"
        )

    return nonce, block_hash


class LBTCMiner:

    def __init__(self, node, wallet_file, workers):
        self.node = node.rstrip("/")
        self.wallet_file = wallet_file
        self.workers = workers

        self.session = requests.Session()

        self.sk = None
        self.address = None

    def wallet(self):
        self.sk, self.address = load_wallet(
            self.wallet_file
        )

        print(f"[WALLET] {self.address}")

    def get_chain(self):
        r = self.session.get(
            self.node + "/api/chain",
            timeout=20,
        )
        r.raise_for_status()

        data = r.json()

        if isinstance(data, dict):
            chain = data.get("chain", data)
        else:
            chain = data

        chain = list(chain)
        chain.sort(key=lambda x: x["index"])

        return chain

    def get_mempool(self):
        try:
            r = self.session.get(
                self.node + "/api/mempool",
                timeout=10,
            )

            if r.status_code != 200:
                return []

            data = r.json()

            if isinstance(data, dict):
                return data.get("transactions", [])

            return data

        except Exception:
            return []

    def get_balance(self):
        r = self.session.get(
            self.node + "/api/balance/" + self.address,
            timeout=15,
        )

        r.raise_for_status()

        data = r.json()

        if isinstance(data, dict):
            balance = data.get(
                "balance",
                data.get("confirmed", 0),
            )
        else:
            balance = data

        return balance

    def reward(self, height):
        hv = height // HALVING_INTERVAL
        return BASE_REWARD // (2 ** hv)

    def submit_block(self, block):
        message = (
            f"BLOCK|{block['index']}|"
            f"{block['hash']}|{self.address}"
        )

        signature = self.sk.sign(
            message.encode(),
            hashfunc=hashlib.sha256,
        ).hex()

        public_key = self.sk.get_verifying_key().to_string().hex()

        headers = {
            "X-Block-Signature": signature,
            "X-Block-Pubkey": public_key,
        }

        r = self.session.post(
            self.node + "/api/block",
            json=block,
            headers=headers,
            timeout=30,
        )

        print(
            f"[NODE] HTTP {r.status_code}"
        )

        try:
            data = r.json()
            print(f"[NODE] {data}")
        except Exception:
            print(r.text[:500])

        return (
            r.status_code == 200
            and isinstance(r.json(), dict)
            and r.json().get("status") == "ok"
        )

    def mine_once(self):
        chain = self.get_chain()

        if not chain:
            raise RuntimeError(
                "El nodo devolvió una cadena vacía."
            )

        mempool = self.get_mempool()

        existing_txids = set()

        for block in chain:
            for tx in block.get("transactions", []):
                txid = tx.get("txid") or tx.get("id")

                if txid:
                    existing_txids.add(txid)

        transactions = []

        for tx in mempool:
            txid = tx.get("txid") or tx.get("id")

            if txid and txid in existing_txids:
                continue

            transactions.append(tx)

        last_block = chain[-1]

        index = last_block["index"] + 1
        timestamp = int(time.time())

        previous_hash = last_block["hash"]

        difficulty = next_difficulty_smooth(
            chain,
            DESIRED_BLOCK_TIME,
        )

        total_fees = sum(
            int(tx.get("fee", 0))
            for tx in transactions
        )

        reward = self.reward(index)

        coinbase = {
            "sender": "coinbase",
            "recipient": self.address,
            "amount": reward + total_fees,
            "fee": total_fees,
            "timestamp": timestamp,
        }

        block_transactions = [
            coinbase
        ] + transactions

        block = {
            "index": index,
            "timestamp": timestamp,
            "transactions": block_transactions,
            "previous_hash": previous_hash,
            "nonce": 0,
            "difficulty": difficulty,
        }

        print()
        print("=" * 60)
        print(f"ALTURA     : {index}")
        print(f"DIFICULTAD : {difficulty}")
        print(f"RECOMPENSA : {reward / COIN:.8f} LBTC")
        print(f"TX         : {len(block_transactions)}")
        print(f"PROCESOS   : {self.workers}")
        print("=" * 60)

        result = mine_nonce(
            block,
            self.workers,
            self.node,
        )

        if result is None:
            return False

        nonce, block_hash = result

        block["nonce"] = nonce
        block["hash"] = block_hash

        print(
            f"[BLOQUE] {block_hash}"
        )

        return self.submit_block(block)

    def run(self):
        self.wallet()

        try:
            balance = self.get_balance()
            print(
                f"[BALANCE] {balance}"
            )
        except Exception as e:
            print(
                f"[BALANCE] no disponible: {e}"
            )

        print(
            f"[NODE] {self.node}"
        )

        while True:
            try:
                accepted = self.mine_once()

                if accepted:
                    print(
                        "[OK] BLOQUE ACEPTADO"
                    )
                else:
                    print(
                        "[INFO] Bloque rechazado; "
                        "actualizando cadena..."
                    )

                time.sleep(2)

            except KeyboardInterrupt:
                print("\n[STOP]")
                return

            except Exception as e:
                print(
                    f"[ERROR] {e}"
                )
                time.sleep(5)


def main():
    parser = argparse.ArgumentParser(
        description="LBTC SHA-256 multiprocess CLI Miner"
    )

    parser.add_argument(
        "--threads",
        type=int,
        default=0,
        help="Numero de procesos de mineria. 0 = todos los CPUs",
    )

    parser.add_argument(
        "--node",
        default=DEFAULT_NODE,
    )

    parser.add_argument(
        "--wallet",
        default=DEFAULT_WALLET,
    )

    args = parser.parse_args()

    cpu_count = os.cpu_count() or 1

    workers = args.threads

    if workers <= 0:
        workers = cpu_count

    if workers > cpu_count:
        workers = cpu_count

    print(
        f"CPU disponibles : {cpu_count}"
    )

    print(
        f"Procesos LBTC   : {workers}"
    )

    miner = LBTCMiner(
        args.node,
        args.wallet,
        workers,
    )

    miner.run()


if __name__ == "__main__":
    mp.freeze_support()
    main()
