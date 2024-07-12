import sys
import threading
import hashlib
from os import system, name, path
import os
from time import time
from colorama import Style
import bcrypt
import json
import pyzipper
import itertools
import string
from numba import cuda

num_threads = 6

title_text = "HASHCRACK v2.5"

hashes_location = "precomputed_hashes.json"

precomputed_hashes = (
    json.load(open(hashes_location, "r")) if path.exists(hashes_location) else {}
)

for hash_algorithm in ["md5", "sha256", "sha1", "bcrypt", "sha512"]:
    if hash_algorithm not in precomputed_hashes:
        precomputed_hashes[hash_algorithm] = {}

args = sys.argv

def update_hashes():
    json.dump(precomputed_hashes, open(hashes_location, "w"))


def clear_screen():
    if name == "nt":
        system("cls")
    else:
        system("clear")


def calculate_hash_sha256(text):
    return hashlib.sha256(text.encode()).hexdigest()


def calculate_hash_md5(text):
    return hashlib.md5(text.encode()).hexdigest()


def calculate_hash_sha1(text):
    return hashlib.sha1(text.encode()).hexdigest()


def calculate_hash_bcrypt(text):
    return bcrypt.hashpw(text.encode(), bcrypt.gensalt()).hex()


def calculate_hash_sha512(text):
    return hashlib.sha512(text.encode()).hexdigest()


def print_to_screen(text):
    sys.stdout.write("\033[H\033[J")
    sys.stdout.write(text + Style.RESET_ALL)
    sys.stdout.flush()


def combine_strings(*args):
    return "\n".join(args)


def number_to_text(number):
    base = ord("!")
    chars = []
    while number:
        number, remainder = divmod(number, 94)
        chars.append(chr(base + remainder))
    return "".join(reversed(chars))


def attempt_password(zip_file, password):
    try:
        with pyzipper.AESZipFile(zip_file) as zf:
            try:
                zf.extractall(pwd=password.encode())

                print_to_screen(
                    combine_strings(
                        title_text + "\n",
                        "Cracked ZIP: " + zip_file,
                        "Password: " + password,
                    )
                )

                zf.close()

                return True
            except Exception:
                return False
    except Exception:
        return False


def password_generator(length):
    chars = string.ascii_letters + string.digits
    for password in itertools.product(chars, repeat=length):
        yield "".join(password)


def crack_zip(zip_file, max_password_length):
    def worker(zip_file, passwords):
        for password in passwords:
            if attempt_password(zip_file, password):
                return

    for length in range(1, max_password_length + 1):
        passwords = password_generator(length)
        chunk_size = 1000
        while True:
            chunk = list(itertools.islice(passwords, chunk_size))
            if not chunk:
                break
            threads = []
            for i in range(num_threads):
                thread_passwords = chunk[i::num_threads]
                t = threading.Thread(target=worker, args=(zip_file, thread_passwords))
                threads.append(t)
                t.start()
            for t in threads:
                t.join()


def crack_hash(hash_value, print_current=False, hash_algorithm="sha256"):
    try:
        if hash_value in precomputed_hashes[hash_algorithm]:
            print_to_screen(
                combine_strings(
                    title_text + "\n",
                    "Cracked hash: " + hash_value,
                    "Cracked: " + precomputed_hashes[hash_algorithm][hash_value],
                    "Hash algorithm: " + hash_algorithm,
                    "This hash was precomputed and was cracked instantly.",
                )
            )
            return

        print_to_screen(
            combine_strings(
                title_text + "\n",
                "Cracking hash: " + hash_value,
                "Hash Algorithm: " + hash_algorithm,
            )
        )

        hasher = globals().get(
            "calculate_hash_" + hash_algorithm, calculate_hash_sha256
        )

        start_time = time()
        result = None
        tried_hashes = []
        attempts = 0

        def batch_worker():
            nonlocal attempts, result, tried_hashes, hasher

            while True:
                with lock:
                    batch_start = next(hash_generator)
                    batch_end = min(batch_start + batch_size, max_attempts)

                for i in range(batch_start, batch_end):
                    if result is not None:
                        return

                    if i in tried_hashes:
                        continue

                    tried_hashes.append(i)

                    attempts += 1
                    current_try = number_to_text(i)

                    current_try_hashed = hasher(current_try)
                    precomputed_hashes[hash_algorithm][current_try] = current_try_hashed

                    if print_current:
                        print_to_screen(
                            combine_strings(
                                title_text + "\n",
                                "Cracking hash: " + hash_value,
                                "Currently trying: " + current_try,
                                "Currently trying (hashed): " + current_try_hashed,
                                "Time elapsed: "
                                + str(round(time() - start_time, 2))
                                + " seconds",
                                "Attempts: " + str(attempts),
                                "Speed: "
                                + str(
                                    round(
                                        attempts / round(time() - start_time + 0.1, 2)
                                    )
                                )
                                + " hashes / second",
                                "Hash algorithm: " + hash_algorithm,
                            )
                        )

                    if hash_value == current_try_hashed:
                        cracked = current_try
                        result = cracked
                        return

        max_attempts = 94**6
        batch_size = max_attempts // num_threads
        hash_generator = iter(range(max_attempts))
        lock = threading.Lock()

        # Check if CUDA is available and define the CUDA kernel
        use_cuda = cuda.is_available()

        if use_cuda:

            @cuda.jit
            def cuda_batch_worker(start, end, hash_value):
                nonlocal attempts, result, tried_hashes, hasher
                idx = cuda.grid(1)
                if start + idx < end:
                    current_try = number_to_text(start + idx)
                    current_try_hashed = hasher(current_try)
                    if hash_value == current_try_hashed:
                        result = current_try
                    attempts += 1

            threads_per_block = 128
            blocks_per_grid = (
                batch_size + (threads_per_block - 1)
            ) // threads_per_block

            for batch_start in range(0, max_attempts, batch_size):
                batch_end = min(batch_start + batch_size, max_attempts)
                result = [None]
                attempts = [0]
                cuda_batch_worker[blocks_per_grid, threads_per_block](
                    batch_start, batch_end, hash_value
                )
                if result is not None:
                    break
        else:
            threads = []
            for _ in range(num_threads):
                thread = threading.Thread(target=batch_worker)
                threads.append(thread)
                thread.start()
            for thread in threads:
                thread.join()

        if result is not None:
            cracked = result

            print_to_screen(
                combine_strings(
                    title_text + "\n",
                    "Cracked hash: " + hash_value,
                    "Cracked: " + cracked,
                    "Time elapsed: " + str(round(time() - start_time, 3)) + " seconds",
                    "Attempts: " + str(attempts),
                    "Speed: "
                    + str(round(attempts / (time() - start_time + 0.1), 2))
                    + " hashes / second",
                    "Hash algorithm: " + hash_algorithm,
                )
            )

            return
    except Exception as e:
        print_to_screen(f"Error: {str(e)}")


formattedArgs = []
mode = None

for arg in args:
    if arg is None:
        raise ValueError("arg cannot be None")

    if arg.startswith("-"):
        if args.index(arg) + 1 < len(args):
            formattedArgs.append([arg, args[args.index(arg) + 1]])
        else:
            formattedArgs.append([arg])
    else:
        continue

for arg in formattedArgs:
    if arg[0] in ("-c", "--crack"):
        hash_value = arg[1]
        mode = "c"
    elif arg[0] in ("-z", "--zip"):
        zip_file = arg[1]
        mode = "z"
    elif arg[0] in ("-h", "--hash"):
        hash_text = arg[1]
        mode = "h"

    if arg[0] in ("-a", "--algorithm"):
        hash_algorithm = arg[1]
    else:
        hash_algorithm = "sha256"

    if arg[0] in ("-si", "--show-info"):
        show_info = True
    else:
        show_info = False

    if arg[0] in ("-m", "--max-password-length"):
        max_password_length = int(arg[1])
    else:
        max_password_length = 32

if mode == "c":
    crack_hash(hash_value, show_info, hash_algorithm)
elif mode == "z":
    crack_zip(zip_file, max_password_length)
elif mode == "h":
    hash = globals().get("calculate_hash_" + hash_algorithm, calculate_hash_sha256)(
        hash_text
    )
    print_to_screen(
        combine_strings(
            title_text + "\n",
            "Text to hash: " + hash_text,
            "Hash: " + hash,
            "Hash algorithm: " + hash_algorithm + "\n",
        )
    )

    if not hash in precomputed_hashes[hash_algorithm]:
        precomputed_hashes[hash_algorithm][hash] = hash_text
else:
    print_to_screen(
        combine_strings(
            title_text + " Usage\n",
            "<program> [-c or --crack] <hash> [-a or --algorithm] <hash algorithm> [-si or --show-info]",
            "'-c / --crack' - Crack hash",
            "'-a / --algorithm' - Hash algorithm (sha256, md5, sha1, bcrypt, sha512)",
            "'-si / --show-info' - Show current information (dynamically updating - slows down a lot)\n",
            "<program> [-z or --zip] <path to zip> [-m or --max-password_length] <max password length>",
            "'-z / --zip' - Zip path",
            "'-m / --max-password_length' - Max password length\n",
            "<program> [-h or --hash] <text to hash> [-a or --algorithm] <hash algorithm>",
            "'-h / --hash' - Hash text",
            "'-a / --algorithm' - Hash algorithm (sha256, md5, sha1, bcrypt, sha512)",
        )
    )

update_hashes()
