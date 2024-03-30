import sys
import threading
import hashlib
from os import system, name
from time import time
from colorama import Style
import bcrypt

title_text = "HASHCRACK v2.4"

args = sys.argv


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


def crack_hash(hash_value, print_current=False, hash_algorithm="sha256"):
    try:
        print_to_screen(combine_strings(title_text + "\n", "Cracking hash: " + hash_value, "Hash Algorithm: " + hash_algorithm))

        hasher = globals().get("calculate_hash_" + hash_algorithm, calculate_hash_sha256)

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

                    if print_current:
                        print_to_screen(combine_strings(title_text + "\n", "Cracking hash: " + hash_value, "Currently trying: " + current_try, "Currently trying (hashed): " + current_try_hashed, "Time elapsed: " + str(round(time() - start_time, 2)) + " seconds", "Attempts: " + str(attempts), "Speed: " + str(round(attempts / round(time() - start_time + 0.1, 2))) + " hashes / second", "Hash algorithm: " + hash_algorithm))

                    if hash_value == current_try_hashed:
                        cracked = current_try
                        result = cracked
                        return

        num_threads = 6
        max_attempts = 94 ** 6
        batch_size = max_attempts // num_threads
        hash_generator = iter(range(max_attempts))
        lock = threading.Lock()

        threads = []
        for _ in range(num_threads):
            thread = threading.Thread(target=batch_worker)
            threads.append(thread)
            thread.start()

        for thread in threads:
            thread.join()

        if result is not None:
            cracked = result

            print_to_screen(combine_strings(title_text + "\n", "Cracked hash: " + hash_value, "Cracked: " + cracked, "Time elapsed: " + str(round(time() - start_time, 3)) + " seconds", "Attempts: " + str(attempts), "Speed: " + str(round(attempts / (time() - start_time + 0.1), 2)) + " hashes / second", "Hash algorithm: " + hash_algorithm))
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

if mode == "c":
    crack_hash(hash_value, show_info, hash_algorithm)
elif mode == "h":
    print_to_screen(combine_strings(title_text + "\n", "Text to hash: " + hash_text, "Hash: " + globals().get("calculate_hash_" + hash_algorithm, calculate_hash_sha256)(hash_text), "Hash algorithm: " + hash_algorithm + "\n"))
else:
    print_to_screen(combine_strings(title_text + " Usage\n", "<program> [-c or --crack] <hash> [-a or --algorithm] <hash algorithm> [-si or --show-info]", "'-c / --crack' - Crack hash", "'-a / --algorithm' - Hash algorithm (sha256, md5, sha1, bcrypt, sha512)", "'-si / --show-info' - Show current information (dynamically updating - slows down a lot)\n", "<program> [-h or --hash] <text to hash> [-a or --algorithm] <hash algorithm>", "'-h / --hash' - Hash text", "'-a / --algorithm' - Hash algorithm (sha256, md5, sha1, bcrypt, sha512)"))
