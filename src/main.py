import sys
import threading
import hashlib
from os import system, name
from time import time
from colorama import Style
import bcrypt

title_text = "----HASHCRACK v1.0----"

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


def crack_hash(hash_value, print_current=False, hash_function=calculate_hash_sha256):
    start_time = time()
    result = None
    tried_hashes = []
    attempts = 0

    def batch_worker():
        nonlocal attempts
        nonlocal result
        nonlocal tried_hashes
        nonlocal print_current

        while True:
            with lock:
                batch_start = next(hash_generator)
                batch_end = min(batch_start + batch_size, max_attempts)

            for i in range(batch_start, batch_end):
                if not result == None:
                    return

                if i in tried_hashes:
                    continue

                attempts += 1
                current_try_hashed = hash_function(number_to_text(i))
                current_try = number_to_text(i)

                if print_current:
                    print_to_screen(
                        combine_strings(
                            title_text,
                            "Cracking hash: " + hash_value,
                            "Currently trying: " + current_try,
                            "Currently trying (hashed): " + current_try_hashed,
                            "Time elapsed: "
                            + str(round(time() - start_time, 2))
                            + " seconds",
                            "Attempts: " + str(attempts),
                            "Speed: "
                            + str(round(attempts / round(time() - start_time + 0.1, 2)))
                            + " hashes / second",
                        )
                    )

                if hash_value == current_try_hashed:
                    cracked = current_try
                    result = cracked
                    return
                else:
                    tried_hashes.append(current_try_hashed)

    num_threads = 6
    max_attempts = 10**7  # Adjust this based on your requirements
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

    if not result == None:
        cracked = result

        print_to_screen(
            combine_strings(
                title_text,
                "Cracked hash: " + hash_value,
                "Cracked: " + cracked,
                "Time elapsed: " + str(round(time() - start_time, 2)) + " seconds",
                "Attempts: " + str(attempts),
                "Speed: "
                + str(round(attempts / (time() - start_time + 0.1), 2))
                + " hashes / second",
            )
        )


if len(args) > 2:
    if args[1] == "-c":
        if len(args) > 4:
            if args[3] == "-sc":
                crack_hash(args[2], True)
            elif args[3] == "-ha" and len(args) > 4:
                if len(args) > 5 and args[5] == "-sc":
                    if args[4] == "sha256":
                        crack_hash(args[2], True, calculate_hash_sha256)
                    elif args[4] == "md5":
                        crack_hash(args[2], True, calculate_hash_md5)
                    elif args[4] == "sha1":
                        crack_hash(args[2], True, calculate_hash_sha1)
                    elif args[4] == "bcrypt":
                        crack_hash(args[2], True, calculate_hash_bcrypt)

                if args[4] == "sha256":
                    crack_hash(args[2], False, calculate_hash_sha256)
                elif args[4] == "md5":
                    crack_hash(args[2], False, calculate_hash_md5)
                elif args[4] == "sha1":
                    crack_hash(args[2], False, calculate_hash_sha1)
                elif args[4] == "bcrypt":
                    crack_hash(args[2], False, calculate_hash_bcrypt)
        else:
            crack_hash(args[2], False)
    elif args[1] == "-h":
        if len(args) > 4 and args[3] == "-ha":
            if args[4] == "sha256":
                print_to_screen(
                    combine_strings(
                        title_text,
                        "Text to hash: " + args[2],
                        "Hash: " + calculate_hash_sha256(args[2]) + "\n",
                    )
                )
            elif args[4] == "md5":
                print_to_screen(
                    combine_strings(
                        title_text,
                        "Text to hash: " + args[2],
                        "Hash: " + calculate_hash_md5(args[2]) + "\n",
                    )
                )

            elif args[4] == "sha1":
                print_to_screen(
                    combine_strings(
                        title_text,
                        "Text to hash: " + args[2],
                        "Hash: " + calculate_hash_sha1(args[2]) + "\n",
                    )
                )

            elif args[4] == "bcrypt":
                print_to_screen(
                    combine_strings(
                        title_text,
                        "Text to hash: " + args[2],
                        "Hash: " + calculate_hash_bcrypt(args[2]) + "\n",
                    )
                )
        else:
            print_to_screen(
                combine_strings(
                    title_text,
                    "Text to hash: " + args[2],
                    "Hash: " + calculate_hash_sha256(args[2]) + "\n",
                )
            )
else:
    print("Usage:\n<program> -c <hash>\n<program> -h <text>")
