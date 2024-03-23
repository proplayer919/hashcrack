import sys
import threading
import hashlib
from os import system, name
from time import time
from colorama import Style
import bcrypt

title_text = "HASHCRACK v2.0"

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


formattedArgs = []
mode = None

for arg in args:
    if arg.startswith("-"):
        if not args[args.index(arg) + 1 % len(args)].startswith("-"):
            formattedArgs.append([arg, args[args.index(arg) + 1]])
        else:
            formattedArgs.append([arg])
    else:
        continue

for arg in formattedArgs:
    if arg[0] == "-c" or arg[0] == "--crack":
        hash_value = arg[1]
        mode = "c"
        
    if arg[0] == "-a" or arg[0] == "--algorithm":
        hash_algorithm = arg[1]
    else:
        hash_algorithm = "sha256"
        
    if arg[0] == "-h" or arg[0] == "--hash":
        hash_text = arg[1]
        mode = "h"
        
    if arg[0] == "-si" or arg[0] == "--show-info":
        show_info = True
    else:
        show_info = False

if mode == "c":
    crack_hash(
        hash_value, show_info, globals()["calculate_hash_" + hash_algorithm]
    )
elif mode == "h":
    print_to_screen(
        combine_strings(
            title_text,
            "Text to hash: " + hash_text,
            "Hash: " + globals()["calculate_hash_" + hash_algorithm](hash_text) + "\n",
        )
    )
else:
    print_to_screen(
        combine_strings(
            title_text + " Usage\n",
            "<program> [-c or --crack] <hash> [-a or --algorithm] <hash algorithm> [-si or --show-info]",
            "'-c / --crack' - Crack hash",
            "'-a / --algorithm' - Hash algorithm (sha256, md5, sha1, bcrypt)",
            "'-si / --show-info' - Show current information (dynamically updating - slows down a lot)\n",
            "<program> [-h or --hash] <text to hash> [-a or --algorithm] <hash algorithm>",
            "'-h / --hash' - Hash text",
            "'-a / --algorithm' - Hash algorithm (sha256, md5, sha1, bcrypt)",
        )
    )
