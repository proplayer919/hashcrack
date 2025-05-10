import sys
import threading
import hashlib
import os
import time
import json
import itertools
import string
import argparse
import bcrypt  # Keep for hashing, but note limitations for cracking
import pyzipper  # For ZIP cracking
import binascii  # For NTLM
import platform  # To get system info
import math  # For ceiling in estimation

# --- Configuration ---
# Number of threads to use for cracking tasks
NUM_THREADS = 6

# File to store precomputed hashes
PRECOMPUTED_HASHES_FILE = "precomputed_hashes.json"

# Default character set for brute-force cracking (alphanumeric + common symbols)
# You can customize this based on expected password complexity
DEFAULT_CHARSET = string.ascii_letters + string.digits + string.punctuation

# Basic mutation rules for dictionary attacks
# Each rule is a function that takes a password string and returns a modified string or a list of strings
# Add more complex rules here as needed
MUTATION_RULES = {
    "append_digit": lambda p: [
        p + str(d) for d in range(10)
    ],  # Append a single digit (0-9)
    "capitalize": lambda p: p.capitalize(),  # Capitalize the first letter
    "lowercase": lambda p: p.lower(),  # Convert to lowercase
    "uppercase": lambda p: p.upper(),  # Convert to uppercase
    "reverse": lambda p: p[::-1],  # Reverse the string
    # Add more rules here, e.g., leetspeak, appending symbols, etc.
    # Example: replace 'a' with '4', 'e' with '3'
    "basic_leet": lambda p: p.replace("a", "4")
    .replace("A", "4")
    .replace("e", "3")
    .replace("E", "3")
    .replace("i", "1")
    .replace("I", "1")
    .replace("o", "0")
    .replace("O", "0")
    .replace("s", "5")
    .replace("S", "5"),
}


# --- Global Data ---
# Dictionary to store precomputed hashes loaded from the file
precomputed_hashes = {}

# Lock for thread-safe access to shared resources (like the found password/hash)
found_lock = threading.Lock()
# Variable to store the cracked password/hash once found
found_result = None
# Event to signal workers to stop when a result is found
stop_event = threading.Event()
# Counter for attempts (shared across threads)
attempts_counter = 0
attempts_lock = threading.Lock()


# --- Utility Functions ---


def clear_screen():
    """Clears the terminal screen."""
    os.system("cls" if os.name == "nt" else "clear")


def load_precomputed_hashes(filepath):
    """Loads precomputed hashes from a JSON file."""
    if os.path.exists(filepath):
        try:
            with open(filepath, "r") as f:
                data = json.load(f)
                # Ensure all expected hash algorithms are present in the loaded data
                for algo in ["md5", "sha256", "sha1", "sha512", "ntlm"]:
                    if algo not in data:
                        data[algo] = {}
                # bcrypt is not suitable for precomputation/cracking this way, so handle separately if needed
                if "bcrypt" not in data:
                    data["bcrypt"] = (
                        {}
                    )  # Keep for storing *generated* bcrypt hashes if needed
                return data
        except json.JSONDecodeError:
            print(
                f"Warning: Could not decode JSON from {filepath}. Starting with empty precomputed hashes."
            )
            return {
                algo: {}
                for algo in ["md5", "sha256", "sha1", "sha512", "ntlm", "bcrypt"]
            }
        except Exception as e:
            print(
                f"Warning: An error occurred loading precomputed hashes from {filepath}: {e}. Starting with empty precomputed hashes."
            )
            return {
                algo: {}
                for algo in ["md5", "sha256", "sha1", "sha512", "ntlm", "bcrypt"]
            }
    else:
        print(
            f"Info: Precomputed hashes file not found at {filepath}. Starting with empty."
        )
        return {
            algo: {} for algo in ["md5", "sha256", "sha1", "sha512", "ntlm", "bcrypt"]
        }


def save_precomputed_hashes(filepath, data):
    """Saves the current precomputed hashes to a JSON file."""
    try:
        with open(filepath, "w") as f:
            json.dump(data, f, indent=4)
    except Exception as e:
        print(f"Error: Could not save precomputed hashes to {filepath}: {e}")


def print_status(message):
    """Prints a status message to the console, clearing previous output."""
    clear_screen()
    print(message)
    sys.stdout.flush()


def format_time(seconds):
    """Formats elapsed time in a human-readable format."""
    if seconds is None:
        return "N/A"
    if seconds < 60:
        return f"{seconds:.2f} seconds"
    elif seconds < 3600:
        minutes = seconds / 60
        return f"{minutes:.2f} minutes"
    elif seconds < 86400:
        hours = seconds / 3600
        return f"{hours:.2f} hours"
    elif seconds < 31536000:  # Approx days in a year
        days = seconds / 86400
        return f"{days:.2f} days"
    else:
        years = seconds / 31536000
        return f"{years:.2f} years"


def apply_rules(password, rules_to_apply):
    """Applies a list of mutation rules to a password."""
    passwords_to_check = [password]
    for rule_name in rules_to_apply:
        if rule_name in MUTATION_RULES:
            new_passwords = []
            for p in passwords_to_check:
                result = MUTATION_RULES[rule_name](p)
                if isinstance(result, list):
                    new_passwords.extend(result)
                else:
                    new_passwords.append(result)
            passwords_to_check = list(set(new_passwords))  # Remove duplicates
    return passwords_to_check


# --- Hashing Functions ---


def calculate_hash_md5(text):
    """Calculates the MD5 hash of a string."""
    return hashlib.md5(text.encode()).hexdigest()


def calculate_hash_sha1(text):
    """Calculates the SHA-1 hash of a string."""
    return hashlib.sha1(text.encode()).hexdigest()


def calculate_hash_sha256(text):
    """Calculates the SHA-256 hash of a string."""
    return hashlib.sha256(text.encode()).hexdigest()


def calculate_hash_sha512(text):
    """Calculates the SHA-512 hash of a string."""
    return hashlib.sha512(text.encode()).hexdigest()


def calculate_hash_ntlm(text):
    """Calculates the NTLM hash of a string."""
    # NTLM uses UTF-16 Little Endian encoding
    try:
        ntlm_hash = hashlib.new("md4", text.encode("utf-16le")).hexdigest()
        return ntlm_hash
    except ValueError:
        # Handle cases where MD4 is not supported
        # print("\nWarning: MD4 algorithm (required for NTLM) is not supported in your Python environment.")
        # print("NTLM hashing and cracking will be skipped.")
        return None  # Indicate that hashing failed due to lack of support


def calculate_hash_bcrypt(text):
    """
    Calculates a bcrypt hash for a string.
    NOTE: bcrypt is designed to be slow and uses a random salt each time.
    This function is for generating *new* bcrypt hashes, not for cracking existing ones
    without knowing the original salt. Cracking existing bcrypt hashes with brute force
    is generally infeasible on typical hardware.
    """
    # bcrypt.gensalt() generates a new salt each time
    hashed = bcrypt.hashpw(text.encode(), bcrypt.gensalt())
    # Store as hex for JSON serialization, but note this loses the salt info needed for verification
    # For verification, you'd need the original hash *including* the salt.
    # A more robust approach for storing/verifying bcrypt would store the full hash string.
    # However, for the purpose of this script's precomputation concept (which is limited for bcrypt),
    # we'll store the hex, but with the understanding that cracking this hex later is not possible
    # without the original salt.
    return hashed.hex()


# Mapping of algorithm names to hashing functions
HASH_ALGORITHMS = {
    "md5": calculate_hash_md5,
    "sha1": calculate_hash_sha1,
    "sha256": calculate_hash_sha256,
    "sha512": calculate_hash_sha512,
    "ntlm": calculate_hash_ntlm,
    "bcrypt": calculate_hash_bcrypt,  # Keep for hashing, but not for cracking
}

# Algorithms that are feasible to crack with brute force or dictionary attack
CRACKABLE_HASH_ALGORITHMS = {
    "md5": calculate_hash_md5,
    "sha1": calculate_hash_sha1,
    "sha256": calculate_hash_sha256,
    "sha512": calculate_hash_sha512,
    "ntlm": calculate_hash_ntlm,
}

# Check for MD4 support and update CRACKABLE_HASH_ALGORITHMS if not available
try:
    hashlib.new("md4")
except ValueError:
    if "ntlm" in CRACKABLE_HASH_ALGORITHMS:
        del CRACKABLE_HASH_ALGORITHMS["ntlm"]
    # print(
    #     "Warning: MD4 algorithm (required for NTLM) is not supported in your Python environment."
    # )
    # print("NTLM hashing and cracking will be disabled.")


# --- Cracking Functions ---


def crack_hash_worker(
    target_hash,
    hash_algorithm_func,
    password_iterator,
    show_info,
    start_time,
    rules_to_apply,
):
    """Worker function for cracking hashes using brute force or dictionary with rules."""
    global found_result, attempts_counter

    for attempt_tuple in password_iterator:  # Iterate over tuples
        # Convert the tuple to a string
        attempt = "".join(attempt_tuple)

        # Check if the stop event is set (meaning password was found by another thread)
        if stop_event.is_set():
            return

        passwords_to_check = apply_rules(attempt, rules_to_apply)

        for password_to_check in passwords_to_check:
            with attempts_lock:
                attempts_counter += 1

            if (
                show_info and attempts_counter % 10000 == 0
            ):  # Update status periodically
                elapsed_time = time.time() - start_time
                speed = attempts_counter / (
                    elapsed_time + 0.1
                )  # Avoid division by zero
                print_status(
                    f"Cracking hash: {target_hash}\n"
                    f"Algorithm: {hash_algorithm_func.__name__.replace('calculate_hash_', '')}\n"
                    f"Currently trying: {password_to_check} (from {attempt})\n"
                    f"Attempts: {attempts_counter}\n"
                    f"Speed: {speed:.2f} hashes/second\n"
                    f"Time elapsed: {format_time(elapsed_time)}"
                )

            hashed_attempt = hash_algorithm_func(password_to_check)
            if (
                hashed_attempt is None
            ):  # Handle case where hashing failed (e.g., NTLM without MD4)
                continue

            if (
                hashed_attempt.lower() == target_hash.lower()
            ):  # Case-insensitive hash comparison
                with found_lock:
                    found_result = password_to_check  # Store the found password
                stop_event.set()  # Signal other threads to stop
                return  # Exit the worker


def crack_hashes(
    hashes_to_crack,
    hash_algorithm,
    max_length=None,
    charset=None,
    wordlist_path=None,
    rules=None,
    show_info=False,
):
    """
    Cracks one or more hashes using brute force or dictionary attack with multiple threads and rules.

    Args:
        hashes_to_crack (list): A list of hash values to crack.
        hash_algorithm (str): The name of the hash algorithm.
        max_length (int, optional): The maximum length for brute-force attempts. Required for brute-force.
        charset (str, optional): The character set for brute-force attempts. Required for brute-force.
        wordlist_path (str, optional): The path to the wordlist file for dictionary attack. Required for dictionary attack.
        rules (list, optional): A list of rule names to apply during dictionary attack.
        show_info (bool): Whether to display cracking progress.
    """
    global found_result, attempts_counter
    cracked_hashes = {}

    if hash_algorithm not in CRACKABLE_HASH_ALGORITHMS:
        print(
            f"Error: Cracking is not supported for the '{hash_algorithm}' algorithm with this tool (possibly due to missing MD4 support for NTLM)."
        )
        return cracked_hashes

    hash_algorithm_func = CRACKABLE_HASH_ALGORITHMS[hash_algorithm]

    for target_hash in hashes_to_crack:
        # Check if the hash is already precomputed
        if (
            hash_algorithm in precomputed_hashes
            and target_hash in precomputed_hashes[hash_algorithm]
        ):
            cracked_password = precomputed_hashes[hash_algorithm][target_hash]
            print(f"--- HASH CRACKED (PRECOMPUTED) ---")
            print(f"Target Hash: {target_hash}")
            print(f"Algorithm: {hash_algorithm}")
            print(f"Cracked Password: {cracked_password}")
            print("This hash was found in the precomputed database.")
            cracked_hashes[target_hash] = cracked_password
            continue  # Move to the next hash if precomputed

        found_result = None  # Reset found_result for each new hash
        stop_event.clear()  # Clear the stop event for each new hash
        attempts_counter = 0  # Reset attempts counter for each new hash

        print_status(
            f"Starting to crack hash: {target_hash}\n" f"Algorithm: {hash_algorithm}"
        )

        start_time = time.time()

        if wordlist_path:
            # Dictionary Attack Mode
            if not os.path.exists(wordlist_path):
                print(f"Error: Wordlist file not found at {wordlist_path}")
                return cracked_hashes  # Exit if wordlist not found

            print(f"Attack Type: Dictionary ({wordlist_path})")
            if rules:
                print(f"Rules Applied: {', '.join(rules)}")

            try:
                with open(wordlist_path, "r", encoding="utf-8", errors="ignore") as f:
                    wordlist_iterator = (
                        line.strip() for line in f if line.strip()
                    )  # Strip whitespace and skip empty lines

                    class ThreadSafeIterator:
                        def __init__(self, iterator):
                            self._iterator = iterator
                            self._lock = threading.Lock()

                        def __iter__(self):
                            return self

                        def __next__(self):
                            with self._lock:
                                try:
                                    return next(self._iterator)
                                except StopIteration:
                                    raise

                    safe_iterator = ThreadSafeIterator(wordlist_iterator)

                    threads = []
                    for i in range(NUM_THREADS):
                        thread = threading.Thread(
                            target=crack_hash_worker,
                            args=(
                                target_hash,
                                hash_algorithm_func,
                                safe_iterator,
                                show_info,
                                start_time,
                                rules if rules else [],
                            ),
                        )
                        threads.append(thread)
                        thread.start()

                    for thread in threads:
                        thread.join()

            except Exception as e:
                print(f"Error reading wordlist: {e}")
                continue  # Move to the next hash on error

        elif max_length is not None and charset is not None:
            # Brute-force Attack Mode
            print(
                f"Attack Type: Brute-force\n"
                f"Max password length: {max_length}\n"
                f"Character set: {charset}"
            )

            for length in range(1, max_length + 1):
                if stop_event.is_set():
                    break  # Stop if password is found for this hash

                print(f"\nTrying passwords of length {length}...")
                password_permutations = itertools.product(charset, repeat=length)

                class ThreadSafeIterator:
                    def __init__(self, iterator):
                        self._iterator = iterator
                        self._lock = threading.Lock()

                    def __iter__(self):
                        return self

                    def __next__(self):
                        with self._lock:
                            try:
                                return next(self._iterator)
                            except StopIteration:
                                raise

                safe_iterator = ThreadSafeIterator(password_permutations)

                threads = []
                for i in range(NUM_THREADS):
                    thread = threading.Thread(
                        target=crack_hash_worker,
                        args=(
                            target_hash,
                            hash_algorithm_func,
                            safe_iterator,
                            show_info,
                            start_time,
                            [],
                        ),
                    )  # Rules not typically used in pure brute-force
                    threads.append(thread)
                    thread.start()

                for thread in threads:
                    thread.join()

                with found_lock:
                    if found_result is not None:
                        break  # Exit the length loop if found for this hash

        else:
            print(
                "Error: For cracking, you must specify either --max-length/--charset (for brute-force) or --wordlist (for dictionary attack)."
            )
            continue  # Move to the next hash if arguments are missing

        end_time = time.time()
        elapsed_time = end_time - start_time

        clear_screen()
        if found_result is not None:
            print(f"--- HASH CRACKED ---")
            print(f"Target Hash: {target_hash}")
            print(f"Algorithm: {hash_algorithm}")
            print(f"Cracked Password: {found_result}")
            print(f"Time Elapsed: {format_time(elapsed_time)}")
            print(f"Total Attempts: {attempts_counter}")

            # Store the cracked hash and password in precomputed hashes
            if hash_algorithm in precomputed_hashes:
                precomputed_hashes[hash_algorithm][target_hash] = found_result
                print("Cracked hash and password added to precomputed hashes.")
            cracked_hashes[target_hash] = found_result

        else:
            print(f"--- CRACKING FAILED ---")
            print(f"Target Hash: {target_hash}")
            print(f"Algorithm: {hash_algorithm}")
            if wordlist_path:
                print(
                    f"Could not crack the hash using the provided wordlist and rules."
                )
            else:
                print(
                    f"Could not crack the hash within the specified maximum length ({max_length}) and character set."
                )
            print(f"Time Elapsed: {format_time(elapsed_time)}")
            print(f"Total Attempts: {attempts_counter}")

    return cracked_hashes


def attempt_zip_password(zip_file_path, password):
    """Attempts to extract a ZIP file with a given password."""
    try:
        with pyzipper.AESZipFile(zip_file_path, "r") as zf:
            # pyzipper requires password as bytes
            zf.extractall(pwd=password.encode("utf-8"))
        return True  # Extraction successful
    except pyzipper.BadZipFile:
        # This might happen if the file is not a valid ZIP or is corrupted
        print(f"Error: Invalid or corrupted ZIP file: {zip_file_path}")
        return False  # Indicate failure, but not a password issue
    except RuntimeError as e:
        # pyzipper raises RuntimeError for incorrect password
        if "Bad password" in str(e):
            return False  # Incorrect password
        else:
            print(f"An unexpected runtime error occurred: {e}")
            return False
    except Exception as e:
        # Catch any other potential exceptions during extraction
        print(f"An unexpected error occurred during ZIP extraction: {e}")
        return False


def crack_zip_worker(zip_file_path, password_iterator, rules_to_apply):
    """Worker function for cracking ZIP passwords with rules."""
    global found_result, attempts_counter

    for attempt_tuple in password_iterator:  # Iterate over tuples
        # Convert the tuple to a string
        attempt = "".join(attempt_tuple)

        if stop_event.is_set():
            return  # Exit if password is found by another thread

        passwords_to_check = apply_rules(attempt, rules_to_apply)

        for password_to_check in passwords_to_check:
            with attempts_lock:
                attempts_counter += 1

            # No show_info for ZIP cracking attempts due to potential overhead,
            # but could add a progress counter based on password iterator size if known.

            if attempt_zip_password(zip_file_path, password_to_check):
                with found_lock:
                    found_result = password_to_check  # Store the found password
                stop_event.set()  # Signal other threads to stop
                return  # Exit the worker


def crack_zip(
    zip_file_path, max_length=None, charset=None, wordlist_path=None, rules=None
):
    """
    Cracks a ZIP file password using brute force or dictionary attack with multiple threads and rules.

    Args:
        zip_file_path (str): The path to the ZIP file.
        max_length (int, optional): The maximum length for brute-force attempts. Required for brute-force.
        charset (str, optional): The character set for brute-force attempts. Required for brute-force.
        wordlist_path (str, optional): The path to the wordlist file for dictionary attack. Required for dictionary attack.
        rules (list, optional): A list of rule names to apply during dictionary attack.
    """
    global found_result, attempts_counter
    found_result = None  # Reset found_result
    stop_event.clear()  # Clear the stop event
    attempts_counter = 0  # Reset attempts counter

    if not os.path.exists(zip_file_path):
        print(f"Error: ZIP file not found at {zip_file_path}")
        return

    print_status(f"Starting to crack ZIP: {zip_file_path}")

    start_time = time.time()

    if wordlist_path:
        # Dictionary Attack Mode
        if not os.path.exists(wordlist_path):
            print(f"Error: Wordlist file not found at {wordlist_path}")
            return

        print(f"Attack Type: Dictionary ({wordlist_path})")
        if rules:
            print(f"Rules Applied: {', '.join(rules)}")

        try:
            with open(wordlist_path, "r", encoding="utf-8", errors="ignore") as f:
                wordlist_iterator = (line.strip() for line in f if line.strip())

                class ThreadSafeIterator:
                    def __init__(self, iterator):
                        self._iterator = iterator
                        self._lock = threading.Lock()

                    def __iter__(self):
                        return self

                    def __next__(self):
                        with self._lock:
                            try:
                                return next(self._iterator)
                            except StopIteration:
                                raise

                safe_iterator = ThreadSafeIterator(wordlist_iterator)

                threads = []
                for i in range(NUM_THREADS):
                    thread = threading.Thread(
                        target=crack_zip_worker,
                        args=(zip_file_path, safe_iterator, rules if rules else []),
                    )
                    threads.append(thread)
                    thread.start()

                for thread in threads:
                    thread.join()

        except Exception as e:
            print(f"Error reading wordlist: {e}")
            return

    elif max_length is not None and charset is not None:
        # Brute-force Attack Mode
        print(
            f"Attack Type: Brute-force\n"
            f"Max password length: {max_length}\n"
            f"Character set: {charset}"
        )

        for length in range(1, max_length + 1):
            if stop_event.is_set():
                break  # Stop if password is found

            print(f"\nTrying passwords of length {length}...")
            password_permutations = itertools.product(charset, repeat=length)

            class ThreadSafeIterator:
                def __init__(self, iterator):
                    self._iterator = iterator
                    self._lock = threading.Lock()

                def __iter__(self):
                    return self

                def __next__(self):
                    with self._lock:
                        try:
                            return next(self._iterator)
                        except StopIteration:
                            raise

            safe_iterator = ThreadSafeIterator(password_permutations)

            threads = []
            for i in range(NUM_THREADS):
                thread = threading.Thread(
                    target=crack_zip_worker, args=(zip_file_path, safe_iterator, [])
                )  # Rules not typically used in pure brute-force
                threads.append(thread)
                thread.start()

            for thread in threads:
                thread.join()

            with found_lock:
                if found_result is not None:
                    break  # Exit the length loop if found

    else:
        print(
            "Error: For cracking, you must specify either --max-length/--charset (for brute-force) or --wordlist (for dictionary attack)."
        )
        return

    end_time = time.time()
    elapsed_time = end_time - start_time

    clear_screen()
    if found_result is not None:
        print(f"--- ZIP CRACKED ---")
        print(f"ZIP File: {zip_file_path}")
        print(f"Cracked Password: {found_result}")
        print(f"Time Elapsed: {format_time(elapsed_time)}")
        print(f"Total Attempts: {attempts_counter}")
    else:
        print(f"--- CRACKING FAILED ---")
        print(f"ZIP File: {zip_file_path}")
        if wordlist_path:
            print(
                f"Could not crack the password using the provided wordlist and rules."
            )
        else:
            print(
                f"Could not crack the password within the specified maximum length ({max_length}) and character set."
            )
        print(f"Time Elapsed: {format_time(elapsed_time)}")
        print(f"Total Attempts: {attempts_counter}")


# --- Test Mode ---


def run_benchmark():
    """Runs a benchmark to test cracking speed for different algorithms."""
    print_status("--- Running Benchmark ---")
    print(f"System: {platform.system()} {platform.release()}")
    print(f"Processor: {platform.processor()}")
    print(f"Using {NUM_THREADS} threads.")
    print("-" * 30)

    test_password = "123"  # Using a short password for a quick benchmark
    test_hashes = {}

    # Generate hashes for the test password
    print(f"\nGenerating test hashes for password: '{test_password}'")
    for algo_name, hash_func in CRACKABLE_HASH_ALGORITHMS.items():
        print(f"  {algo_name}: Calculating...")
        # Check if the hash function returned None (indicating lack of support)
        test_hash = hash_func(test_password)
        if test_hash is not None:
            test_hashes[algo_name] = test_hash
            print(f"    Hash: {test_hashes[algo_name]}")
        # else: Warning message is printed within calculate_hash_ntlm

    print("\nStarting cracking benchmark...")

    # --- Brute-force Benchmark ---
    # Using a fixed small number of attempts for a quick benchmark
    benchmark_attempts = 100000
    benchmark_charset = string.ascii_lowercase + string.digits  # Simple charset
    # Determine a length that provides enough attempts for the benchmark
    benchmark_length = 1
    while (len(benchmark_charset) ** benchmark_length) < benchmark_attempts:
        benchmark_length += 1

    print(
        f"\nBrute-force Benchmark (Charset: '{benchmark_charset}', Target Attempts: {benchmark_attempts})"
    )

    for algo_name, target_hash in test_hashes.items():
        print(f"\nBenchmarking {algo_name}...")
        global found_result, attempts_counter
        found_result = None
        stop_event.clear()
        attempts_counter = 0

        hash_algorithm_func = CRACKABLE_HASH_ALGORITHMS[algo_name]

        start_time = time.time()

        # Create a limited iterator for the benchmark
        password_permutations = itertools.product(
            benchmark_charset, repeat=benchmark_length
        )
        # Take only the required number of attempts for the benchmark
        benchmark_iterator = itertools.islice(password_permutations, benchmark_attempts)

        class ThreadSafeIterator:
            def __init__(self, iterator):
                self._iterator = iterator
                self._lock = threading.Lock()

            def __iter__(self):
                return self

            def __next__(self):
                with self._lock:
                    try:
                        return next(self._iterator)
                    except StopIteration:
                        raise

        safe_iterator = ThreadSafeIterator(benchmark_iterator)

        threads = []
        for i in range(NUM_THREADS):
            thread = threading.Thread(
                target=crack_hash_worker,
                args=(
                    target_hash,
                    hash_algorithm_func,
                    safe_iterator,
                    False,
                    start_time,
                    [],
                ),
            )  # show_info=False for cleaner benchmark output, no rules for brute-force
            threads.append(thread)
            thread.start()

        for thread in threads:
            thread.join()

        end_time = time.time()
        elapsed_time = end_time - start_time

        # Ensure elapsed time is not zero for speed calculation
        elapsed_time = elapsed_time if elapsed_time > 0 else 0.1

        speed = attempts_counter / elapsed_time  # Attempts per second
        print(f"  {algo_name}: Benchmark complete.")
        print(f"  Attempts: {attempts_counter}")
        print(f"  Time Elapsed: {format_time(elapsed_time)}")
        print(f"  Speed: {speed:.2f} hashes/second")

    print("\n--- Benchmark Complete ---")
    print("\nNote on GPU Acceleration:")
    print("This script primarily uses CPU-based hashing libraries (like hashlib).")
    print(
        "Achieving significant speedups using GPUs (CUDA, OpenCL, integrated) for password cracking"
    )
    print(
        "typically requires specialized libraries or tools designed for this purpose,"
    )
    print(
        "which can leverage the parallel processing power of GPUs much more effectively"
    )
    print("than standard Python functions.")
    print("Examples of such tools include Hashcat and John the Ripper.")
    print(
        "Integrating full GPU support into this script would require significant low-level"
    )
    print(
        "GPU programming or wrapping external tools, which is beyond the scope of this script."
    )


# --- Estimate Mode ---


def estimate_cracking_time(
    target, algorithm, max_length=None, charset=None, wordlist_path=None, rules=None
):
    """
    Estimates the time required to crack a password or hash.

    Args:
        target (str): The password or hash to estimate cracking time for.
        algorithm (str): The hash algorithm.
        max_length (int, optional): The maximum length for brute-force attempts. Required for brute-force.
        charset (str, optional): The character set for brute-force attempts. Required for brute-force.
        wordlist_path (str, optional): The path to the wordlist file for dictionary attack. Required for dictionary attack.
        rules (list, optional): A list of rule names to apply during dictionary attack.
    """
    print_status("--- Running Estimation ---")
    print(f"Target: {target}")
    print(f"Algorithm: {algorithm}")

    if algorithm not in CRACKABLE_HASH_ALGORITHMS:
        print(
            f"Error: Estimation is not supported for the '{algorithm}' algorithm with this tool."
        )
        return

    hash_algorithm_func = CRACKABLE_HASH_ALGORITHMS[algorithm]

    # --- Run a micro-benchmark to get current speed ---
    benchmark_attempts = 50000  # Smaller benchmark for estimation
    benchmark_charset = string.ascii_lowercase + string.digits
    benchmark_length = 1
    while (len(benchmark_charset) ** benchmark_length) < benchmark_attempts:
        benchmark_length += 1

    print(
        f"\nRunning micro-benchmark for speed estimation ({benchmark_attempts} attempts)..."
    )

    temp_target_hash = hash_algorithm_func(
        "abc123"
    )  # Use a simple fixed password for benchmark hash
    if temp_target_hash is None:
        print(f"Error: Could not run micro-benchmark for {algorithm} (hashing failed).")
        return

    global found_result, attempts_counter
    found_result = None
    stop_event.clear()
    attempts_counter = 0

    start_time = time.time()

    password_permutations = itertools.product(
        benchmark_charset, repeat=benchmark_length
    )
    benchmark_iterator = itertools.islice(password_permutations, benchmark_attempts)

    class ThreadSafeIterator:
        def __init__(self, iterator):
            self._iterator = iterator
            self._lock = threading.Lock()

        def __iter__(self):
            return self

        def __next__(self):
            with self._lock:
                try:
                    return next(self._iterator)
                except StopIteration:
                    raise

    safe_iterator = ThreadSafeIterator(benchmark_iterator)

    threads = []
    for i in range(NUM_THREADS):
        thread = threading.Thread(
            target=crack_hash_worker,
            args=(
                temp_target_hash,
                hash_algorithm_func,
                safe_iterator,
                False,  # No show_info for micro-benchmark
                start_time,
                [],  # No rules for micro-benchmark
            ),
        )
        threads.append(thread)
        thread.start()

    for thread in threads:
        thread.join()

    end_time = time.time()
    elapsed_time = end_time - start_time
    elapsed_time = elapsed_time if elapsed_time > 0 else 0.1  # Avoid division by zero

    speed_per_second = attempts_counter / elapsed_time
    print(f"Micro-benchmark complete. Speed: {speed_per_second:.2f} hashes/second.")
    print("-" * 30)

    # --- Calculate total attempts for the target ---
    total_attempts = 0
    attack_type = None

    if wordlist_path:
        attack_type = "Dictionary"
        if not os.path.exists(wordlist_path):
            print(f"Error: Wordlist file not found at {wordlist_path}")
            return

        try:
            with open(wordlist_path, "r", encoding="utf-8", errors="ignore") as f:
                wordlist_size = sum(1 for line in f if line.strip())
            print(f"Wordlist size: {wordlist_size} words.")

            # Estimate the number of attempts including rules
            estimated_mutations_per_word = 1  # Start with the original word
            if rules:
                print(f"Applying rules: {', '.join(rules)}")
                # A very rough estimation of mutations per word.
                # This is a simplification; actual mutations depend on the word and rule.
                # For 'append_digit', it's 10 mutations per word. For others, it's 1.
                # A more accurate estimate would require analyzing the wordlist and rules.
                estimated_mutations_per_word = 0
                for rule_name in rules:
                    if rule_name == "append_digit":
                        estimated_mutations_per_word += 10
                    else:
                        estimated_mutations_per_word += (
                            1  # Assuming most rules produce one output
                        )

                # Avoid overcounting the original word if no rules are applied
                if not rules:
                    estimated_mutations_per_word = 1  # Just the original word

                # A better approach is to sample the wordlist and apply rules to estimate average mutations
                # For simplicity here, we'll use a basic heuristic.
                # Let's refine this: count the number of *unique* outputs for a few sample words.
                sample_words = ["password", "test", "word123"]  # Sample words
                total_sample_mutations = 0
                total_sample_words = 0
                for sample_word in sample_words:
                    mutations = apply_rules(sample_word, rules)
                    total_sample_mutations += len(mutations)
                    total_sample_words += 1

                if total_sample_words > 0:
                    estimated_mutations_per_word = (
                        total_sample_mutations / total_sample_words
                    )
                    print(
                        f"Estimated average mutations per word (based on samples): {estimated_mutations_per_word:.2f}"
                    )
                else:
                    estimated_mutations_per_word = (
                        1  # Fallback if no sample words processed
                    )

            total_attempts = wordlist_size * estimated_mutations_per_word
            print(f"Estimated total attempts (including rules): {int(total_attempts)}")

        except Exception as e:
            print(f"Error reading wordlist for estimation: {e}")
            return

    elif max_length is not None and charset is not None:
        attack_type = "Brute-force"
        print(f"Max password length: {max_length}")
        print(f"Character set size: {len(charset)}")

        total_attempts = 0
        # Calculate total attempts for all lengths up to max_length
        for length in range(1, max_length + 1):
            attempts_this_length = len(charset) ** length
            total_attempts += attempts_this_length
            # Add a safeguard for extremely large numbers to prevent overflow/hang
            if total_attempts > sys.maxsize / 1000:  # Arbitrary large number
                print(
                    f"Warning: Estimated attempts exceeding practical limits at length {length}."
                )
                total_attempts = float("inf")  # Represent as infinite
                break

        print(
            f"Estimated total brute-force attempts (up to length {max_length}): {total_attempts}"
        )

    else:
        print(
            "Error: For estimation, you must specify either --max-length/--charset (for brute-force) or --wordlist (for dictionary attack)."
        )
        return

    # --- Estimate Time ---
    if total_attempts == 0:
        print("Estimated total attempts is 0. Estimation complete.")
        return
    elif total_attempts == float("inf"):
        estimated_time_seconds = float("inf")
    else:
        estimated_time_seconds = total_attempts / speed_per_second

    print("\n--- Estimated Cracking Time ---")
    print(f"Algorithm: {algorithm}")
    print(f"Attack Type: {attack_type}")
    print(
        f"Estimated Attempts: {int(total_attempts) if total_attempts != float('inf') else 'Infinite'}"
    )
    print(f"Estimated Speed: {speed_per_second:.2f} hashes/second")
    print(f"Estimated Time: {format_time(estimated_time_seconds)}")
    print("-" * 30)


# --- Main Execution ---


def main():
    """Parses arguments and runs the selected mode."""
    global precomputed_hashes

    # Load precomputed hashes at the start
    precomputed_hashes = load_precomputed_hashes(PRECOMPUTED_HASHES_FILE)

    parser = argparse.ArgumentParser(
        description="HASHCRACK v2.11 - A simple hash and ZIP cracker with brute-force, dictionary, NTLM, file cracking, benchmark, and estimate support."
    )

    # Group for cracking modes (mutually exclusive)
    mode_group = parser.add_mutually_exclusive_group(required=True)
    mode_group.add_argument(
        "-c", "--crack-hash", metavar="HASH", help="Crack a single hash value."
    )
    mode_group.add_argument(
        "-cf",
        "--crack-hashes-file",
        metavar="FILE",
        help="Crack multiple hash values from a file (one hash per line).",
    )
    mode_group.add_argument(
        "-z", "--crack-zip", metavar="ZIP_FILE", help="Crack a ZIP file password."
    )
    mode_group.add_argument(
        "-H", "--hash-text", metavar="TEXT", help="Calculate the hash of a given text."
    )
    mode_group.add_argument(
        "-Hf",
        "--hash-texts-file",
        metavar="FILE",
        help="Calculate hashes for multiple texts from a file (one text per line).",
    )
    mode_group.add_argument(
        "--test", action="store_true", help="Run a benchmark test of cracking speed."
    )
    mode_group.add_argument(
        "--estimate",
        metavar="TARGET",
        help="Estimate cracking time for a password or hash.",
    )

    # Optional arguments for cracking and estimation modes
    parser.add_argument(
        "-a",
        "--algorithm",
        metavar="ALGO",
        default="sha256",
        choices=list(HASH_ALGORITHMS.keys()),
        help=f"Hash algorithm to use. Choices: {', '.join(HASH_ALGORITHMS.keys())}. Default: sha256.",
    )
    # Arguments for brute-force (used in cracking and estimation)
    parser.add_argument(
        "-m",
        "--max-length",
        metavar="LENGTH",
        type=int,
        help="Maximum length of password/text to try for brute-force cracking or estimation.",
    )
    parser.add_argument(
        "-s",
        "--charset",
        metavar="CHARSET",
        default=DEFAULT_CHARSET,
        help=f"Character set to use for brute-force cracking or estimation. Default: '{DEFAULT_CHARSET}'.",
    )
    # Argument for dictionary attack (used in cracking and estimation)
    parser.add_argument(
        "-w",
        "--wordlist",
        metavar="FILE",
        help="Path to a wordlist file for dictionary attack or estimation.",
    )
    # Argument for rules (used in dictionary cracking and estimation)
    parser.add_argument(
        "-r",
        "--rules",
        metavar="RULE",
        nargs="+",  # Allows multiple rule names
        choices=list(MUTATION_RULES.keys()),
        help=f"List of rule names to apply during dictionary attack or estimation. Choices: {', '.join(MUTATION_RULES.keys())}. Can specify multiple rules separated by spaces.",
    )
    parser.add_argument(
        "-si",
        "--show-info",
        action="store_true",
        help="Show dynamic cracking progress information (may slow down cracking).",
    )

    args = parser.parse_args()

    clear_screen()  # Clear screen before starting the main task

    # Determine the cracking/estimation mode based on provided arguments
    is_bruteforce = args.max_length is not None
    is_dictionary = args.wordlist is not None

    if args.test:
        run_benchmark()

    elif args.estimate:
        if is_bruteforce and is_dictionary:
            print(
                "Error: Cannot specify both --max-length/--charset (brute-force) and --wordlist (dictionary) for estimation."
            )
        elif is_bruteforce or is_dictionary:
            if is_bruteforce:
                if args.rules:
                    print(
                        "Warning: Rules are typically used with dictionary attacks, not brute-force. Ignoring --rules for estimation."
                    )
                estimate_cracking_time(
                    args.estimate,
                    args.algorithm,
                    max_length=args.max_length,
                    charset=args.charset,
                )
            elif is_dictionary:
                estimate_cracking_time(
                    args.estimate,
                    args.algorithm,
                    wordlist_path=args.wordlist,
                    rules=args.rules,
                )
        else:
            print(
                "Error: For estimation, you must specify either --max-length/--charset (for brute-force) or --wordlist (for dictionary attack)."
            )

    elif args.crack_hash or args.crack_hashes_file:
        hashes_to_crack = []
        if args.crack_hash:
            hashes_to_crack.append(args.crack_hash)
        elif args.crack_hashes_file:
            if not os.path.exists(args.crack_hashes_file):
                print(f"Error: Hashes file not found at {args.crack_hashes_file}")
                sys.exit(1)
            try:
                with open(
                    args.crack_hashes_file, "r", encoding="utf-8", errors="ignore"
                ) as f:
                    hashes_to_crack = [line.strip() for line in f if line.strip()]
                if not hashes_to_crack:
                    print(
                        f"Error: Hashes file is empty or contains only whitespace lines."
                    )
                    sys.exit(1)
            except Exception as e:
                print(f"Error reading hashes file: {e}")
                sys.exit(1)

        if is_bruteforce and is_dictionary:
            print(
                "Error: Cannot specify both --max-length/--charset (brute-force) and --wordlist (dictionary) for hash cracking."
            )
        elif is_bruteforce or is_dictionary:
            if is_bruteforce:
                if args.rules:
                    print(
                        "Warning: Rules are typically used with dictionary attacks, not brute-force. Ignoring --rules."
                    )
                crack_hashes(
                    hashes_to_crack,
                    args.algorithm,
                    max_length=args.max_length,
                    charset=args.charset,
                    show_info=args.show_info,
                )
            elif is_dictionary:
                crack_hashes(
                    hashes_to_crack,
                    args.algorithm,
                    wordlist_path=args.wordlist,
                    rules=args.rules,
                    show_info=args.show_info,
                )
        else:
            print(
                "Error: For hash cracking, you must specify either --max-length/--charset (for brute-force) or --wordlist (for dictionary attack)."
            )

    elif args.crack_zip:
        if is_bruteforce and is_dictionary:
            print(
                "Error: Cannot specify both --max-length/--charset (brute-force) and --wordlist (dictionary) for ZIP cracking."
            )
        elif is_bruteforce or is_dictionary:
            if is_bruteforce:
                if args.rules:
                    print(
                        "Warning: Rules are typically used with dictionary attacks, not brute-force. Ignoring --rules."
                    )
                crack_zip(
                    args.crack_zip,
                    max_length=args.max_length,
                    charset=args.charset,
                )
            elif is_dictionary:
                crack_zip(
                    args.crack_zip,
                    wordlist_path=args.wordlist,
                    rules=args.rules,
                )
        else:
            print(
                "Error: For cracking, you must specify either --max-length/--charset (for brute-force) or --wordlist (for dictionary attack)."
            )

    elif args.hash_text or args.hash_texts_file:
        texts_to_hash = []
        if args.hash_text:
            texts_to_hash.append(args.hash_text)
        elif args.hash_texts_file:
            if not os.path.exists(args.hash_texts_file):
                print(f"Error: Texts file not found at {args.hash_texts_file}")
                sys.exit(1)
            try:
                with open(
                    args.hash_texts_file, "r", encoding="utf-8", errors="ignore"
                ) as f:
                    texts_to_hash = [line.strip() for line in f if line.strip()]
                if not texts_to_hash:
                    print(
                        f"Error: Texts file is empty or contains only whitespace lines."
                    )
                    sys.exit(1)
            except Exception as e:
                print(f"Error reading texts file: {e}")
                sys.exit(1)

        if args.algorithm not in HASH_ALGORITHMS:
            print(
                f"Error: Invalid hash algorithm specified for hashing: {args.algorithm}"
            )
            return

        hasher = HASH_ALGORITHMS[args.algorithm]

        print(f"--- HASH CALCULATION ---")
        print(f"Algorithm: {args.algorithm}")

        for text in texts_to_hash:
            hashed_text = hasher(text)
            if (
                hashed_text is not None
            ):  # Check if hashing was successful (e.g., NTLM without MD4)
                print(f"Original Text: '{text}' -> Hash: {hashed_text}")

                # Store the generated hash and original text in precomputed hashes
                if args.algorithm in precomputed_hashes:
                    precomputed_hashes[args.algorithm][hashed_text] = text
                else:
                    print(
                        f"Warning: Cannot store precomputed hash for algorithm '{args.algorithm}'."
                    )
            # else: Warning message is printed within calculate_hash_ntlm

    # Save precomputed hashes before exiting
    save_precomputed_hashes(PRECOMPUTED_HASHES_FILE, precomputed_hashes)


if __name__ == "__main__":
    main()
