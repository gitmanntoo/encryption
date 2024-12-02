import sys
import argparse
import base64
import datetime
import getpass
import hashlib

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend


HELP_STRING = """
Encrypt and decrypt text using Python builtin Fernet.

You will be prompted for a series of secret phrases.
- Order is important!

After all phrases are entered, data will be encrypted or decrypted.
"""


def get_multiline_input(prompt="Enter text (end with Ctrl+D on Unix or Ctrl+Z on Windows):\n"):
    print(prompt, end="")
    return sys.stdin.read()


def get_secret_phrases(show_phrases: bool = False) -> list[str]:
    """
    Collects a multiple secret pharses without displaying the input characters.
    - If show_phrases is true, the phrases will be displayed to the user.

    Args:
        show_phrases (bool): If True, display secret phrases in the terminal.

    Returns:
        str: The collected multi-line password.
    """

    if show_phrases:
        print("Enter secret phrases. Enter an empty line to end.")
    else:
        print("Enter secret phrases. Input will be hidden. Enter an empty line to end.")

    lines = []
    while True:
        # Get a line of the password without showing it on the console.
        prompt = f"Phrase {len(lines) + 1}: "
        if show_phrases:
            line = input(prompt).strip()
        else:
            line = getpass.getpass(prompt).strip()
            # Check if the terminator was entered, indicating end of input.
        if line == "":
            break

        lines.append(line)

    return lines


def salt_from_phrases(phrases: list[str]) -> bytes:
    """Convert a list of seed strings into a sha256 as bytes.
    """

    out = b""
    for p in phrases:
        p = out.hex() + p
        out = hashlib.sha256(p.encode()).digest()

    return out


def generate_key(phrases: list[str], length: int = 32) -> bytes:
    """Generate a key from given password and seed strings.
    - phrases is a list of at least two strings
      - the first string is used as the password
      - all other strings are combined to form the salt
    """

    last_key = b""
    for p in phrases:
        p = f"{last_key}{p}"

        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA512(),
            length=length,
            salt=salt_from_phrases(phrases),
            iterations=100000,
            backend=default_backend()
        )

        last_key = base64.urlsafe_b64encode(kdf.derive(p.encode()))

    return last_key


def do_encrypt(fernet_key: bytes, input_bytes: bytes) -> bytes:
    """Encrypt the input text using the given key.
    
    Add noise with the following steps:
    - base64 encode the input_bytes
    - add 99 bytes from the current datetime to the beginning and end of the input_bytes
    """

    input_string = base64.urlsafe_b64encode(input_bytes).decode()

    now = datetime.datetime.now()
    before_string = hashlib.sha512(str(now).encode()).hexdigest()[:99]

    now = datetime.datetime.now()
    after_string = hashlib.sha512(str(now).encode()).hexdigest()[:99]

    input_string = f"{before_string}{input_string}{after_string}"

    f = Fernet(fernet_key)
    return f.encrypt(input_string.encode())


def do_decrypt(fernet_key: bytes, input_bytes: bytes) -> bytes:
    """Decrypt the input text using the given key.
    - Remove some noise from the first and last 99 characters.
    """

    f = Fernet(fernet_key)
    
    decrypted_string = f.decrypt(input_bytes).decode()
    decrypted_string = decrypted_string[99:-99]

    return base64.urlsafe_b64decode(decrypted_string.encode())


def print_output(out: str):
    """Print the output to stdout with separators before and after."""

    print()
    print("=" * 5, "BEGIN OUTPUT", "=" * 5)
    print(out)
    print("=" * 5, "END OUTPUT", "=" * 5)


def main():
    parser = argparse.ArgumentParser(
        description=HELP_STRING,
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument(
        "-d", "--decrypt",
        action="store_true",
        help="Decrypt the input (default is encryption)",
    )
    parser.add_argument(
        "--show-phrases",
        action="store_true",
        help="Display the secret phrases used to encrypt/decrypt",
    )
    parser.add_argument(
        "--no-base64",
        action="store_true",
        help="Encrypted data is NOT base64 encoded",
    )
    parser.add_argument(
        "-i", "--input",
        help="Read input from a file instead of stdin",
    )
    parser.add_argument(
        "-o", "--output",
        help="Write output to a file instead of stdout",
    )
    parser.add_argument(
        "--gen-key",
        action="store_true",
        help="Generate key and exit",
    )
    args = parser.parse_args()

    input_bytes = ""
    if args.input is not None:
        with open(args.input, "rb") as f:
            input_bytes = f.read()

    secrets = get_secret_phrases(args.show_phrases)
    if len(secrets) == 0:
        print("No secret phrases entered.")
        return
    fernet_key = generate_key(secrets)

    if args.gen_key:
        print_output(fernet_key.decode())
        return

    if not input_bytes:
        input_bytes = get_multiline_input().encode()
    if not args.decrypt:
        # Encrypt data using the given key.
        encrypted_bytes = do_encrypt(fernet_key, input_bytes)

        if not args.no_base64:
            encrypted_bytes = base64.urlsafe_b64encode(encrypted_bytes)

        if args.output is not None:
            with open(args.output, "wb") as f:
                f.write(encrypted_bytes)
        else:
            print_output(encrypted_bytes.decode())

    elif args.decrypt:
        # Decrypt data using the given key.
        if not args.no_base64:
            input_bytes = base64.urlsafe_b64decode(input_bytes)

        decrypted_bytes = do_decrypt(fernet_key, input_bytes)

        if args.output is not None:
            with open(args.output, "wb") as f:
                f.write(decrypted_bytes)
        else:
            print_output(decrypted_bytes.decode(errors="ignore"))


if __name__ == "__main__":
    main()
