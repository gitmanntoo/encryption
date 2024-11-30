import sys
import argparse
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
import getpass
import hashlib
import re

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

    print("Enter secret phrases.  Enter an empty line to end.")
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


def main():
    parser = argparse.ArgumentParser(
        description=HELP_STRING,
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    ed_group = parser.add_mutually_exclusive_group(required=True)
    ed_group.add_argument(
        "-e", "--encrypt",
        action="store_true",
        help="Encrypt the input (cannot be used with --decrypt)",
    )
    ed_group.add_argument(
        "-d", "--decrypt",
        action="store_true",
        help="Decrypt the input (cannot be used with --encrypt)",
    )
    parser.add_argument(
        "--show-phrases",
        action="store_true",
        help="Display the secret phrases used to encrypt/decrypt",
    )
    parser.add_argument(
        "--base64",
        action="store_true",
        help="Encrypted data is base64 encoded",
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
        "--generate-key",
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

    if args.generate_key:
        print(fernet_key.decode())
        return

    if not input_bytes:
        input_bytes = get_multiline_input().encode()
    if args.encrypt:
        # Encrypt data using the given key.
        f = Fernet(fernet_key)

        encrypted_bytes = f.encrypt(input_bytes)
        if args.base64:
            encrypted_bytes = base64.urlsafe_b64encode(encrypted_bytes)

        if args.output is not None:
            with open(args.output, "wb") as f:
                f.write(encrypted_bytes)
        else:
            print(encrypted_bytes)

    elif args.decrypt:
        # Decrypt data using the given key.
        f = Fernet(fernet_key)

        if args.base64:
            input_bytes = base64.urlsafe_b64decode(input_bytes)
        decrypted_bytes = f.decrypt(input_bytes)

        if args.output is not None:
            with open(args.output, "wb") as f:
                f.write(decrypted_bytes)
        else:
            print(decrypted_bytes.decode())


if __name__ == "__main__":
    main()
