import os
import sys
import argparse
import base64
import gnupg
import getpass
import hashlib
from pathlib import Path
import re

HELP_STRING = """
Encrypt and decrypt or files using gpg.
- gpg should already be installed on your system.
- keys should already be imported into your gpg keyring.

You will be prompted for a series of secret phrases.
- Order is important!

After all phrases are entered, data will be encrypted or decrypted.
"""


def get_multiline_input(
    prompt: str = "Enter text (end with Ctrl+D on Unix or Ctrl+Z on Windows):\n",
    append_to: str = None,
) -> str:
    
    if append_to is not None:
        print("APPENDING TO:")
        print(append_to)
        print("APPENDING...")

    print(prompt, end="")

    output = sys.stdin.read()
    if append_to is not None:
        output = append_to + output

    return output


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


def do_decrypt(
    args: argparse.Namespace,
    gpg: gnupg.GPG,
):
    """
    Decrypts the given input using the given passphrase.
    - Either input_file or input_string must be provided.
    """

    passphrase = None
    if args.passphrase:
        passphrase = getpass.getpass("Enter passphrase: ").strip()

    if args.input:
        if not os.path.exists(args.input):
            return b""

        decrypt_result = gpg.decrypt_file(args.input, passphrase=passphrase)
    else:
        input_string = get_multiline_input()
        decrypt_result = gpg.decrypt(input_string, passphrase=passphrase)

    if not decrypt_result.ok:
        raise Exception(f"!!! ERROR: {decrypt_result.status}")
    
    return decrypt_result.data


def do_encrypt(
    args: argparse.Namespace,
    gpg: gnupg.GPG,
    append_to: str = None,
):
    """
    Encrypts the given input for the given recipients.
    - Either input_file or input_string must be provided.
    - Recipients must be provided.
    """

    if args.input is not None:
        encrypt_result = gpg.encrypt_file(args.input, args.recipient)
    else:
        input_string = get_multiline_input(append_to=append_to)
        encrypt_result = gpg.encrypt(input_string, args.recipient)

    if not encrypt_result.ok:
        raise Exception(f"!!! ERROR: {encrypt_result.status}")
    
    return encrypt_result.data


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
    ed_group.add_argument(
        "-a", "--append",
        action="store_true",
        help="Append to input if it exists",
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
    
    input_group = parser.add_mutually_exclusive_group()
    input_group.add_argument(
        "-i", "--input",
        help="Read input from a file instead of stdin",
    )

    parser.add_argument(
        "-o", "--output",
        help="Write output to a file instead of stdout",
    )

    parser.add_argument(
        "-r", "--recipient",
        action="append",
        help="Specify the recipient of the encrypted data, repeatable",
    )
    parser.add_argument(
        "-p", "--passphrase",
        action="store_true",
        help="Prompt for a passphrase",
    )

    args = parser.parse_args()

    if args.encrypt or args.append:
        if args.recipient is None or len(args.recipient) == 0:
            print("!!! ERROR: No recipients specified")
            return

    gpg = gnupg.GPG()

    if args.decrypt:
        decrypt_result = do_decrypt(args, gpg)

        if args.output is not None:
            with open(args.output, "wb") as f:
                f.write(decrypt_result)
        else:
            print(decrypt_result.decode())

        return

    elif args.encrypt:
        encrypt_result = do_encrypt(args, gpg)

        if args.output is not None:
            with open(args.output, "wb") as f:
                f.write(encrypt_result)
        else:
            print(encrypt_result.decode())

    elif args.append:
        decrypt_result = do_decrypt(args, gpg)
        
        # Clear the input so that encryption uses the terminal.
        if args.output is None:
            args.output = args.input
        args.input = None

        encrypt_result = do_encrypt(
            args, gpg, append_to=decrypt_result.decode())

        if args.output is not None:
            with open(args.output, "wb") as f:
                f.write(encrypt_result)
        else:
            print(encrypt_result.decode())

    # input_bytes = ""
    # if args.input is not None:
    #     with open(args.input, "rb") as f:
    #         input_bytes = f.read()

    # secrets = get_secret_phrases(args.show_phrases)
    # if len(secrets) == 0:
    #     print("No secret phrases entered.")
    #     return
    # fernet_key = generate_key(secrets)

    # if not input_bytes:
    #     input_bytes = get_multiline_input().encode()
    # if args.encrypt:
    #     # Encrypt data using the given key.
    #     f = Fernet(fernet_key)

    #     encrypted_bytes = f.encrypt(input_bytes)
    #     if args.base64:
    #         encrypted_bytes = base64.urlsafe_b64encode(encrypted_bytes)

    #     if args.output is not None:
    #         with open(args.output, "wb") as f:
    #             f.write(encrypted_bytes)
    #     else:
    #         print(encrypted_bytes)

    # elif args.decrypt:
    #     # Decrypt data using the given key.
    #     f = Fernet(fernet_key)

    #     if args.base64:
    #         input_bytes = base64.urlsafe_b64decode(input_bytes)
    #     decrypted_bytes = f.decrypt(input_bytes)

    #     if args.output is not None:
    #         with open(args.output, "wb") as f:
    #             f.write(decrypted_bytes)
    #     else:
    #         print(decrypted_bytes.decode())


if __name__ == "__main__":
    main()
