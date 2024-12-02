# Encryption Tool

Encrypt or decrypt text using a series of phrases.

The script will prompt for a series of phrases. Phrases are hidden unless `--show-phrases` is used.

After phrases have been entered, the script prompts for text to encrypt or decrypt. Encryption output and decryption input are base64 encoded unless `--no-base64` is used.

## Encryption

Default behavior is to encrypt text. Run with one of the following:

- Run from Docker: `docker run -it --rm dockmann/encryption`
- Run from script: `sh run-it.sh`
- Run from source: `python encryption.py`

## Decryption

Pass the `--decrypt` flag to decrypt text.

- Run from Docker: `docker run -it --rm dockmann/encryption --decrypt`
- Run from script: `sh run-it.sh --decrypt`
- Run from source: `python encryption.py --decrypt`
