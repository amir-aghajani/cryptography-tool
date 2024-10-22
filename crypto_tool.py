import os
import argparse
from cryptography.fernet import Fernet, InvalidToken


def load_key(key_path):
    """Load the encryption key from a file."""
    if not os.path.exists(key_path):
        raise FileNotFoundError(f"The key file '{key_path}' does not exist.")

    with open(key_path, "rb") as key_file:
        key = key_file.read()
    return key


def encrypt_file(file_path, key, output_file):
    """Encrypt the specified file and save it as a new file."""
    fernet = Fernet(key)

    with open(file_path, "rb") as file:
        file_data = file.read()

    encrypted_data = fernet.encrypt(file_data)

    with open(output_file, "wb") as file:
        file.write(encrypted_data)

    print(f"File '{file_path}' has been encrypted and saved as '{output_file}'.")


def decrypt_file(file_path, key, output_file):
    """Decrypt the specified file and save it as a new file."""
    fernet = Fernet(key)

    try:
        with open(file_path, "rb") as file:
            encrypted_data = file.read()

        decrypted_data = fernet.decrypt(encrypted_data)

        with open(output_file, "wb") as file:
            file.write(decrypted_data)

        print(f"File '{file_path}' has been decrypted and saved as '{output_file}'.")
    except InvalidToken:
        print("Error: The provided key is invalid or the file cannot be decrypted with this key.")


def main():
    parser = argparse.ArgumentParser(description='File encryption/decryption tool.')
    parser.add_argument('--key-path', required=True,
                        help='Specify the path for the key file (must end with .key)')
    parser.add_argument('--file', required=True,
                        help='Specify the path of the file to encrypt or decrypt')
    parser.add_argument('--mode', choices=['encrypt', 'decrypt'], required=True,
                        help='Specify the operation: "encrypt" or "decrypt"')
    parser.add_argument('--output', required=True,
                        help='Specify the path for the output file (for encrypted or decrypted content)')

    args = parser.parse_args()

    # Check if the key path ends with .key
    if not args.key_path.endswith('.key'):
        print("Error: The key file path must end with '.key'.")
        return

    # Load the key
    try:
        key = load_key(args.key_path)
    except FileNotFoundError as e:
        print(e)
        return

    # Check if the specified file exists
    if not os.path.exists(args.file):
        print(f"Error: The file '{args.file}' does not exist.")
        return

    if args.mode == 'encrypt':
        encrypt_file(args.file, key, args.output)
    elif args.mode == 'decrypt':
        decrypt_file(args.file, key, args.output)


if __name__ == "__main__":
    main()
