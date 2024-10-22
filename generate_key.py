import os
import base64
import argparse
import getpass
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet


def generate_random_key(key_path):
    """Generate a random key and save it to the specified path."""
    key = Fernet.generate_key()
    with open(key_path, "wb") as key_file:
        key_file.write(key)
    print(f"Random key generated and saved as '{key_path}'.")


def generate_key_from_password(key_path, password):
    """Generate a key from the given password and save it."""
    salt = b"constant_salt_value"  # Fixed salt for reproducibility
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key = base64.urlsafe_b64encode(kdf.derive(password.encode()))

    with open(key_path, "wb") as key_file:
        key_file.write(key)

    print(f"Key derived from password and saved as '{key_path}'.")


def main():
    parser = argparse.ArgumentParser(description='Key generation tool.')
    parser.add_argument('--method', choices=['random', 'password'], required=True,
                        help='Specify the key generation method: "random" or "password"')
    parser.add_argument('--key-path', default='secret.key',
                        help='Specify the path for the key file (default is "secret.key", must end with .key)')

    args = parser.parse_args()

    # Check if the key path ends with .key
    if not args.key_path.endswith('.key'):
        print("Error: The key file path must end with '.key'.")
        return

    if os.path.exists(args.key_path):
        overwrite = input(
            f"The key file '{args.key_path}' already exists. Do you want to overwrite it? (y/n): ").strip().lower()
        if overwrite != 'y':
            print("Operation canceled. The key was not overwritten.")
            return

    if args.method == 'random':
        generate_random_key(args.key_path)
    elif args.method == 'password':
        print("Note: The password input will be hidden for security.")
        password = getpass.getpass("Enter a password: ")
        generate_key_from_password(args.key_path, password)


if __name__ == "__main__":
    main()
