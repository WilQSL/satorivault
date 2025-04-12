import os
import sys
import yaml
import base64
import argparse
import msvcrt
from datetime import datetime
try:
    from Crypto.Cipher import AES
    from Crypto.Protocol.KDF import PBKDF2
    from Crypto.Random import get_random_bytes
    from Crypto.Util.Padding import pad, unpad
except ImportError:
    from Cryptodome.Cipher import AES
    from Cryptodome.Protocol.KDF import PBKDF2
    from Cryptodome.Random import get_random_bytes
    from Cryptodome.Util.Padding import pad, unpad

# Program constants
VERSION = "1.0.0"
AUTHOR = "by WilQSL"
PROGRAM_DESCRIPTION = "Secure password manager for Satori Network neuron vault"
DEFAULT_VAULT_FILE = "vault.yaml"

# Menu constants
MENU_OPTIONS = {
    "1": "Decrypt and view vault contents",
    "2": "Save decrypted vault to file",
    "3": "Change vault & neuron password",
    "4": "Exit"
}

# Color constants
COLORS = {
    'HEADER': '\033[95m',
    'OKBLUE': '\033[94m',
    'OKGREEN': '\033[92m',
    'WARNING': '\033[93m',
    'FAIL': '\033[91m',
    'ENDC': '\033[0m',
    'BOLD': '\033[1m',
    'UNDERLINE': '\033[4m'
}

def print_color(text, color, silent=False):
    """Print text in specified color"""
    if not silent:
        print(f"{COLORS[color]}{text}{COLORS['ENDC']}")

def print_header(silent=False):
    """Print program header"""
    if not silent:
        os.system('cls' if os.name == 'nt' else 'clear')
        print("\n" + "="*60)
        print_color("SatoriVault", 'HEADER')
        print_color(f"Version: {VERSION} {AUTHOR}", 'OKBLUE')
        print("\n" + "-"*60)
        print_color(PROGRAM_DESCRIPTION, 'OKBLUE')
        print("-"*60)
        print("="*60 + "\n")

def print_menu(silent=False):
    """Print program menu"""
    if not silent:
        print("\n" + "-"*40)
        print_color("Main Menu", 'HEADER')
        for key, value in MENU_OPTIONS.items():
            print(f"{key}. {value}")
        print("-"*40)

def print_warning(message, silent=False):
    """Print warning message"""
    if not silent:
        print_color(f"WARNING: {message}", 'WARNING')

def print_error(message, silent=False):
    """Print error message"""
    if not silent:
        print_color(f"ERROR: {message}", 'FAIL')

def print_success(message, silent=False):
    """Print success message"""
    if not silent:
        print_color(f"SUCCESS: {message}", 'OKGREEN')

def print_status(message, silent=False):
    """Print status message"""
    if not silent:
        print_color(f"STATUS: {message}", 'OKBLUE')

def handle_error(message, silent=False):
    """Handle error and wait for Enter"""
    print_error(message, silent)
    if not silent:
        input("\nPress Enter to return to main menu...")
    return False

def get_password(prompt):
    """Get password with asterisk display"""
    print(prompt, end='', flush=True)
    password = []
    while True:
        char = msvcrt.getch()
        if char == b'\r' or char == b'\n':  # Enter
            print()
            break
        elif char == b'\x08':  # Backspace
            if password:
                password.pop()
                print('\b \b', end='', flush=True)
        else:
            password.append(char.decode())
            print('*', end='', flush=True)
    return ''.join(password)

def create_backup(vault_path, silent=False):
    """Create backup of vault file"""
    try:
        if not os.path.exists(vault_path):
            return handle_error(f"File {vault_path} not found", silent)
            
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_path = f"vault_backup_{timestamp}.yaml"
        
        with open(vault_path, 'rb') as src, open(backup_path, 'wb') as dst:
            dst.write(src.read())
            
        print_success(f"Backup created: {backup_path}", silent)
        return True
    except Exception as e:
        return handle_error(f"Failed to create backup: {str(e)}", silent)

def save_decrypted_data(data, filename, silent=False):
    """Save decrypted data to file"""
    try:
        with open(filename, 'w') as f:
            yaml.dump(data, f, default_flow_style=False)
        print_success(f"Decrypted data saved to {filename}", silent)
        return True
    except Exception as e:
        return handle_error(f"Failed to save decrypted data: {str(e)}", silent)

def encrypt(content, password: str) -> str:
    """Encrypt content using AES with key derived from password"""
    salt = get_random_bytes(16)
    key = PBKDF2(password, salt, dkLen=32, count=1000000)
    cipher = AES.new(key, AES.MODE_CBC)
    ctBytes = cipher.encrypt(pad(content.encode(), AES.block_size))
    return base64.b64encode(salt + cipher.iv + ctBytes).decode()

def decrypt(encrypted, password: str) -> str:
    """Decrypt content encrypted by encrypt_content function"""
    encryptedBytes = base64.b64decode(encrypted)
    salt = encryptedBytes[:16]
    iv = encryptedBytes[16:32]
    ct = encryptedBytes[32:]
    key = PBKDF2(password, salt, dkLen=32, count=1000000)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    pt = unpad(cipher.decrypt(ct), AES.block_size).decode()
    return pt

def encryptMapValues(content: dict, password: str, keys: list = None) -> dict:
    """Encrypt all values in dictionary, even if nested"""
    if password is None:
        return content
    encrypted = {}
    keys = keys or []
    for k, v in content.items():
        if isinstance(v, str) and (len(k) == 0 or (len(k) > 0 and k in keys)):
            encrypted[k] = encrypt(v, password)
        elif isinstance(v, dict):
            encrypted[k] = encryptMapValues(v, password, keys)
        else:
            encrypted[k] = v
    return encrypted

def decryptMapValues(encrypted: dict, password: str, keys: list = None) -> dict:
    """Decrypt all values in dictionary, even if nested"""
    if password is None:
        return encrypted
    decrypted = {}
    keys = keys or []
    for k, v in encrypted.items():
        if isinstance(v, str) and (len(k) == 0 or (len(k) > 0 and k in keys)):
            decrypted[k] = decrypt(v, password)
        elif isinstance(v, dict):
            decrypted[k] = decryptMapValues(v, password, keys)
        else:
            decrypted[k] = v
    return decrypted

def load_yaml(path: str):
    """Load YAML file"""
    if os.path.exists(path):
        with open(path, 'r') as f:
            return yaml.safe_load(f) or {}
    return {}

def save_yaml(data: dict, path: str):
    """Save data to YAML file"""
    with open(path, 'w') as f:
        yaml.dump(data, f, default_flow_style=False)

def decrypt_vault(vault_path, password, silent=False):
    """Attempt to decrypt vault.yaml file with given password"""
    try:
        encrypted_data = load_yaml(vault_path)
        if not encrypted_data:
            handle_error(f"Could not find {vault_path} file", silent)
            return None
            
        decrypted_data = decryptMapValues(
            encrypted=encrypted_data,
            password=password,
            keys=['entropy', 'privateKey', 'words']
        )
        
        if 'entropy' in decrypted_data and decrypted_data['entropy']:
            print_success("Successfully decrypted the file!", silent)
            return decrypted_data
        else:
            handle_error("Invalid password!", silent)
            return None
            
    except Exception as e:
        handle_error(f"Error during decryption: {str(e)}", silent)
        return None

def encrypt_vault(vault_path, data, password, silent=False):
    """Encrypt data and save to vault.yaml"""
    try:
        encrypted_data = encryptMapValues(
            content=data,
            password=password,
            keys=['entropy', 'privateKey', 'words']
        )
        
        save_yaml(encrypted_data, vault_path)
        print_success("Successfully encrypted and saved the file!", silent)
        return True
        
    except Exception as e:
        handle_error(f"Error during encryption: {str(e)}", silent)
        return False

def main():
    parser = argparse.ArgumentParser(
        description='SatoriVault - Neuron Vault Password Manager',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Silent Mode Usage Examples:
  python satorivault.py --silent --old current_password --new new_password
    - Changes the vault password from 'current_password' to 'new_password'
    - Automatically creates a backup before changing the password
    - Returns success or error message

  python satorivault.py --silent --old current_password --new new_password --file /path/to/vault.yaml
    - Changes the password in specified vault file
    - Automatically creates a backup before changing the password
    - Returns success or error message

Required Parameters in Silent Mode:
  --old current_password    Current vault password
  --new new_password       New vault password to set

Optional Parameters:
  --file path              Path to vault file (default: vault.yaml in current directory)

Note: In silent mode, both --old and --new parameters are required.
      The program will automatically create a backup before changing the password.
""")
    parser.add_argument('--silent', action='store_true', help='Run in silent mode (non-interactive)')
    parser.add_argument('--old', type=str, help='Current vault password (required in silent mode)')
    parser.add_argument('--new', type=str, help='New vault password (required in silent mode)')
    parser.add_argument('--file', type=str, help='Path to vault file (default: vault.yaml in current directory)')
    
    args = parser.parse_args()
    vault_path = args.file if args.file else DEFAULT_VAULT_FILE
    
    if args.silent:
        if not args.old or not args.new:
            print("ERROR: In silent mode both --old and --new parameters are required")
            return 1
            
        if not create_backup(vault_path, silent=True):
            return 1
            
        decrypted_data = decrypt_vault(vault_path, args.old, silent=True)
        if decrypted_data:
            if encrypt_vault(vault_path, decrypted_data, args.new, silent=True):
                print("SUCCESS: Password successfully changed!")
                return 0
            else:
                print("ERROR: Failed to encrypt with new password")
                return 1
        else:
            print("ERROR: Invalid password!")
            return 1
    else:
        print_header()
        print_warning("ALWAYS create a backup of your vault.yaml file before making any changes!")
        
        while True:
            print_header()
            print_menu()
            choice = input("Choose an option (1-4): ")
            
            if choice == "1":
                print_status("Decrypting vault...")
                password = get_password("Enter vault password: ")
                decrypted_data = decrypt_vault(vault_path, password)
                
                if decrypted_data:
                    print("\n" + "-"*40)
                    print_color("Vault Contents", 'HEADER')
                    print(yaml.dump(decrypted_data, default_flow_style=False))
                    print("-"*40)
                    input("\nPress Enter to return to main menu...")
                    
            elif choice == "2":
                print_status("Saving decrypted vault...")
                password = get_password("Enter vault password: ")
                decrypted_data = decrypt_vault(vault_path, password)
                
                if decrypted_data:
                    filename = input("Enter filename to save decrypted data (default: decrypted_vault.yaml): ")
                    if not filename:
                        filename = "decrypted_vault.yaml"
                    if save_decrypted_data(decrypted_data, filename):
                        input("\nPress Enter to return to main menu...")
                    
            elif choice == "3":
                print_status("Changing vault password...")
                if not create_backup(vault_path):
                    continue
                    
                old_password = get_password("Enter current vault password: ")
                decrypted_data = decrypt_vault(vault_path, old_password)
                
                if decrypted_data:
                    new_password = get_password("Enter new vault password: ")
                    confirm_password = get_password("Confirm new vault password: ")
                    
                    if new_password == confirm_password:
                        if encrypt_vault(vault_path, decrypted_data, new_password):
                            print_success("Vault password successfully changed!")
                            input("\nPress Enter to return to main menu...")
                    else:
                        handle_error("Passwords do not match!")
                        
            elif choice == "4":
                print("\n" + "="*60)
                print_color("Thank you for using SatoriVault!", 'OKBLUE')
                print("="*60 + "\n")
                break
                
            else:
                handle_error("Invalid choice!")

if __name__ == "__main__":
    sys.exit(main()) 