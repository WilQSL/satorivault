# SatoriVault v1.0.0

Secure password manager for Satori Network neuron vault.

## Description

SatoriVault is a command-line tool for managing Satori Network neuron vault passwords and private keys. It provides a secure way to change your neuron login password and manage encrypted vault files.

## Important Security Notes

- **ALWAYS** create a backup of your vault.yaml file before making any changes
- The vault password is the same as your neuron login password
- Never share your vault password or private keys
- Keep your backup files in a secure location

## Features

- AES-256 encryption for secure data storage
- Interactive menu-based interface
- Command-line interface for automation
- Automatic backup creation before password changes
- Password masking for enhanced security
- Support for custom vault file locations

## Installation

1. Clone the repository:
```bash
git clone https://github.com/WilQSL/satorivault.git
cd satorivault
```

2. Create a virtual environment:
```bash
python -m venv .venv
```

3. Activate the virtual environment:
- Windows:
```bash
.venv\Scripts\activate
```
- Linux/Mac:
```bash
source .venv/bin/activate
```

4. Install dependencies:
```bash
pip install -r requirements.txt
```

## Usage

### Interactive Mode

Run the program without arguments:
```bash
python satorivault.py
```

The program will display a menu with the following options:
1. Decrypt and view vault contents
2. Save decrypted vault to file
3. Change vault & neuron password
4. Exit

### Command-line Mode (Silent)

Change password automatically:
```bash
python satorivault.py --silent --old current_password --new new_password
```

Change password in a specific vault file:
```bash
python satorivault.py --silent --old current_password --new new_password --file /path/to/vault.yaml
```

### Command-line Parameters

- `--silent`: Run in non-interactive mode
- `--old current_password`: Current vault password (required in silent mode)
- `--new new_password`: New vault password (required in silent mode)
- `--file path`: Path to vault file (optional, defaults to vault.yaml in current directory)

## Security Features

- AES-256 encryption
- Password masking during input
- Automatic backup creation
- Secure file handling
- Error handling and validation

## Requirements

- Python 3.6 or higher
- pycryptodomex==3.19.1
- PyYAML

## Error Handling

The program provides clear error messages for:
- Invalid passwords
- Missing or corrupted files
- File access issues
- Encryption/decryption errors

## Backup Instructions

1. Before making any changes, the program automatically creates a backup
2. Backup files are named with timestamp: `vault_backup_YYYYMMDD_HHMMSS.yaml`
3. Keep your backup files in a secure location
4. Never delete backup files until you're sure the changes are successful

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Support

For support, please create an issue in the repository. 