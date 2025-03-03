# ReplaceCrypt

ReplaceCrypt is an in-place encryption and decryption tool for files and directories. It replaces the original file with its encrypted or decrypted version and uses a unique magic header to prevent accidental double encryption or decryption.

## Overview

ReplaceCrypt uses strong AES encryption and ensures that files are processed only once by marking them with a magic header. It supports both single file operations and recursive processing of directories, making it easy to secure your data without the need for separate output files.

## Features

- **In-Place Operations:** Encrypt or decrypt files directly in their original location.
- **Recursive Directory Support:** Process all files within a directory and its subdirectories.
- **Magic Header Protection:** Prevents accidental double encryption or decryption by marking processed files.
- **Simple Command-Line Interface:** Easy-to-use interactive prompts for quick operations.

## Requirements

- Python 3.6 or higher
- [cryptography](https://pypi.org/project/cryptography/) library

## Installation

1. **Clone the repository:**
   ```bash
   git clone https://github.com/yourusername/ReplaceCrypt.git
   cd ReplaceCrypt
   ```

2. **(Optional) Create a virtual environment:**
   ```bash
   python -m venv venv
   source venv/bin/activate   # On Windows: venv\Scripts\activate
   ```

3. **Install the dependencies:**
   ```bash
   pip install cryptography
   ```

## Usage

Run the script from the command line:
```bash
python cryptor.py
```

Follow the interactive prompts:
- Choose between encryption (`E`) or decryption (`D`).
- Provide the path to the file or directory.
- Enter the password for the operation.

**Note:**  
- During encryption, if a file already contains the magic header, it will be skipped.
- During decryption, if a file does not contain the magic header, it will be skipped.

## Warning

**Data Overwrite Risk:**  
ReplaceCrypt modifies files in-place. Please backup your data before using this tool to avoid accidental data loss.

## Contributing

Contributions, bug reports, and feature requests are welcome!  
Fork the repository and submit a pull request with your improvements.

## License

ReplaceCrypt is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.