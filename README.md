# Tvault Core

## 📋Description

TVault Core is a foundational library for creating and managing secure data vaults. 
It provides functionality for encryption, decryption, integrity verification, and secret sharing.

## 🚀 Features

- **Encryption & Decryption** — secure storage and retrieval of sensitive data
- **Integrity Verification** — using HMAC and ED25519 to ensure authenticity
- **Shamir's Secret Sharing** — distribute secrets for enhanced security 
- **Data Compression** — efficient storage using various compression algorithms
- **Containerization** — unified format for storing encrypted data

## 🛠️ Installation

### Download releases

[TVault Releases](https://github.com/namelesscorp/tvault-core/releases)

### Go

```shell
go get github.com/namelesscorp/tvault-core
```

## 🚩 Command-Line Usage

TVault Core can be run as a standalone application with various command-line flags.

### Basic Command Structure

```shell
tvault-core [command] [flags]
```

### Available Commands

- `encrypt` - encrypt directories
- `decrypt` - decrypt tvault container
- `info` - information about application
- `version` - cli, container, token supported versions

### Common Flags

```shell
# Encryption Options (without integrity provider)
tvault-core encrypt
-container-path="./example/vault.tvlt"
-compression-type="zip"
-folder-path="./example/vault"
-passphrase="test1234"
-token-save-type="stdout"
-integrity-provider="none"
-is-shamir-enabled=true

# Encryption Options (with integrity provider)
tvault-core encrypt
-container-path="./example/vault.tvlt"
-compression-type="zip"
-folder-path="./example/vault"
-passphrase="test-passphrase"
-token-save-type="stdout"
-integrity-provider="hmac"
-is-shamir-enabled=true
-additional-password="test-password"

# Decryption Options (Multiple tokens, separate '|')
tvault-core decrypt
-container-path="./example/vault.tvlt"
-folder-path="./example/vault"
-token="Qwerty1234...|Ytrewq4321..."
-additional-password="test-password"

# Decryption Options (Master token)
tvault-core decrypt
-container-path="./example/vault.tvlt"
-folder-path="./example/vault"
-token="Qwerty1234..."
-additional-password="test-password"

# Decryption Options (without integrity provider)
tvault-core decrypt
-container-path="./example/vault.tvlt"
-folder-path="./example/vault"
-token="Qwerty1234..."
```

## 📂 Project Structure

- **cmd** — application entry point
- **compression** — compression modules
- **container** — storage container management
- **decrypt** — decryption functionality
- **encrypt** — encryption functionality
- **integrity_provider** — integrity verification (provider) modules
- **lib** — common library functions
- **shamir** — implementation of Shamir's Secret Sharing
- **token** — authentication token management

## 🤝 Contributing
We welcome contributions to the project. 
Detailed information about the development process, commit formatting, and creating merge requests can be found in [CONTRIBUTING.md](CONTRIBUTING.md).

## 📝 License
TVault Core is proprietary software. 
Use of this code is governed by the license agreement.

## 📞 Contact
If you have questions or issues, please create an Issue in the repository or contact the development team.

- [tvault.app](https://tvault.app)
- support@tvault.app

- [nameless.company](https://nameless.company)
- support@nameless.company

---

© 2025 Trust Vault And NameLess Corp. All rights reserved.
