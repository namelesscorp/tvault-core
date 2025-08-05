# Trust Vault Core

## Table of Contents
- [Description](#description)
- [Key Features](#key-features)
    - [Comprehensive File and Directory Encryption](#comprehensive-file-and-directory-encryption)
    - [Advanced Key Management](#advanced-key-management)
    - [Data Integrity Assurance](#data-integrity-assurance)
    - [Versatile Interface](#versatile-interface)
- [Security Features](#security-features)
- [Installation](#installation)
    - [Download](#download)
    - [Go](#go)
    - [From Source](#from-source)
- [Core Components](#core-components)
    - [Seal](#seal)
    - [Unseal](#unseal)
    - [Reseal](#reseal)
- [Token Types](#token-types)
    - [None Type](#none-type)
    - [Master Type](#master-type)
    - [Share Type](#share-type)
- [Integrity Verification](#integrity-verification)
    - [None (No Verification)](#none-no-verification)
    - [HMAC (Hash-based Message Authentication Code)](#hmac-hash-based-message-authentication-code)
    - [Ed25519 (Digital Signature)](#ed25519-digital-signature)
- [Security Best Practices](#security-best-practices)
- [Contributing](#contributing)
- [License](#license)
- [Contact](#contact)

## Description

TVault Core is an advanced open-source cryptographic system designed to provide reliable protection for confidential data using modern encryption algorithms.
This platform offers a comprehensive toolkit for securing files and directories, managing cryptographic keys, and ensuring data integrity.
Developed with principles of modularity and flexibility in mind, TVault Core offers both a command-line interface for simple use and a programming API for deep integration into custom applications. 
The system supports multiple mechanisms for storing and distributing encryption keys, including advanced secret sharing methods.

## Key Features

### Comprehensive File and Directory Encryption

- **Robust Data Protection**: Using the AES-256 standard for encryption
- **Directory Structure Preservation**: Complete preservation of file hierarchy during encryption
- **Built-in Compression**: Reduction of encrypted container size
- **Container Metadata**: Storage of creation time, update information, and user comments

### Advanced Key Management

- **Access Tokens**: Creation and management of tokens for secure key distribution
- **Shamir's Secret Sharing Scheme**: Division of the master key into multiple parts requiring a specified threshold for recovery
- **Multi-level Protection**: Support for additional passwords to enhance security
- **Flexible Configuration**: Customizable parameters for any usage scenario

### Data Integrity Assurance

- **HMAC Verification**: Prevention of tampering or modification of encrypted data
- **Independent Integrity Providers**: Separate mechanisms for data authenticity verification
- **Digital Signature Support**: Extensibility for using digital signature algorithms

### Versatile Interface

- **Command Line**: Full-featured CLI for all operations
- **Programming API**: Integration into applications via Go API
- **Flexible Output Formats**: Support for plaintext and JSON formats for all operations
- **Advanced Error Handling**: Detailed error information for simplified debugging

## Security Features

- **AES-256 Encryption**: Industry-standard encryption algorithm
- **PBKDF2 Key Derivation**: Secure password-based key generation
- **HMAC Integrity Verification**: Prevents tampering with encrypted data
- **Distributed Key Management**: Split keys using Shamir's Secret Sharing
- **Multiple Token Formats**: Support for different token storage methods

## Installation

### Download

[Releases](https://github.com/namelesscorp/tvault-core/releases)

### Go

```shell
go get github.com/namelesscorp/tvault-core
```

### From Source

```shell
git clone https://github.com/namelesscorp/tvault-core.git
cd tvault-core
make build
```

## Core Components

### Seal

The `seal` module is responsible for encrypting directories, creating secure containers, and generating access tokens. 
It supports various compression algorithms, key management methods, and integrity assurance mechanisms.

The sealing process includes:
1. Compressing the specified directory
2. Generating a cryptographically strong key
3. Encrypting the compressed data
4. Creating and saving access tokens
5. Forming container metadata


```shell
tvault seal \
container \
  -new-path="/path/to/output.tvlt" \
  -folder-path="/path/to/folder" \
  -passphrase="your-secure-passphrase" \
compression \
  -type="zip" \
token \
  -type="share" \
token-writer \
  -type="file" \
  -format="json" \
  -path="/path/to/token/file" \
integrity-provider \
  -type="hmac" \
  -new-passphrase="your-integrity-password" \
shamir \
  -is-enabled=true \
  -shares=5 \
  -threshold=3 \
log-writer \
  -type="stdout" \
  -format="json"
```

### Unseal

The `unseal` module performs the reverse process, decrypting containers using the appropriate tokens or passwords. 
It verifies data integrity, decrypts the content, and restores the original directory structure.

The unsealing process includes:
1. Reading and verifying container metadata
2. Restoring the master key from tokens or password
3. Verifying data integrity
4. Decrypting the container
5. Unpacking and restoring the original files and directories


```shell
tvault unseal \
container \
  -current-path="/path/to/container.tvlt" \
  -folder-path="/path/to/output" \
  -passphrase="your-passphrase" \
token-reader \
  -type="file" \
  -format="json" \
  -path="/path/to/token/file" \
integrity-provider \
  -current-passphrase="your-integrity-password" \
log-writer \
  -type="stdout" \
  -format="json"
```

### Reseal

The `reseal` module allows updating the content of an existing container without changing its token structure and keys. 
This is particularly useful for regularly updating encrypted data without the need to distribute new tokens.

The resealing process includes:
1. Decrypting the existing container
2. Compressing new data
3. Encrypting the updated content using the same key
4. Updating container metadata
5. Generating new tokens with the same cryptographic key

```shell
tvault reseal \
container \
  -current-path="/path/to/original.tvlt" \
  -new-path="/path/to/updated.tvlt" \
  -folder-path="/path/to/new/content" \
token-reader \
  -type="file" \
  -format="json" \
  -path="/path/to/token/file" \
token-writer \
  -type="file" \
  -format="json" \
  -path="/path/to/updated/token/file" \
integrity-provider \
  -current-passphrase="your-integrity-password" \
log-writer \
  -type="stdout" \
  -format="json"
```

## Token Types

TVault Core supports multiple token types:

### None Type
Encryption using only a password, without creating a separate token. 
This method is simple to use but requires secure storage and transmission of the password.

### Master Type
A single token containing the master key, encrypted using a password. 
This approach provides an additional layer of security by separating the key and password.

### Share Type
Multiple tokens using Shamir's Secret Sharing scheme.
This method allows distributing access among multiple participants, requiring a certain number of tokens to decrypt the data.

## Integrity Verification

TVault Core includes multiple integrity providers:

### None (No Verification)
Basic mode without integrity verification. 
Suitable for non-critical data or cases where integrity is ensured by external means.

### HMAC (Hash-based Message Authentication Code)
Using cryptographic hash functions to ensure data integrity and authenticity.
Requires an additional password to enhance protection.

### Ed25519 (Digital Signature)
A promising mechanism based on the Ed25519 digital signature algorithm, providing a high level of protection against data forgery.

## Security Best Practices

- **Separate Storage**: Store tokens separately from encrypted containers
- **Strong Passwords**: Use complex, unique passwords for containers and integrity verification
- **Token Backups**: Regularly create backups of tokens — without them, data recovery is impossible
- **Distributed Access**: For critical data, use the Shamir scheme with a reasonable threshold
- **Periodic Updates**: Regularly update containers using the reseal function
- **Secure Channels**: Transmit tokens only through secure communication channels
- **Integrity Verification**: Always use integrity verification mechanisms for critical data

## Contributing
We welcome contributions to the project. 
Detailed information about the development process, commit formatting, and creating merge requests can be found in [CONTRIBUTING.md](CONTRIBUTING.md).

## License
TVault Core is proprietary software. 
Use of this code is governed by the [license](LICENSE) agreement.

## Contact
If you have questions or issues, please create an Issue in the repository or contact the development team.

- [tvault.app](https://tvault.app)
- support@tvault.app

- [nameless.company](https://nameless.company)
- support@nameless.company

---

© 2025 Trust Vault. All rights reserved.
