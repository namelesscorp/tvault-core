# Example (tvault-core)

This directory contains examples for running the main commands:

- `seal` — create a protected container from a folder;
- `reseal` — repack / update an existing container;
- `unseal` — extract files from a container;
- `container info` — display container information.

## Preparation

It is recommended to run the commands from the repository root.

Before running the commands, create the required directories:

```shell
mkdir -p ./example/seal ./example/decrypt ./example/log
```

Put the files you want to seal into:

```text
./example/seal
```

## 1. Seal — create a container

This command creates the `vault.tvlt` container from the contents of the `./example/seal` folder.

```shell
tvault-core \
    seal \
      container \
        -tags="docs" \
        -name="hello" \
        -new-path="./example/vault.tvlt" \
        -folder-path="./example/seal" \
        -passphrase="test1234" \
      compression \
        -type="zip" \
      token \
        -type="share" \
      token-writer \
        -type="file" \
        -format="json" \
        -path="./example/keys.json" \
      integrity-provider \
        -type="hmac" \
        -new-passphrase="1234" \
      shamir \
        -is-enabled=true \
      log-writer \
        -type="file" \
        -format="json" \
        -path="./example/log/seal.log"
```

After running the command, the following files will be created:

```text
./example/vault.tvlt
./example/keys.json
./example/log/seal.log
```

## 2. Reseal — update the container

This command reseals the container using the existing container and keys.

```shell
tvault-core \
    reseal \
      container \
        -current-path="./example/vault.tvlt" \
        -new-path="./example/vault.tvlt" \
        -folder-path="./example/seal" \
        -passphrase="test1234" \
        -comment="" \
        -tags="" \
      integrity-provider \
        -current-passphrase="1234" \
      token-reader \
        -type="file" \
        -format="json" \
        -path="./example/keys.json" \
      log-writer \
        -type="stdout" \
        -format="json"
```

## 3. Unseal — extract the container

This command extracts the container contents into the `./example/decrypt` folder.

```shell
tvault-core \
    unseal \
      container \
        -current-path="./example/vault.tvlt" \
        -folder-path="./example/decrypt" \
      token-reader \
        -type="file" \
        -format="json" \
        -path="./example/keys.json" \
      integrity-provider \
        -current-passphrase="1234" \
      log-writer \
        -type="stdout" \
        -format="json"
```

After running the command, the decrypted files will be available in:

```text
./example/decrypt
```

## 4. Container info — show container information

This command prints information about the container.

```shell
tvault-core \
    container \
      info \
        -path="./example/vault.tvlt"
```

## Full scenario

```shell
mkdir -p ./example/seal ./example/decrypt ./example/log

tvault-core \
    seal \
      container \
        -tags="docs" \
        -name="hello" \
        -new-path="./example/vault.tvlt" \
        -folder-path="./example/seal" \
        -passphrase="test1234" \
      compression \
        -type="zip" \
      token \
        -type="share" \
      token-writer \
        -type="file" \
        -format="json" \
        -path="./example/keys.json" \
      integrity-provider \
        -type="hmac" \
        -new-passphrase="1234" \
      shamir \
        -is-enabled=true \
      log-writer \
        -type="file" \
        -format="json" \
        -path="./example/log/seal.log"

tvault-core \
    container \
      info \
        -path="./example/vault.tvlt"
        
tvault-core \
    unseal \
      container \
        -current-path="./example/vault.tvlt" \
        -folder-path="./example/decrypt" \
      token-reader \
        -type="file" \
        -format="json" \
        -path="./example/keys.json" \
      integrity-provider \
        -current-passphrase="1234" \
      log-writer \
        -type="stdout" \
        -format="json"
```

## Files used in this example

| Path | Description |
| --- | --- |
| `./example/seal` | Source folder with files to seal |
| `./example/vault.tvlt` | Created container |
| `./example/keys.json` | Token / keys file |
| `./example/decrypt` | Folder for extracted files |
| `./example/log/seal.log` | Seal command log file |

## Test passphrases

| Purpose | Value |
| --- | --- |
| Container passphrase | `test1234` |
| Integrity passphrase | `1234` |

> Do not use these values in production.