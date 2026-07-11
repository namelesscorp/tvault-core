# Security score (tvault-core)

## Description

The `security` package provides a security scoring mechanism for encrypted containers in the TVault Core project.

It analyzes container configuration parameters and calculates a normalized security score from `0.0` to `1.0`. The score helps estimate how strong the selected protection settings are, including token type, integrity provider, compression, Shamir shares, thresholds, passphrase length, and the presence of sensitive files.

## Features

- Calculates an overall security score for a container configuration
- Provides a human-readable security level
- Returns detailed per-category scoring
- Detects potentially sensitive file names and extensions
- Evaluates token and integrity provider choices
- Considers Shamir's Secret Sharing parameters
- Estimates passphrase strength based on length

## Security Levels

The final score is mapped to one of the following levels:

| Score range | Level       | Description                    |
|-------------|-------------|--------------------------------|
| `0.90–1.00` | `excellent` | Strong security configuration  |
| `0.70–0.89` | `good`      | Good protection level          |
| `0.50–0.69` | `moderate`  | Acceptable but can be improved |
| `0.30–0.49` | `weak`      | Weak protection level          |
| `0.00–0.29` | `critical`  | Critical security risk         |

## Scoring Categories

The package calculates the score using weighted categories:

| Category                      | Weight | Description                                    |
|-------------------------------|--------|------------------------------------------------|
| Sensitive files               | `0.10` | Checks whether sensitive files are present     |
| Integrity provider            | `0.15` | Evaluates the selected integrity provider      |
| Token                         | `0.15` | Evaluates the selected token type              |
| Compression                   | `0.05` | Checks whether compression is enabled          |
| Shares                        | `0.15` | Evaluates the number of Shamir shares          |
| Thresholds                    | `0.10` | Evaluates the Shamir threshold-to-shares ratio |
| Container passphrase          | `0.15` | Evaluates container passphrase strength        |
| Integrity provider passphrase | `0.15` | Evaluates integrity provider passphrase length |

## Supported Values

### Token Types

| Type     | Score | Description                        |
|----------|-------|------------------------------------|
| `share`  | `1.0` | Secret is split into Shamir shares |
| `master` | `0.5` | Master token is used directly      |
| `none`   | `0.0` | No token protection is used        |

### Integrity Providers

| Type      | Score | Description                        |
|-----------|-------|------------------------------------|
| `ed25519` | `1.0` | Ed25519 signature-based protection |
| `hmac`    | `0.7` | HMAC-based integrity protection    |
| `none`    | `0.0` | No integrity protection is used    |

### Compression Types

| Type   | Score | Description                |
|--------|-------|----------------------------|
| `zip`  | `1.0` | ZIP compression is enabled |
| `none` | `0.0` | Compression is disabled    |

## Sensitive File Detection

The package detects sensitive files using file extensions and filename patterns.

### Sensitive Extensions

Examples of sensitive extensions:

- `.key`
- `.pem`
- `.crt`
- `.password`
- `.secret`
- `.env`
- `.config`
- `.settings`
- `.log`

### Sensitive Filename Patterns

Examples of sensitive filename patterns:

- `password`
- `secret`
- `key`
- `token`
- `credential`
- `auth`
- `private`
- `cert`
- `certificate`
- `sensitive`

If at least one file matches a sensitive extension or pattern, the sensitive files category receives the maximum score.

## Passphrase Scoring

Passphrase strength is estimated by length:

| Passphrase length | Score |
|-------------------|-------|
| Empty             | `0.0` |
| Less than 8       | `0.3` |
| 8–15              | `0.6` |
| 16–23             | `0.8` |
| 24 or more        | `1.0` |

## Shamir Scoring

### Shares

The number of Shamir shares is scored using the following rule:
```text
min(number_of_shares / 5, 1.0)
```

Examples:

| Shares | Score |
|--------|-------|
| `0`    | `0.0` |
| `1`    | `0.2` |
| `3`    | `0.6` |
| `5`    | `1.0` |
| `10`   | `1.0` |

### Thresholds

The threshold score is based on the threshold-to-shares ratio:
```text
 min(threshold / shares, 1.0)
```

Examples:

| Shares | Threshold | Score |
|--------|-----------|-------|
| `5`    | `1`       | `0.2` |
| `5`    | `3`       | `0.6` |
| `5`    | `5`       | `1.0` |

A higher threshold means a stricter quorum is required to recover the secret.

## Security Considerations

- The score is a heuristic and should not be treated as a formal cryptographic security proof
- Strong passphrases should always be used for both container encryption and integrity protection
- `share` tokens are recommended when distributed key recovery is required
- Integrity protection should not be disabled for sensitive data
- A higher Shamir threshold improves protection but may reduce recoverability
- Sensitive file detection is based on names and extensions, not file contents
- Compression may slightly obscure internal structure but must not be treated as encryption

## Recommended Configuration

For strong protection, use:

- Token type: `share`
- Integrity provider: `hmac` or `ed25519`
- Compression: `zip`
- Shares: `5` or more
- Threshold: at least `3`
- Container passphrase: 24+ characters
- Integrity provider passphrase: 24+ characters