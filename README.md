# TLS-Crypto-Asymmetric

[English](README.md) | [中文](README.zh-CN.md)

[![Latest Stable Version](https://poser.pugx.org/tourze/tls-crypto-asymmetric/v)](https://packagist.org/packages/tourze/tls-crypto-asymmetric)
[![Total Downloads](https://poser.pugx.org/tourze/tls-crypto-asymmetric/downloads)](https://packagist.org/packages/tourze/tls-crypto-asymmetric)
[![License](https://poser.pugx.org/tourze/tls-crypto-asymmetric/license)](https://packagist.org/packages/tourze/tls-crypto-asymmetric)
[![PHP Version](https://img.shields.io/badge/php-%3E%3D8.1-blue.svg)](https://php.net/)
[![Coverage Status](https://img.shields.io/badge/coverage-%3E90%25-brightgreen.svg)]()

This package provides comprehensive asymmetric cryptography implementations for the TLS protocol.

## Table of Contents

- [Features](#features)
- [Installation](#installation)
- [Usage](#usage)
  - [RSA Encryption](#rsa-encryption)
  - [ECDSA Signatures](#ecdsa-signatures)
  - [Ed25519 Signatures](#ed25519-signatures)
  - [Ed448 Signatures](#ed448-signatures)
  - [DSA Signatures](#dsa-signatures)
  - [Signature Verification Utility](#signature-verification-utility)
- [Advanced Usage](#advanced-usage)
- [Supported Algorithms](#supported-algorithms)
- [Key Pair Structure](#key-pair-structure)
- [Exception Handling](#exception-handling)
- [Requirements](#requirements)
- [Testing](#testing)
- [Contributing](#contributing)
- [License](#license)

## Features

- **RSA** encryption and signatures (with PKCS#1, OAEP padding)
- **ECDSA** implementation (with multiple curve support)
- **EdDSA** (Ed25519, Ed448) implementation
- **DSA** and traditional signature algorithms
- **Key format handling** (PKCS#1, PKCS#8, etc.)
- **Signature verification** utilities
- **High-performance** cryptographic operations
- **Production-ready** with comprehensive test coverage
- **Easy-to-use** API with consistent interfaces

## Installation

```bash
composer require tourze/tls-crypto-asymmetric
```

## Usage

### RSA Encryption

```php
use Tourze\TLSCryptoAsymmetric\Cipher\RSA;

$rsa = new RSA();

// Generate key pair
$keyPair = $rsa->generateKeyPair(['keySize' => 2048]);

// Encrypt data
$plaintext = 'Hello, World!';
$ciphertext = $rsa->encrypt($plaintext, $keyPair['publicKey']);

// Decrypt data
$decrypted = $rsa->decrypt($ciphertext, $keyPair['privateKey']);

// Sign data
$signature = $rsa->sign($plaintext, $keyPair['privateKey']);

// Verify signature
$isValid = $rsa->verify($plaintext, $signature, $keyPair['publicKey']);
```

### ECDSA Signatures

```php
use Tourze\TLSCryptoAsymmetric\Cipher\ECDSA;

$ecdsa = new ECDSA();

// Generate key pair with specific curve
$keyPair = $ecdsa->generateKeyPair(['curve' => 'prime256v1']);

// Sign data
$data = 'Message to sign';
$signature = $ecdsa->sign($data, $keyPair['privateKey']);

// Verify signature
$isValid = $ecdsa->verify($data, $signature, $keyPair['publicKey']);
```

### Ed25519 Signatures

```php
use Tourze\TLSCryptoAsymmetric\Cipher\Ed25519;

$ed25519 = new Ed25519();

// Generate key pair
$keyPair = $ed25519->generateKeyPair();

// Sign data
$data = 'Message to sign';
$signature = $ed25519->sign($data, $keyPair['privateKey']);

// Verify signature
$isValid = $ed25519->verify($data, $signature, $keyPair['publicKey']);
```

### Ed448 Signatures

```php
use Tourze\TLSCryptoAsymmetric\Cipher\Ed448;

$ed448 = new Ed448();

// Generate key pair
$keyPair = $ed448->generateKeyPair();

// Sign data
$data = 'Message to sign';
$signature = $ed448->sign($data, $keyPair['privateKey']);

// Verify signature
$isValid = $ed448->verify($data, $signature, $keyPair['publicKey']);
```

### DSA Signatures

```php
use Tourze\TLSCryptoAsymmetric\Cipher\DSA;

$dsa = new DSA();

// Generate key pair
$keyPair = $dsa->generateKeyPair(['keySize' => 2048]);

// Sign data
$data = 'Message to sign';
$signature = $dsa->sign($data, $keyPair['privateKey']);

// Verify signature
$isValid = $dsa->verify($data, $signature, $keyPair['publicKey']);
```

### Signature Verification Utility

```php
use Tourze\TLSCryptoAsymmetric\Signature\SignatureVerifier;

$verifier = new SignatureVerifier();

// Verify signature with algorithm auto-detection
$isValid = $verifier->verify($data, $signature, $publicKey, $algorithm);
```

### KeyPair Utility Class

```php
use Tourze\TLSCryptoAsymmetric\KeyPair\KeyPair;

// Create KeyPair from array
$keyPairArray = $rsa->generateKeyPair();
$keyPair = KeyPair::fromArray($keyPairArray);

// Access keys
$privateKey = $keyPair->getPrivateKey();
$publicKey = $keyPair->getPublicKey();

// Convert back to array
$arrayFormat = $keyPair->toArray();
```

## Advanced Usage

### Custom RSA Key Generation

```php
$rsa = new RSA();

// Generate RSA key with custom parameters
$keyPair = $rsa->generateKeyPair([
    'keySize' => 4096,
    'digest_alg' => 'sha256',
    'private_key_type' => OPENSSL_KEYTYPE_RSA
]);
```

### ECDSA with Custom Curves

```php
$ecdsa = new ECDSA();

// Use specific elliptic curve
$keyPair = $ecdsa->generateKeyPair(['curve' => 'secp384r1']);

// Available curves: prime256v1, secp384r1, secp521r1
```

### Error Handling Best Practices

```php
try {
    $rsa = new RSA();
    $keyPair = $rsa->generateKeyPair();
    $encrypted = $rsa->encrypt($data, $keyPair['publicKey']);
} catch (AsymmetricCipherException $e) {
    // Handle cryptographic errors
    error_log('Crypto error: ' . $e->getMessage());
} catch (\Exception $e) {
    // Handle other errors
    error_log('General error: ' . $e->getMessage());
}
```

## Supported Algorithms

### RSA
- Key sizes: 512 (test only), 1024, 2048, 3072, 4096 bits
- Padding: PKCS#1 v1.5, OAEP
- Supports encryption/decryption and signing/verification

### ECDSA
- Curves: secp256r1 (prime256v1), secp384r1, secp521r1, and many others
- Supports signing/verification only

### EdDSA
- **Ed25519**: High-speed, high-security signatures
- **Ed448**: Enhanced security with larger key size
- Supports signing/verification only

### DSA
- Key sizes: 1024, 2048, 3072 bits
- Supports signing/verification only

## Key Pair Structure

All algorithms return key pairs in the following format:

```php
[
    'privateKey' => '-----BEGIN PRIVATE KEY-----...-----END PRIVATE KEY-----',
    'publicKey' => '-----BEGIN PUBLIC KEY-----...-----END PUBLIC KEY-----'
]
```

## Exception Handling

The package provides specific exceptions for different error conditions:

- `AsymmetricCipherException`: General cryptographic errors
- `CryptoException`: Base cryptographic exception
- `InvalidKeyPairException`: Invalid key pair errors
- `InvalidSignatureAlgorithmException`: Unsupported algorithm errors

```php
try {
    $keyPair = $rsa->generateKeyPair(['keySize' => 9999]);
} catch (AsymmetricCipherException $e) {
    echo 'Error: ' . $e->getMessage();
}
```

## Requirements

- PHP 8.1 or higher
- OpenSSL extension
- Sodium extension (for Ed25519/Ed448)
- Hash extension

## Testing

Run the test suite:

```bash
vendor/bin/phpunit
```

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

MIT
