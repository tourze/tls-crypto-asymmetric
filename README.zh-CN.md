# TLS-Crypto-Asymmetric

[English](README.md) | [中文](README.zh-CN.md)

[![Latest Stable Version](https://poser.pugx.org/tourze/tls-crypto-asymmetric/v)](https://packagist.org/packages/tourze/tls-crypto-asymmetric)
[![Total Downloads](https://poser.pugx.org/tourze/tls-crypto-asymmetric/downloads)](https://packagist.org/packages/tourze/tls-crypto-asymmetric)
[![License](https://poser.pugx.org/tourze/tls-crypto-asymmetric/license)](https://packagist.org/packages/tourze/tls-crypto-asymmetric)
[![PHP Version](https://img.shields.io/badge/php-%3E%3D8.1-blue.svg)](https://php.net/)
[![Coverage Status](https://img.shields.io/badge/coverage-%3E90%25-brightgreen.svg)]()

此包为 TLS 协议提供全面的非对称加密算法实现。

## 目录

- [功能特性](#功能特性)
- [安装](#安装)
- [使用方法](#使用方法)
  - [RSA 加密](#rsa-加密)
  - [ECDSA 签名](#ecdsa-签名)
  - [Ed25519 签名](#ed25519-签名)
  - [Ed448 签名](#ed448-签名)
  - [DSA 签名](#dsa-签名)
  - [签名验证工具](#签名验证工具)
- [高级用法](#高级用法)
- [支持的算法](#支持的算法)
- [密钥对结构](#密钥对结构)
- [异常处理](#异常处理)
- [系统要求](#系统要求)
- [测试](#测试)
- [贡献](#贡献)
- [许可证](#许可证)

## 功能特性

- **RSA** 加密和签名（支持 PKCS#1、OAEP 填充）
- **ECDSA** 实现（支持多种曲线）
- **EdDSA** (Ed25519, Ed448) 实现
- **DSA** 和传统签名算法
- **密钥格式处理**（PKCS#1、PKCS#8 等）
- **签名验证**工具
- **高性能**加密操作
- **生产可用**，拥有全面的测试覆盖
- **易于使用**的 API，接口一致

## 安装

```bash
composer require tourze/tls-crypto-asymmetric
```

## 使用方法

### RSA 加密

```php
use Tourze\TLSCryptoAsymmetric\Cipher\RSA;

$rsa = new RSA();

// 生成密钥对
$keyPair = $rsa->generateKeyPair(['keySize' => 2048]);

// 加密数据
$plaintext = 'Hello, World!';
$ciphertext = $rsa->encrypt($plaintext, $keyPair['publicKey']);

// 解密数据
$decrypted = $rsa->decrypt($ciphertext, $keyPair['privateKey']);

// 签名数据
$signature = $rsa->sign($plaintext, $keyPair['privateKey']);

// 验证签名
$isValid = $rsa->verify($plaintext, $signature, $keyPair['publicKey']);
```

### ECDSA 签名

```php
use Tourze\TLSCryptoAsymmetric\Cipher\ECDSA;

$ecdsa = new ECDSA();

// 使用指定曲线生成密钥对
$keyPair = $ecdsa->generateKeyPair(['curve' => 'prime256v1']);

// 签名数据
$data = 'Message to sign';
$signature = $ecdsa->sign($data, $keyPair['privateKey']);

// 验证签名
$isValid = $ecdsa->verify($data, $signature, $keyPair['publicKey']);
```

### Ed25519 签名

```php
use Tourze\TLSCryptoAsymmetric\Cipher\Ed25519;

$ed25519 = new Ed25519();

// 生成密钥对
$keyPair = $ed25519->generateKeyPair();

// 签名数据
$data = 'Message to sign';
$signature = $ed25519->sign($data, $keyPair['privateKey']);

// 验证签名
$isValid = $ed25519->verify($data, $signature, $keyPair['publicKey']);
```

### Ed448 签名

```php
use Tourze\TLSCryptoAsymmetric\Cipher\Ed448;

$ed448 = new Ed448();

// 生成密钥对
$keyPair = $ed448->generateKeyPair();

// 签名数据
$data = 'Message to sign';
$signature = $ed448->sign($data, $keyPair['privateKey']);

// 验证签名
$isValid = $ed448->verify($data, $signature, $keyPair['publicKey']);
```

### DSA 签名

```php
use Tourze\TLSCryptoAsymmetric\Cipher\DSA;

$dsa = new DSA();

// 生成密钥对
$keyPair = $dsa->generateKeyPair(['keySize' => 2048]);

// 签名数据
$data = 'Message to sign';
$signature = $dsa->sign($data, $keyPair['privateKey']);

// 验证签名
$isValid = $dsa->verify($data, $signature, $keyPair['publicKey']);
```

### 签名验证工具

```php
use Tourze\TLSCryptoAsymmetric\Signature\SignatureVerifier;

$verifier = new SignatureVerifier();

// 自动检测算法并验证签名
$isValid = $verifier->verify($data, $signature, $publicKey, $algorithm);
```

### 密钥对工具类

```php
use Tourze\TLSCryptoAsymmetric\KeyPair\KeyPair;

// 从数组创建密钥对
$keyPairArray = $rsa->generateKeyPair();
$keyPair = KeyPair::fromArray($keyPairArray);

// 访问密钥
$privateKey = $keyPair->getPrivateKey();
$publicKey = $keyPair->getPublicKey();

// 转换回数组格式
$arrayFormat = $keyPair->toArray();
```

## 高级用法

### 自定义RSA密钥生成

```php
$rsa = new RSA();

// 使用自定义参数生成RSA密钥
$keyPair = $rsa->generateKeyPair([
    'keySize' => 4096,
    'digest_alg' => 'sha256',
    'private_key_type' => OPENSSL_KEYTYPE_RSA
]);
```

### 使用自定义曲线的ECDSA

```php
$ecdsa = new ECDSA();

// 使用特定椭圆曲线
$keyPair = $ecdsa->generateKeyPair(['curve' => 'secp384r1']);

// 可用曲线：prime256v1、secp384r1、secp521r1
```

### 错误处理最佳实践

```php
try {
    $rsa = new RSA();
    $keyPair = $rsa->generateKeyPair();
    $encrypted = $rsa->encrypt($data, $keyPair['publicKey']);
} catch (AsymmetricCipherException $e) {
    // 处理加密错误
    error_log('加密错误: ' . $e->getMessage());
} catch (\Exception $e) {
    // 处理其他错误
    error_log('一般错误: ' . $e->getMessage());
}
```

## 支持的算法

### RSA
- 密钥大小：512（仅测试用）、1024、2048、3072、4096 位
- 填充方式：PKCS#1 v1.5、OAEP
- 支持加密/解密和签名/验证

### ECDSA
- 曲线：secp256r1 (prime256v1)、secp384r1、secp521r1 等
- 仅支持签名/验证

### EdDSA
- **Ed25519**：高速、高安全的签名
- **Ed448**：更大密钥尺寸的增强安全性
- 仅支持签名/验证

### DSA
- 密钥大小：1024、2048、3072 位
- 仅支持签名/验证

## 密钥对结构

所有算法都返回以下格式的密钥对：

```php
[
    'privateKey' => '-----BEGIN PRIVATE KEY-----...-----END PRIVATE KEY-----',
    'publicKey' => '-----BEGIN PUBLIC KEY-----...-----END PUBLIC KEY-----'
]
```

## 异常处理

此包为不同的错误条件提供了特定的异常：

- `AsymmetricCipherException`：通用加密错误
- `CryptoException`：基础加密异常
- `InvalidKeyPairException`：无效密钥对错误
- `InvalidSignatureAlgorithmException`：不支持的算法错误

```php
try {
    $keyPair = $rsa->generateKeyPair(['keySize' => 9999]);
} catch (AsymmetricCipherException $e) {
    echo '错误：' . $e->getMessage();
}
```

## 系统要求

- PHP 8.1 或更高版本
- OpenSSL 扩展
- Sodium 扩展（用于 Ed25519/Ed448）
- Hash 扩展

## 测试

运行测试套件：

```bash
vendor/bin/phpunit
```

## 贡献

欢迎贡献！请随时提交 Pull Request。

## 许可证

MIT 