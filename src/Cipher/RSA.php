<?php

declare(strict_types=1);

namespace Tourze\TLSCryptoAsymmetric\Cipher;

use Tourze\TLSCryptoAsymmetric\Contract\AsymmetricCipherInterface;
use Tourze\TLSCryptoAsymmetric\Exception\AsymmetricCipherException;

/**
 * RSA非对称加密算法实现
 */
class RSA implements AsymmetricCipherInterface
{
    /**
     * RSA填充方式
     */
    public const PADDING_PKCS1 = OPENSSL_PKCS1_PADDING;
    public const PADDING_OAEP = OPENSSL_PKCS1_OAEP_PADDING;

    /**
     * 默认的密钥大小（位）
     */
    private const DEFAULT_KEY_SIZE = 2048;

    public function getName(): string
    {
        return 'rsa';
    }

    /**
     * 生成密钥对
     *
     * @param array $options 生成密钥对时的选项
     *                      - keySize: 密钥大小（位，默认2048）
     * @return array 包含'privateKey'和'publicKey'的数组
     * @throws AsymmetricCipherException 如果生成密钥对失败
     */
    public function generateKeyPair(array $options = []): array
    {
        $keySize = $options['keySize'] ?? self::DEFAULT_KEY_SIZE;

        // 验证密钥大小
        $validKeySizes = [512, 1024, 2048, 3072, 4096]; // 添加512位用于测试

        if (!in_array($keySize, $validKeySizes)) {
            throw new AsymmetricCipherException('无效的RSA密钥大小，支持的值为：512(仅测试用), 1024, 2048, 3072, 4096');
        }

        // 生产环境警告
        if ($keySize < 1024 && !isset($options['allowInsecure']) && PHP_SAPI !== 'cli') {
            throw new AsymmetricCipherException('生产环境中不应使用小于1024位的RSA密钥，如必须用于测试，请设置allowInsecure选项');
        }

        $config = [
            'private_key_bits' => $keySize,
            'private_key_type' => OPENSSL_KEYTYPE_RSA,
        ];

        // 生成密钥对
        $res = openssl_pkey_new($config);
        if ($res === false) {
            throw new AsymmetricCipherException('RSA密钥对生成失败: ' . openssl_error_string());
        }

        // 导出私钥
        openssl_pkey_export($res, $privateKey);
        if (empty($privateKey)) {
            throw new AsymmetricCipherException('RSA私钥导出失败: ' . openssl_error_string());
        }

        // 导出公钥
        $keyDetails = openssl_pkey_get_details($res);
        if ($keyDetails === false) {
            throw new AsymmetricCipherException('RSA密钥详情获取失败: ' . openssl_error_string());
        }

        $publicKey = $keyDetails['key'];

        return [
            'privateKey' => $privateKey,
            'publicKey' => $publicKey,
            'keySize' => $keySize,
        ];
    }

    /**
     * 使用公钥加密数据
     *
     * @param string $plaintext 明文数据
     * @param string $publicKey 公钥（PEM格式）
     * @param array $options 加密选项
     *                      - padding: 填充方式（默认PADDING_OAEP）
     * @return string 加密后的数据
     * @throws AsymmetricCipherException 如果加密失败
     */
    public function encrypt(string $plaintext, string $publicKey, array $options = []): string
    {
        $padding = $options['padding'] ?? self::PADDING_OAEP;

        // 加载公钥
        $pubKeyRes = openssl_pkey_get_public($publicKey);
        if ($pubKeyRes === false) {
            throw new AsymmetricCipherException('RSA公钥加载失败: ' . openssl_error_string());
        }

        // 获取密钥详情以确定最大明文长度
        $keyDetails = openssl_pkey_get_details($pubKeyRes);
        if ($keyDetails === false) {
            throw new AsymmetricCipherException('RSA密钥详情获取失败: ' . openssl_error_string());
        }

        $keySize = $keyDetails['bits'] / 8;

        // 计算最大明文长度
        $maxPlaintextLength = match ($padding) {
            self::PADDING_PKCS1 => $keySize - 11,
            self::PADDING_OAEP => $keySize - 42, // SHA-1哈希长度为20字节，再加上填充等
            default => throw new AsymmetricCipherException('不支持的RSA填充方式'),
        };

        // 如果明文太长，抛出异常
        if (strlen($plaintext) > $maxPlaintextLength) {
            throw new AsymmetricCipherException('明文长度超过最大限制，请考虑使用分段加密或对称加密');
        }

        // 加密
        $result = '';
        $success = openssl_public_encrypt($plaintext, $result, $pubKeyRes, $padding);

        if ($success === false) {
            throw new AsymmetricCipherException('RSA加密失败: ' . openssl_error_string());
        }

        return $result;
    }

    /**
     * 使用私钥解密数据
     *
     * @param string $ciphertext 密文数据
     * @param string $privateKey 私钥（PEM格式）
     * @param array $options 解密选项
     *                      - padding: 填充方式（默认PADDING_OAEP）
     * @return string 解密后的数据
     * @throws AsymmetricCipherException 如果解密失败
     */
    public function decrypt(string $ciphertext, string $privateKey, array $options = []): string
    {
        $padding = $options['padding'] ?? self::PADDING_OAEP;

        // 加载私钥
        $privKeyRes = openssl_pkey_get_private($privateKey);
        if ($privKeyRes === false) {
            throw new AsymmetricCipherException('RSA私钥加载失败: ' . openssl_error_string());
        }

        // 解密
        $result = '';
        $success = openssl_private_decrypt($ciphertext, $result, $privKeyRes, $padding);

        if ($success === false) {
            throw new AsymmetricCipherException('RSA解密失败: ' . openssl_error_string());
        }

        return $result;
    }

    /**
     * 使用私钥签名数据
     *
     * @param string $data 要签名的数据
     * @param string $privateKey 私钥（PEM格式）
     * @param array $options 签名选项
     *                      - algorithm: 签名算法（默认'sha256'）
     * @return string 签名
     * @throws AsymmetricCipherException 如果签名失败
     */
    public function sign(string $data, string $privateKey, array $options = []): string
    {
        $algorithm = $options['algorithm'] ?? 'sha256';

        // 加载私钥
        $privKeyRes = openssl_pkey_get_private($privateKey);
        if ($privKeyRes === false) {
            throw new AsymmetricCipherException('RSA私钥加载失败: ' . openssl_error_string());
        }

        // 签名
        $signature = '';
        $success = openssl_sign($data, $signature, $privKeyRes, $algorithm);

        if ($success === false) {
            throw new AsymmetricCipherException('RSA签名生成失败: ' . openssl_error_string());
        }

        return $signature;
    }

    /**
     * 使用公钥验证签名
     *
     * @param string $data 原始数据
     * @param string $signature 签名
     * @param string $publicKey 公钥（PEM格式）
     * @param array $options 验证选项
     *                      - algorithm: 签名算法（默认'sha256'）
     * @return bool 签名是否有效
     * @throws AsymmetricCipherException 如果验证过程出错
     */
    public function verify(string $data, string $signature, string $publicKey, array $options = []): bool
    {
        $algorithm = $options['algorithm'] ?? 'sha256';

        // 加载公钥
        $pubKeyRes = openssl_pkey_get_public($publicKey);
        if ($pubKeyRes === false) {
            throw new AsymmetricCipherException('RSA公钥加载失败: ' . openssl_error_string());
        }

        // 验证签名
        $result = openssl_verify($data, $signature, $pubKeyRes, $algorithm);

        if ($result === -1) {
            throw new AsymmetricCipherException('RSA签名验证过程出错: ' . openssl_error_string());
        }

        return $result === 1;
    }
}
