<?php

declare(strict_types=1);

namespace Tourze\TLSCryptoAsymmetric\Cipher;

use Tourze\TLSCryptoAsymmetric\Contract\AsymmetricCipherInterface;
use Tourze\TLSCryptoAsymmetric\Exception\AsymmetricCipherException;

/**
 * DSA数字签名算法实现
 *
 * 数字签名算法(Digital Signature Algorithm)是美国联邦信息处理标准(FIPS)中定义的一种签名算法
 * 主要用于数字签名，而非加密/解密
 */
class DSA implements AsymmetricCipherInterface
{
    /**
     * 默认DSA密钥长度
     */
    private const DEFAULT_KEY_BITS = 2048;

    /**
     * 默认的消息摘要算法
     */
    private const DEFAULT_DIGEST_ALG = 'sha256';

    /**
     * 获取算法名称
     *
     * @return string
     */
    public function getName(): string
    {
        return 'dsa';
    }

    /**
     * 生成DSA密钥对
     *
     * @param array $options 生成密钥对时的选项
     * @return array 包含私钥和公钥的数组
     * @throws AsymmetricCipherException 如果生成密钥对失败
     */
    public function generateKeyPair(array $options = []): array
    {
        // 检查OpenSSL扩展是否加载
        if (!extension_loaded('openssl')) {
            throw new AsymmetricCipherException('OpenSSL扩展未加载，无法使用DSA');
        }

        // 获取密钥大小
        $keyBits = $options['bits'] ?? self::DEFAULT_KEY_BITS;

        // 验证密钥大小
        if ($keyBits < 1024 || $keyBits > 4096) {
            throw new AsymmetricCipherException('DSA密钥长度必须在1024-4096位之间');
        }

        try {
            // 创建DSA密钥对
            $config = [
                'private_key_bits' => $keyBits,
                'private_key_type' => OPENSSL_KEYTYPE_DSA,
            ];

            $res = openssl_pkey_new($config);
            if ($res === false) {
                throw new AsymmetricCipherException('DSA密钥对生成失败: ' . openssl_error_string());
            }

            // 导出私钥（PEM格式）
            if (!openssl_pkey_export($res, $privateKeyPem)) {
                throw new AsymmetricCipherException('DSA私钥导出失败: ' . openssl_error_string());
            }

            // 导出公钥（PEM格式）
            $details = openssl_pkey_get_details($res);
            if ($details === false) {
                throw new AsymmetricCipherException('获取DSA密钥详情失败: ' . openssl_error_string());
            }

            $publicKeyPem = $details['key'];

            return [
                'privateKey' => $privateKeyPem,
                'publicKey' => $publicKeyPem,
                'bits' => $keyBits,
            ];
        } catch  (\Throwable $e) {
            throw new AsymmetricCipherException('DSA密钥对生成失败: ' . $e->getMessage());
        }
    }

    /**
     * 使用公钥加密数据
     *
     * 注意：DSA是签名算法，不支持加密操作
     *
     * @param string $plaintext 明文数据
     * @param string $publicKey 公钥
     * @param array $options 加密选项
     * @return string 加密后的数据
     * @throws AsymmetricCipherException 始终抛出异常，因为DSA不支持加密
     */
    public function encrypt(string $plaintext, string $publicKey, array $options = []): string
    {
        throw new AsymmetricCipherException('DSA是签名算法，不支持加密操作');
    }

    /**
     * 使用私钥解密数据
     *
     * 注意：DSA是签名算法，不支持解密操作
     *
     * @param string $ciphertext 密文数据
     * @param string $privateKey 私钥
     * @param array $options 解密选项
     * @return string 解密后的数据
     * @throws AsymmetricCipherException 始终抛出异常，因为DSA不支持解密
     */
    public function decrypt(string $ciphertext, string $privateKey, array $options = []): string
    {
        throw new AsymmetricCipherException('DSA是签名算法，不支持解密操作');
    }

    /**
     * 使用私钥签名数据
     *
     * @param string $data 要签名的数据
     * @param string $privateKey 私钥
     * @param array $options 签名选项
     * @return string 签名
     * @throws AsymmetricCipherException 如果签名失败
     */
    public function sign(string $data, string $privateKey, array $options = []): string
    {
        // 检查OpenSSL扩展是否加载
        if (!extension_loaded('openssl')) {
            throw new AsymmetricCipherException('OpenSSL扩展未加载，无法使用DSA');
        }

        try {
            // 获取摘要算法
            $digestAlg = $options['digest_alg'] ?? self::DEFAULT_DIGEST_ALG;

            // 加载私钥
            $privKey = openssl_pkey_get_private($privateKey);
            if ($privKey === false) {
                throw new AsymmetricCipherException('加载DSA私钥失败: ' . openssl_error_string());
            }

            // 验证私钥类型
            $details = openssl_pkey_get_details($privKey);
            if ($details === false || $details['type'] !== OPENSSL_KEYTYPE_DSA) {
                throw new AsymmetricCipherException('提供的密钥不是DSA密钥');
            }

            // 使用OpenSSL进行签名
            $signature = '';
            if (!openssl_sign($data, $signature, $privKey, $digestAlg)) {
                throw new AsymmetricCipherException('DSA签名失败: ' . openssl_error_string());
            }

            return $signature;
        } catch  (\Throwable $e) {
            throw new AsymmetricCipherException('DSA签名失败: ' . $e->getMessage());
        }
    }

    /**
     * 使用公钥验证签名
     *
     * @param string $data 原始数据
     * @param string $signature 签名
     * @param string $publicKey 公钥
     * @param array $options 验证选项
     * @return bool 签名是否有效
     * @throws AsymmetricCipherException 如果验证签名失败
     */
    public function verify(string $data, string $signature, string $publicKey, array $options = []): bool
    {
        // 检查OpenSSL扩展是否加载
        if (!extension_loaded('openssl')) {
            throw new AsymmetricCipherException('OpenSSL扩展未加载，无法使用DSA');
        }

        try {
            // 获取摘要算法
            $digestAlg = $options['digest_alg'] ?? self::DEFAULT_DIGEST_ALG;

            // 加载公钥
            $pubKey = openssl_pkey_get_public($publicKey);
            if ($pubKey === false) {
                throw new AsymmetricCipherException('加载DSA公钥失败: ' . openssl_error_string());
            }

            // 验证公钥类型
            $details = openssl_pkey_get_details($pubKey);
            if ($details === false || $details['type'] !== OPENSSL_KEYTYPE_DSA) {
                throw new AsymmetricCipherException('提供的密钥不是DSA密钥');
            }

            // 使用OpenSSL验证签名
            $result = openssl_verify($data, $signature, $pubKey, $digestAlg);
            if ($result === -1) {
                throw new AsymmetricCipherException('DSA签名验证失败: ' . openssl_error_string());
            }

            return $result === 1;
        } catch  (\Throwable $e) {
            throw new AsymmetricCipherException('DSA签名验证失败: ' . $e->getMessage());
        }
    }
}
