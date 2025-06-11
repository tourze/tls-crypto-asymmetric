<?php

declare(strict_types=1);

namespace Tourze\TLSCryptoAsymmetric\Cipher;

use Tourze\TLSCryptoAsymmetric\Contract\AsymmetricCipherInterface;
use Tourze\TLSCryptoAsymmetric\Exception\AsymmetricCipherException;

/**
 * Ed448签名算法实现
 *
 * Ed448是基于Edwards448曲线的EdDSA签名算法变种
 * 主要用于数字签名，而非加密/解密
 *
 * 注意：PHP原生libsodium目前可能不支持Ed448，此类提供兼容实现框架
 */
class Ed448 implements AsymmetricCipherInterface
{
    /**
     * Ed448私钥字节长度 (114字节)
     */
    private const SECRET_KEY_BYTES = 114;

    /**
     * Ed448公钥字节长度 (57字节)
     */
    private const PUBLIC_KEY_BYTES = 57;

    /**
     * Ed448签名字节长度 (114字节)
     */
    private const SIGNATURE_BYTES = 114;

    /**
     * OpenSSL ED448算法标识
     *
     * 注意：某些PHP版本可能没有定义OPENSSL_ALGO_ED448常量
     */
    private const OPENSSL_ALGO_ED448 = 'ed448';

    /**
     * 是否使用OpenSSL的替代实现
     */
    private bool $useOpenSSL;

    /**
     * 构造函数
     */
    public function __construct()
    {
        // sodium_compat目前不支持Ed448，使用OpenSSL的替代实现
        $this->useOpenSSL = true;
    }

    /**
     * 获取算法名称
     *
     * @return string
     */
    public function getName(): string
    {
        return 'ed448';
    }

    /**
     * 检查环境是否支持Ed448
     *
     * @throws AsymmetricCipherException 如果不支持Ed448
     */
    private function checkSupport(): void
    {
        // 使用OpenSSL替代实现，检查OpenSSL扩展
        if (!extension_loaded('openssl')) {
            throw new AsymmetricCipherException('OpenSSL扩展未加载，无法使用Ed448替代实现');
        }

        // 检查OpenSSL是否支持Ed448曲线
        $curves = openssl_get_curve_names();
        if (!in_array('ED448', $curves)) {
            throw new AsymmetricCipherException('当前OpenSSL版本不支持Ed448曲线');
        }
    }

    /**
     * 生成Ed448密钥对
     *
     * @param array $options 生成密钥对时的选项
     * @return array 包含私钥和公钥的数组
     * @throws AsymmetricCipherException 如果生成密钥对失败
     */
    public function generateKeyPair(array $options = []): array
    {
        $this->checkSupport();

        // 使用OpenSSL替代实现
        try {
            // 创建EC密钥对
            $config = [
                'curve_name' => 'ED448',
                'private_key_type' => OPENSSL_KEYTYPE_EC,
            ];

            $res = openssl_pkey_new($config);
            if ($res === false) {
                throw new AsymmetricCipherException('Ed448密钥对生成失败: ' . openssl_error_string());
            }

            // 导出私钥和公钥
            if (!openssl_pkey_export($res, $privateKeyPem)) {
                throw new AsymmetricCipherException('Ed448私钥导出失败: ' . openssl_error_string());
            }

            $details = openssl_pkey_get_details($res);
            if ($details === false) {
                throw new AsymmetricCipherException('获取Ed448密钥详情失败: ' . openssl_error_string());
            }

            $publicKeyPem = $details['key'];

            return [
                'privateKey' => $privateKeyPem,
                'publicKey' => $publicKeyPem,
            ];
        } catch  (\Throwable $e) {
            throw new AsymmetricCipherException('Ed448密钥对生成失败: ' . $e->getMessage());
        }
    }

    /**
     * 使用公钥加密数据
     *
     * 注意：Ed448是签名算法，不支持加密操作
     *
     * @param string $plaintext 明文数据
     * @param string $publicKey 公钥
     * @param array $options 加密选项
     * @return string 加密后的数据
     * @throws AsymmetricCipherException 始终抛出异常，因为Ed448不支持加密
     */
    public function encrypt(string $plaintext, string $publicKey, array $options = []): string
    {
        throw new AsymmetricCipherException('Ed448是签名算法，不支持加密操作');
    }

    /**
     * 使用私钥解密数据
     *
     * 注意：Ed448是签名算法，不支持解密操作
     *
     * @param string $ciphertext 密文数据
     * @param string $privateKey 私钥
     * @param array $options 解密选项
     * @return string 解密后的数据
     * @throws AsymmetricCipherException 始终抛出异常，因为Ed448不支持解密
     */
    public function decrypt(string $ciphertext, string $privateKey, array $options = []): string
    {
        throw new AsymmetricCipherException('Ed448是签名算法，不支持解密操作');
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
        $this->checkSupport();

        // 使用OpenSSL替代实现
        try {
            // 加载私钥
            $privKey = openssl_pkey_get_private($privateKey);
            if ($privKey === false) {
                throw new AsymmetricCipherException('加载Ed448私钥失败: ' . openssl_error_string());
            }

            // 验证私钥类型
            $details = openssl_pkey_get_details($privKey);
            if ($details === false || $details['type'] !== OPENSSL_KEYTYPE_EC) {
                throw new AsymmetricCipherException('提供的密钥不是ED448密钥');
            }

            // 使用OpenSSL签名
            $signature = '';
            if (!openssl_sign($data, $signature, $privKey, self::OPENSSL_ALGO_ED448)) {
                throw new AsymmetricCipherException('Ed448签名失败: ' . openssl_error_string());
            }

            return $signature;
        } catch  (\Throwable $e) {
            throw new AsymmetricCipherException('Ed448签名失败: ' . $e->getMessage());
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
        $this->checkSupport();

        // 使用OpenSSL替代实现
        try {
            // 加载公钥
            $pubKey = openssl_pkey_get_public($publicKey);
            if ($pubKey === false) {
                throw new AsymmetricCipherException('加载Ed448公钥失败: ' . openssl_error_string());
            }

            // 验证公钥类型
            $details = openssl_pkey_get_details($pubKey);
            if ($details === false || $details['type'] !== OPENSSL_KEYTYPE_EC) {
                throw new AsymmetricCipherException('提供的密钥不是ED448密钥');
            }

            // 验证签名
            $result = openssl_verify($data, $signature, $pubKey, self::OPENSSL_ALGO_ED448);

            if ($result === -1) {
                throw new AsymmetricCipherException('Ed448签名验证失败: ' . openssl_error_string());
            }

            return $result === 1;
        } catch  (\Throwable $e) {
            throw new AsymmetricCipherException('Ed448签名验证失败: ' . $e->getMessage());
        }
    }
}
