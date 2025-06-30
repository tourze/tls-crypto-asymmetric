<?php

declare(strict_types=1);

namespace Tourze\TLSCryptoAsymmetric\Cipher;

use Tourze\TLSCryptoAsymmetric\Contract\AsymmetricCipherInterface;
use Tourze\TLSCryptoAsymmetric\Exception\AsymmetricCipherException;

/**
 * ECDSA签名算法实现
 *
 * 椭圆曲线数字签名算法，主要用于数字签名，而非加密/解密
 */
class ECDSA implements AsymmetricCipherInterface
{
    /**
     * 默认使用的曲线
     */
    private const DEFAULT_CURVE = 'prime256v1'; // 即NIST P-256

    /**
     * 获取算法名称
     *
     * @return string
     */
    public function getName(): string
    {
        return 'ecdsa';
    }

    /**
     * 生成ECDSA密钥对
     *
     * @param array $options 生成密钥对时的选项
     * @return array 包含私钥和公钥的数组
     * @throws AsymmetricCipherException 如果生成密钥对失败
     */
    public function generateKeyPair(array $options = []): array
    {
        $curve = $options['curve'] ?? self::DEFAULT_CURVE;

        // 检查OpenSSL是否支持ECDSA
        if (!extension_loaded('openssl')) {
            throw new AsymmetricCipherException('OpenSSL扩展未加载，无法使用ECDSA');
        }

        // 获取支持的曲线列表
        $supportedCurves = [];
        try {
            $supportedCurves = openssl_get_curve_names();
            if ($supportedCurves === false) {
                throw new AsymmetricCipherException('无法获取支持的椭圆曲线列表');
            }
        } catch (\Throwable $e) {
            throw new AsymmetricCipherException('获取支持的椭圆曲线失败: ' . $e->getMessage());
        }

        if (!in_array($curve, $supportedCurves)) {
            throw new AsymmetricCipherException('不支持的椭圆曲线: ' . $curve);
        }

        try {
            // 创建ECDSA私钥
            $config = [
                'private_key_type' => OPENSSL_KEYTYPE_EC,
                'curve_name' => $curve,
            ];

            $privateKey = @openssl_pkey_new($config);

            if ($privateKey === false) {
                $error = openssl_error_string();
                throw new AsymmetricCipherException('ECDSA密钥对生成失败: ' . ($error !== false ? $error : '未知错误'));
            }

            // 导出私钥细节
            $keyDetails = @openssl_pkey_get_details($privateKey);
            if ($keyDetails === false) {
                $error = openssl_error_string();
                throw new AsymmetricCipherException('无法获取ECDSA密钥细节: ' . ($error !== false ? $error : '未知错误'));
            }

            // 导出 PEM 格式的私钥和公钥
            $privateKeyPem = '';
            if (!@openssl_pkey_export($privateKey, $privateKeyPem)) {
                $error = openssl_error_string();
                throw new AsymmetricCipherException('导出ECDSA私钥失败: ' . ($error !== false ? $error : '未知错误'));
            }

            $publicKeyPem = $keyDetails['key'];

            return [
                'privateKey' => $privateKeyPem,
                'publicKey' => $publicKeyPem,
                'curve' => $curve,
            ];
        } catch (AsymmetricCipherException $e) {
            throw $e;
        } catch (\Throwable $e) {
            throw new AsymmetricCipherException('ECDSA密钥对生成失败: ' . $e->getMessage());
        }
    }

    /**
     * 使用公钥加密数据
     *
     * 注意：ECDSA是签名算法，不支持加密操作
     *
     * @param string $plaintext 明文数据
     * @param string $publicKey 公钥
     * @param array $options 加密选项
     * @return string 加密后的数据
     * @throws AsymmetricCipherException 始终抛出异常，因为ECDSA不支持加密
     */
    public function encrypt(string $plaintext, string $publicKey, array $options = []): string
    {
        throw new AsymmetricCipherException('ECDSA是签名算法，不支持加密操作');
    }

    /**
     * 使用私钥解密数据
     *
     * 注意：ECDSA是签名算法，不支持解密操作
     *
     * @param string $ciphertext 密文数据
     * @param string $privateKey 私钥
     * @param array $options 解密选项
     * @return string 解密后的数据
     * @throws AsymmetricCipherException 始终抛出异常，因为ECDSA不支持解密
     */
    public function decrypt(string $ciphertext, string $privateKey, array $options = []): string
    {
        throw new AsymmetricCipherException('ECDSA是签名算法，不支持解密操作');
    }

    /**
     * 使用私钥签名数据
     *
     * @param string $data 要签名的数据
     * @param string $privateKey 私钥 (PEM格式)
     * @param array $options 签名选项
     * @return string 签名
     * @throws AsymmetricCipherException 如果签名失败
     */
    public function sign(string $data, string $privateKey, array $options = []): string
    {
        // 检查OpenSSL是否可用
        if (!extension_loaded('openssl')) {
            throw new AsymmetricCipherException('OpenSSL扩展未加载，无法使用ECDSA');
        }

        $hashAlgo = $options['hash'] ?? 'sha256';

        try {
            // 加载私钥
            $key = openssl_pkey_get_private($privateKey);
            if ($key === false) {
                throw new AsymmetricCipherException('无效的ECDSA私钥: ' . openssl_error_string());
            }

            // 签名数据
            $signature = '';
            $result = openssl_sign($data, $signature, $key, $hashAlgo);

            if ($result === false) {
                throw new AsymmetricCipherException('ECDSA签名失败: ' . openssl_error_string());
            }

            return $signature;
        } catch (\Throwable $e) {
            throw new AsymmetricCipherException('ECDSA签名失败: ' . $e->getMessage());
        }
    }

    /**
     * 使用公钥验证签名
     *
     * @param string $data 原始数据
     * @param string $signature 签名
     * @param string $publicKey 公钥 (PEM格式)
     * @param array $options 验证选项
     * @return bool 签名是否有效
     * @throws AsymmetricCipherException 如果验证签名失败
     */
    public function verify(string $data, string $signature, string $publicKey, array $options = []): bool
    {
        // 检查OpenSSL是否可用
        if (!extension_loaded('openssl')) {
            throw new AsymmetricCipherException('OpenSSL扩展未加载，无法使用ECDSA');
        }

        $hashAlgo = $options['hash'] ?? 'sha256';

        try {
            // 加载公钥
            $key = openssl_pkey_get_public($publicKey);
            if ($key === false) {
                throw new AsymmetricCipherException('无效的ECDSA公钥: ' . openssl_error_string());
            }

            // 验证签名
            $result = openssl_verify($data, $signature, $key, $hashAlgo);

            if ($result === -1) {
                throw new AsymmetricCipherException('ECDSA签名验证失败: ' . openssl_error_string());
            }

            return $result === 1;
        } catch (\Throwable $e) {
            throw new AsymmetricCipherException('ECDSA签名验证失败: ' . $e->getMessage());
        }
    }
}
