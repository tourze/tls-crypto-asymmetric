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
     */
    public function getName(): string
    {
        return 'ecdsa';
    }

    /**
     * 生成ECDSA密钥对
     *
     * @param array<string, mixed> $options 生成密钥对时的选项
     *
     * @return array<string, string> 包含私钥和公钥的数组
     *
     * @throws AsymmetricCipherException 如果生成密钥对失败
     */
    public function generateKeyPair(array $options = []): array
    {
        $curve = $options['curve'] ?? self::DEFAULT_CURVE;

        $this->validateOpenSSLExtension();
        $this->validateCurve($curve);

        return $this->createKeyPair($curve);
    }

    /**
     * 验证OpenSSL扩展是否可用
     *
     * @throws AsymmetricCipherException
     */
    private function validateOpenSSLExtension(): void
    {
        if (!extension_loaded('openssl')) {
            throw new AsymmetricCipherException('OpenSSL扩展未加载，无法使用ECDSA');
        }
    }

    /**
     * 验证椭圆曲线是否受支持
     *
     * @param string $curve 椭圆曲线名称
     *
     * @throws AsymmetricCipherException
     */
    private function validateCurve(string $curve): void
    {
        $supportedCurves = $this->getSupportedCurves();

        if (!in_array($curve, $supportedCurves, true)) {
            throw new AsymmetricCipherException('不支持的椭圆曲线: ' . $curve);
        }
    }

    /**
     * 获取支持的椭圆曲线列表
     *
     * @return array<string> 支持的椭圆曲线列表
     *
     * @throws AsymmetricCipherException
     */
    private function getSupportedCurves(): array
    {
        try {
            $supportedCurves = openssl_get_curve_names();
            if (false === $supportedCurves) {
                throw new AsymmetricCipherException('无法获取支持的椭圆曲线列表');
            }

            return $supportedCurves;
        } catch (\Throwable $e) {
            throw new AsymmetricCipherException('获取支持的椭圆曲线失败: ' . $e->getMessage());
        }
    }

    /**
     * 创建ECDSA密钥对
     *
     * @param string $curve 椭圆曲线名称
     *
     * @return array<string, string> 包含私钥和公钥的数组
     *
     * @throws AsymmetricCipherException
     */
    private function createKeyPair(string $curve): array
    {
        try {
            $config = [
                'private_key_type' => OPENSSL_KEYTYPE_EC,
                'curve_name' => $curve,
            ];

            $privateKey = $this->generatePrivateKey($config);
            $keyDetails = $this->getKeyDetails($privateKey);
            $privateKeyPem = $this->exportPrivateKey($privateKey);

            return [
                'privateKey' => $privateKeyPem,
                'publicKey' => $keyDetails['key'],
            ];
        } catch (AsymmetricCipherException $e) {
            throw $e;
        } catch (\Throwable $e) {
            throw new AsymmetricCipherException('ECDSA密钥对生成失败: ' . $e->getMessage());
        }
    }

    /**
     * 生成私钥资源
     *
     * @param array<string, mixed> $config 密钥生成配置
     *
     * @return \OpenSSLAsymmetricKey 私钥资源
     *
     * @throws AsymmetricCipherException
     */
    private function generatePrivateKey(array $config): \OpenSSLAsymmetricKey
    {
        $privateKey = @openssl_pkey_new($config);

        if (false === $privateKey) {
            $error = openssl_error_string();
            throw new AsymmetricCipherException('ECDSA密钥对生成失败: ' . (false !== $error ? $error : '未知错误'));
        }

        return $privateKey;
    }

    /**
     * 获取密钥详细信息
     *
     * @param \OpenSSLAsymmetricKey $privateKey 私钥资源
     *
     * @return array<string, mixed> 密钥详细信息
     *
     * @throws AsymmetricCipherException
     */
    private function getKeyDetails(\OpenSSLAsymmetricKey $privateKey): array
    {
        $keyDetails = @openssl_pkey_get_details($privateKey);
        if (false === $keyDetails) {
            $error = openssl_error_string();
            throw new AsymmetricCipherException('无法获取ECDSA密钥细节: ' . (false !== $error ? $error : '未知错误'));
        }

        return $keyDetails;
    }

    /**
     * 导出PEM格式的私钥
     *
     * @param \OpenSSLAsymmetricKey $privateKey 私钥资源
     *
     * @return string PEM格式的私钥
     *
     * @throws AsymmetricCipherException
     */
    private function exportPrivateKey(\OpenSSLAsymmetricKey $privateKey): string
    {
        $privateKeyPem = '';
        if (!@openssl_pkey_export($privateKey, $privateKeyPem)) {
            $error = openssl_error_string();
            throw new AsymmetricCipherException('导出ECDSA私钥失败: ' . (false !== $error ? $error : '未知错误'));
        }

        return $privateKeyPem;
    }

    /**
     * 使用公钥加密数据
     *
     * 注意：ECDSA是签名算法，不支持加密操作
     *
     * @param string $plaintext 明文数据
     * @param string $publicKey 公钥
     * @param array<string, mixed>  $options   加密选项
     *
     * @return string 加密后的数据
     *
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
     * @param array<string, mixed>  $options    解密选项
     *
     * @return string 解密后的数据
     *
     * @throws AsymmetricCipherException 始终抛出异常，因为ECDSA不支持解密
     */
    public function decrypt(string $ciphertext, string $privateKey, array $options = []): string
    {
        throw new AsymmetricCipherException('ECDSA是签名算法，不支持解密操作');
    }

    /**
     * 使用私钥签名数据
     *
     * @param string $data       要签名的数据
     * @param string $privateKey 私钥 (PEM格式)
     * @param array<string, mixed>  $options    签名选项
     *
     * @return string 签名
     *
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
            if (false === $key) {
                throw new AsymmetricCipherException('无效的ECDSA私钥: ' . openssl_error_string());
            }

            // 签名数据
            $signature = '';
            $result = openssl_sign($data, $signature, $key, $hashAlgo);

            if (false === $result) {
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
     * @param string $data      原始数据
     * @param string $signature 签名
     * @param string $publicKey 公钥 (PEM格式)
     * @param array<string, mixed>  $options   验证选项
     *
     * @return bool 签名是否有效
     *
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
            if (false === $key) {
                throw new AsymmetricCipherException('无效的ECDSA公钥: ' . openssl_error_string());
            }

            // 验证签名
            $result = openssl_verify($data, $signature, $key, $hashAlgo);

            if (-1 === $result) {
                throw new AsymmetricCipherException('ECDSA签名验证失败: ' . openssl_error_string());
            }

            return 1 === $result;
        } catch (\Throwable $e) {
            throw new AsymmetricCipherException('ECDSA签名验证失败: ' . $e->getMessage());
        }
    }
}
