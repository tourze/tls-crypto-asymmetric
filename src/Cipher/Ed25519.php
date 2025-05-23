<?php

declare(strict_types=1);

namespace Tourze\TLSCryptoAsymmetric\Cipher;

use ParagonIE_Sodium_Compat;
use Tourze\TLSCryptoAsymmetric\Contract\AsymmetricCipherInterface;
use Tourze\TLSCryptoAsymmetric\Exception\AsymmetricCipherException;

/**
 * Ed25519签名算法实现
 *
 * Ed25519是基于Edwards25519曲线的EdDSA签名算法变种
 * 主要用于数字签名，而非加密/解密
 */
class Ed25519 implements AsymmetricCipherInterface
{
    /**
     * 获取算法名称
     *
     * @return string
     */
    public function getName(): string
    {
        return 'ed25519';
    }

    /**
     * 生成Ed25519密钥对
     *
     * @param array $options 生成密钥对时的选项
     * @return array 包含私钥和公钥的数组
     * @throws AsymmetricCipherException 如果生成密钥对失败
     */
    public function generateKeyPair(array $options = []): array
    {
        try {
            // 生成Ed25519密钥对
            $keyPair = ParagonIE_Sodium_Compat::crypto_sign_keypair();
            $privateKey = ParagonIE_Sodium_Compat::crypto_sign_secretkey($keyPair);
            $publicKey = ParagonIE_Sodium_Compat::crypto_sign_publickey($keyPair);

            return [
                'privateKey' => $privateKey,
                'publicKey' => $publicKey,
            ];
        } catch (\Exception $e) {
            throw new AsymmetricCipherException('Ed25519密钥对生成失败: ' . $e->getMessage());
        }
    }

    /**
     * 使用公钥加密数据
     *
     * 注意：Ed25519是签名算法，不支持加密操作
     *
     * @param string $plaintext 明文数据
     * @param string $publicKey 公钥
     * @param array $options 加密选项
     * @return string 加密后的数据
     * @throws AsymmetricCipherException 始终抛出异常，因为Ed25519不支持加密
     */
    public function encrypt(string $plaintext, string $publicKey, array $options = []): string
    {
        throw new AsymmetricCipherException('Ed25519是签名算法，不支持加密操作');
    }

    /**
     * 使用私钥解密数据
     *
     * 注意：Ed25519是签名算法，不支持解密操作
     *
     * @param string $ciphertext 密文数据
     * @param string $privateKey 私钥
     * @param array $options 解密选项
     * @return string 解密后的数据
     * @throws AsymmetricCipherException 始终抛出异常，因为Ed25519不支持解密
     */
    public function decrypt(string $ciphertext, string $privateKey, array $options = []): string
    {
        throw new AsymmetricCipherException('Ed25519是签名算法，不支持解密操作');
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
        // 获取私钥长度常量
        $secretKeyBytes = defined('ParagonIE_Sodium_Compat::CRYPTO_SIGN_SECRETKEYBYTES') ?
            ParagonIE_Sodium_Compat::CRYPTO_SIGN_SECRETKEYBYTES :
            (defined('SODIUM_CRYPTO_SIGN_SECRETKEYBYTES') ? SODIUM_CRYPTO_SIGN_SECRETKEYBYTES : 64);

        // 验证私钥长度
        if (strlen($privateKey) !== $secretKeyBytes) {
            throw new AsymmetricCipherException('无效的Ed25519私钥长度');
        }

        try {
            // 使用Ed25519算法进行签名
            return ParagonIE_Sodium_Compat::crypto_sign_detached($data, $privateKey);
        } catch (\Exception $e) {
            throw new AsymmetricCipherException('Ed25519签名失败: ' . $e->getMessage());
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
        // 获取密钥长度常量
        $publicKeyBytes = defined('ParagonIE_Sodium_Compat::CRYPTO_SIGN_PUBLICKEYBYTES') ?
            ParagonIE_Sodium_Compat::CRYPTO_SIGN_PUBLICKEYBYTES :
            (defined('SODIUM_CRYPTO_SIGN_PUBLICKEYBYTES') ? SODIUM_CRYPTO_SIGN_PUBLICKEYBYTES : 32);

        $signBytes = defined('ParagonIE_Sodium_Compat::CRYPTO_SIGN_BYTES') ?
            ParagonIE_Sodium_Compat::CRYPTO_SIGN_BYTES :
            (defined('SODIUM_CRYPTO_SIGN_BYTES') ? SODIUM_CRYPTO_SIGN_BYTES : 64);

        // 验证公钥长度
        if (strlen($publicKey) !== $publicKeyBytes) {
            throw new AsymmetricCipherException('无效的Ed25519公钥长度');
        }

        // 验证签名长度
        if (strlen($signature) !== $signBytes) {
            throw new AsymmetricCipherException('无效的Ed25519签名长度');
        }

        try {
            // 验证签名
            return ParagonIE_Sodium_Compat::crypto_sign_verify_detached($signature, $data, $publicKey);
        } catch (\Exception $e) {
            throw new AsymmetricCipherException('Ed25519签名验证失败: ' . $e->getMessage());
        }
    }
}
