<?php

declare(strict_types=1);

namespace Tourze\TLSCryptoAsymmetric\Signature;

use phpseclib3\Crypt\EC;
use phpseclib3\Crypt\RSA;
use Tourze\TLSCryptoAsymmetric\Exception\InvalidSignatureAlgorithmException;

/**
 * 签名验证器 - 用于验证证书和CRL的数字签名
 */
class SignatureVerifier
{
    /**
     * 验证签名
     *
     * @param string $data      被签名的数据
     * @param string $signature 签名值
     * @param string $publicKey 用于验证的公钥（PEM格式）
     * @param string $algorithm 签名算法
     *
     * @return bool 如果签名有效则返回true
     *
     * @throws \InvalidArgumentException 当算法不支持时
     */
    public function verify(string $data, string $signature, string $publicKey, string $algorithm): bool
    {
        if (!$this->isAlgorithmSupported($algorithm)) {
            throw new InvalidSignatureAlgorithmException("不支持的签名算法: {$algorithm}");
        }

        try {
            // 解析算法类型和哈希算法
            $algorithmInfo = $this->parseAlgorithm($algorithm);
            $hashAlgorithm = $algorithmInfo['hash'];
            $signatureType = $algorithmInfo['type'];

            // 根据签名类型选择验证方法
            return match ($signatureType) {
                'rsa' => $this->verifyRSASignature($data, $signature, $publicKey, $hashAlgorithm),
                'ecdsa' => $this->verifyECDSASignature($data, $signature, $publicKey, $hashAlgorithm),
                default => throw new InvalidSignatureAlgorithmException("未知的签名类型: {$signatureType}"),
            };
        } catch (\Throwable $e) {
            // 签名验证过程中出现任何异常都视为验证失败
            return false;
        }
    }

    /**
     * 验证RSA签名
     *
     * @param string $data          原始数据
     * @param string $signature     签名值
     * @param string $publicKey     公钥（PEM格式）
     * @param string $hashAlgorithm 哈希算法
     *
     * @return bool 验证结果
     */
    private function verifyRSASignature(string $data, string $signature, string $publicKey, string $hashAlgorithm): bool
    {
        $rsa = RSA::loadPublicKey($publicKey);
        assert($rsa instanceof RSA\PublicKey);

        // 设置签名模式和哈希算法
        $rsa = $rsa->withPadding(RSA::SIGNATURE_PKCS1);
        assert($rsa instanceof RSA\PublicKey);
        $rsa = $rsa->withHash($hashAlgorithm);
        assert($rsa instanceof RSA\PublicKey);

        return $rsa->verify($data, $signature);
    }

    /**
     * 验证ECDSA签名
     *
     * @param string $data          原始数据
     * @param string $signature     签名值
     * @param string $publicKey     公钥（PEM格式）
     * @param string $hashAlgorithm 哈希算法
     *
     * @return bool 验证结果
     */
    private function verifyECDSASignature(string $data, string $signature, string $publicKey, string $hashAlgorithm): bool
    {
        $ec = EC::loadPublicKey($publicKey);
        assert($ec instanceof EC\PublicKey);

        // 设置哈希算法
        $ec = $ec->withHash($hashAlgorithm);
        assert($ec instanceof EC\PublicKey);

        return $ec->verify($data, $signature);
    }

    /**
     * 解析算法信息
     *
     * @param string $algorithm 算法标识符
     *
     * @return array{hash: string, type: string} 包含哈希算法和签名类型的数组
     */
    private function parseAlgorithm(string $algorithm): array
    {
        return match ($algorithm) {
            'sha1WithRSAEncryption' => ['hash' => 'sha1', 'type' => 'rsa'],
            'sha256WithRSAEncryption' => ['hash' => 'sha256', 'type' => 'rsa'],
            'sha384WithRSAEncryption' => ['hash' => 'sha384', 'type' => 'rsa'],
            'sha512WithRSAEncryption' => ['hash' => 'sha512', 'type' => 'rsa'],
            'ecdsa-with-SHA1' => ['hash' => 'sha1', 'type' => 'ecdsa'],
            'ecdsa-with-SHA256' => ['hash' => 'sha256', 'type' => 'ecdsa'],
            'ecdsa-with-SHA384' => ['hash' => 'sha384', 'type' => 'ecdsa'],
            'ecdsa-with-SHA512' => ['hash' => 'sha512', 'type' => 'ecdsa'],
            default => throw new InvalidSignatureAlgorithmException("无法解析算法: {$algorithm}"),
        };
    }

    /**
     * 获取支持的算法列表
     *
     * @return array<string> 支持的算法列表
     */
    public function getSupportedAlgorithms(): array
    {
        return [
            'sha1WithRSAEncryption',
            'sha256WithRSAEncryption',
            'sha384WithRSAEncryption',
            'sha512WithRSAEncryption',
            'ecdsa-with-SHA1',
            'ecdsa-with-SHA256',
            'ecdsa-with-SHA384',
            'ecdsa-with-SHA512',
        ];
    }

    /**
     * 检查算法是否受支持
     *
     * @param string $algorithm 要检查的算法
     *
     * @return bool 如果算法受支持则返回true
     */
    public function isAlgorithmSupported(string $algorithm): bool
    {
        return in_array($algorithm, $this->getSupportedAlgorithms(), true);
    }
}
