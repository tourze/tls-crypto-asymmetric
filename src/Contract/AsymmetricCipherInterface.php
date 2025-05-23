<?php

declare(strict_types=1);

namespace Tourze\TLSCryptoAsymmetric\Contract;

/**
 * 非对称加密算法接口
 */
interface AsymmetricCipherInterface
{
    /**
     * 获取算法名称
     *
     * @return string
     */
    public function getName(): string;

    /**
     * 生成密钥对
     *
     * @param array $options 生成密钥对时的选项（如密钥大小、曲线类型等）
     * @return array 包含私钥和公钥的数组
     */
    public function generateKeyPair(array $options = []): array;

    /**
     * 使用公钥加密数据
     *
     * @param string $plaintext 明文数据
     * @param string $publicKey 公钥
     * @param array $options 加密选项
     * @return string 加密后的数据
     */
    public function encrypt(string $plaintext, string $publicKey, array $options = []): string;

    /**
     * 使用私钥解密数据
     *
     * @param string $ciphertext 密文数据
     * @param string $privateKey 私钥
     * @param array $options 解密选项
     * @return string 解密后的数据
     */
    public function decrypt(string $ciphertext, string $privateKey, array $options = []): string;

    /**
     * 使用私钥签名数据
     *
     * @param string $data 要签名的数据
     * @param string $privateKey 私钥
     * @param array $options 签名选项
     * @return string 签名
     */
    public function sign(string $data, string $privateKey, array $options = []): string;

    /**
     * 使用公钥验证签名
     *
     * @param string $data 原始数据
     * @param string $signature 签名
     * @param string $publicKey 公钥
     * @param array $options 验证选项
     * @return bool 签名是否有效
     */
    public function verify(string $data, string $signature, string $publicKey, array $options = []): bool;
}
