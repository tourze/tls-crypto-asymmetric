<?php

declare(strict_types=1);

namespace Tourze\TLSCryptoAsymmetric\KeyPair;

use Tourze\TLSCryptoAsymmetric\Exception\InvalidKeyPairException;

/**
 * 密钥对类，封装公钥和私钥
 */
class KeyPair
{
    /**
     * @var string 私钥
     */
    private string $privateKey;
    
    /**
     * @var string 公钥
     */
    private string $publicKey;
    
    /**
     * 构造函数
     *
     * @param string $privateKey 私钥
     * @param string $publicKey 公钥
     */
    public function __construct(string $privateKey, string $publicKey)
    {
        $this->privateKey = $privateKey;
        $this->publicKey = $publicKey;
    }
    
    /**
     * 从数组创建密钥对
     *
     * @param array $keyPair 包含 'privateKey' 和 'publicKey' 的数组
     * @return self
     */
    public static function fromArray(array $keyPair): self
    {
        if (!isset($keyPair['privateKey']) || !isset($keyPair['publicKey'])) {
            throw new InvalidKeyPairException('密钥对数组必须包含 privateKey 和 publicKey');
        }

        return new self($keyPair['privateKey'], $keyPair['publicKey']);
    }
    
    /**
     * 获取私钥
     *
     * @return string
     */
    public function getPrivateKey(): string
    {
        return $this->privateKey;
    }
    
    /**
     * 获取公钥
     *
     * @return string
     */
    public function getPublicKey(): string
    {
        return $this->publicKey;
    }
    
    /**
     * 转换为数组
     *
     * @return array
     */
    public function toArray(): array
    {
        return [
            'privateKey' => $this->privateKey,
            'publicKey' => $this->publicKey,
        ];
    }
}