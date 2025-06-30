<?php

declare(strict_types=1);

namespace Tourze\TLSCryptoAsymmetric\Tests\KeyPair;

use PHPUnit\Framework\TestCase;
use Tourze\TLSCryptoAsymmetric\Exception\InvalidKeyPairException;
use Tourze\TLSCryptoAsymmetric\KeyPair\KeyPair;

/**
 * KeyPair 测试类
 *
 * @covers \Tourze\TLSCryptoAsymmetric\KeyPair\KeyPair
 */
class KeyPairTest extends TestCase
{
    /**
     * 测试构造函数和获取方法
     */
    public function testConstructorAndGetters(): void
    {
        $privateKey = '-----BEGIN PRIVATE KEY-----test-----END PRIVATE KEY-----';
        $publicKey = '-----BEGIN PUBLIC KEY-----test-----END PUBLIC KEY-----';
        
        $keyPair = new KeyPair($privateKey, $publicKey);
        
        $this->assertSame($privateKey, $keyPair->getPrivateKey());
        $this->assertSame($publicKey, $keyPair->getPublicKey());
    }
    
    /**
     * 测试从数组创建密钥对
     */
    public function testFromArray(): void
    {
        $privateKey = '-----BEGIN PRIVATE KEY-----test-----END PRIVATE KEY-----';
        $publicKey = '-----BEGIN PUBLIC KEY-----test-----END PUBLIC KEY-----';
        
        $keyPairArray = [
            'privateKey' => $privateKey,
            'publicKey' => $publicKey,
        ];
        
        $keyPair = KeyPair::fromArray($keyPairArray);
        
        $this->assertInstanceOf(KeyPair::class, $keyPair);
        $this->assertSame($privateKey, $keyPair->getPrivateKey());
        $this->assertSame($publicKey, $keyPair->getPublicKey());
    }
    
    /**
     * 测试从缺少私钥的数组创建密钥对
     */
    public function testFromArrayMissingPrivateKey(): void
    {
        $this->expectException(InvalidKeyPairException::class);
        $this->expectExceptionMessage('密钥对数组必须包含 privateKey 和 publicKey');
        
        KeyPair::fromArray(['publicKey' => 'test']);
    }
    
    /**
     * 测试从缺少公钥的数组创建密钥对
     */
    public function testFromArrayMissingPublicKey(): void
    {
        $this->expectException(InvalidKeyPairException::class);
        $this->expectExceptionMessage('密钥对数组必须包含 privateKey 和 publicKey');
        
        KeyPair::fromArray(['privateKey' => 'test']);
    }
    
    /**
     * 测试从空数组创建密钥对
     */
    public function testFromArrayEmpty(): void
    {
        $this->expectException(InvalidKeyPairException::class);
        $this->expectExceptionMessage('密钥对数组必须包含 privateKey 和 publicKey');
        
        KeyPair::fromArray([]);
    }
    
    /**
     * 测试转换为数组
     */
    public function testToArray(): void
    {
        $privateKey = '-----BEGIN PRIVATE KEY-----test-----END PRIVATE KEY-----';
        $publicKey = '-----BEGIN PUBLIC KEY-----test-----END PUBLIC KEY-----';
        
        $keyPair = new KeyPair($privateKey, $publicKey);
        $array = $keyPair->toArray();
        
        $this->assertArrayHasKey('privateKey', $array);
        $this->assertArrayHasKey('publicKey', $array);
        $this->assertSame($privateKey, $array['privateKey']);
        $this->assertSame($publicKey, $array['publicKey']);
    }
    
    /**
     * 测试往返转换（数组 -> KeyPair -> 数组）
     */
    public function testRoundTripConversion(): void
    {
        $originalArray = [
            'privateKey' => '-----BEGIN PRIVATE KEY-----test-----END PRIVATE KEY-----',
            'publicKey' => '-----BEGIN PUBLIC KEY-----test-----END PUBLIC KEY-----',
        ];
        
        $keyPair = KeyPair::fromArray($originalArray);
        $resultArray = $keyPair->toArray();
        
        $this->assertSame($originalArray, $resultArray);
    }
}