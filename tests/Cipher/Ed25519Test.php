<?php

declare(strict_types=1);

namespace Tourze\TLSCryptoAsymmetric\Tests\Cipher;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use Tourze\TLSCryptoAsymmetric\Cipher\Ed25519;
use Tourze\TLSCryptoAsymmetric\Exception\AsymmetricCipherException;

/**
 * Ed25519签名算法测试
 *
 * @internal
 */
#[CoversClass(Ed25519::class)]
final class Ed25519Test extends TestCase
{
    protected function setUp(): void
    {
        parent::setUp();
        // 这个测试类不需要特殊的设置
    }

    /**
     * 测试获取算法名称
     */
    public function testGetName(): void
    {
        $ed25519 = new Ed25519();
        $this->assertEquals('ed25519', $ed25519->getName());
    }

    /**
     * 测试生成密钥对
     */
    public function testGenerateKeyPair(): void
    {
        // 检查sodium扩展或sodium_compat是否可用
        if (!extension_loaded('sodium') && !class_exists('ParagonIE_Sodium_Compat')) {
            self::markTestSkipped('libsodium扩展未加载且sodium_compat不可用，无法测试Ed25519');
        }

        $ed25519 = new Ed25519();
        $keyPair = $ed25519->generateKeyPair();

        $this->assertArrayHasKey('privateKey', $keyPair);
        $this->assertArrayHasKey('publicKey', $keyPair);

        // 获取密钥长度常量
        $secretKeyBytes = defined('SODIUM_CRYPTO_SIGN_SECRETKEYBYTES') ?
            SODIUM_CRYPTO_SIGN_SECRETKEYBYTES :
            64; // Ed25519私钥固定64字节

        $publicKeyBytes = defined('SODIUM_CRYPTO_SIGN_PUBLICKEYBYTES') ?
            SODIUM_CRYPTO_SIGN_PUBLICKEYBYTES :
            32; // Ed25519公钥固定32字节

        $this->assertEquals($secretKeyBytes, strlen($keyPair['privateKey']));
        $this->assertEquals($publicKeyBytes, strlen($keyPair['publicKey']));
    }

    /**
     * 测试Ed25519签名和验证
     */
    public function testSignAndVerify(): void
    {
        // 检查sodium扩展或sodium_compat是否可用
        if (!extension_loaded('sodium') && !class_exists('ParagonIE_Sodium_Compat')) {
            self::markTestSkipped('libsodium扩展未加载且sodium_compat不可用，无法测试Ed25519');
        }

        $ed25519 = new Ed25519();
        $keyPair = $ed25519->generateKeyPair();
        $privateKey = $keyPair['privateKey'];
        $publicKey = $keyPair['publicKey'];

        $message = 'Hello, Ed25519!';

        // 签名
        $signature = $ed25519->sign($message, $privateKey);

        // 获取签名长度常量
        $signBytes = defined('SODIUM_CRYPTO_SIGN_BYTES') ?
            SODIUM_CRYPTO_SIGN_BYTES :
            64; // Ed25519签名固定64字节

        $this->assertEquals($signBytes, strlen($signature));

        // 验证有效签名
        $valid = $ed25519->verify($message, $signature, $publicKey);
        $this->assertTrue($valid);

        // 验证无效签名 - 修改消息
        $valid = $ed25519->verify('Modified message', $signature, $publicKey);
        $this->assertFalse($valid);

        // 验证无效签名 - 修改签名
        $tamperedSignature = $signature;
        $tamperedSignature[0] = chr(ord($tamperedSignature[0]) ^ 1); // 翻转一个比特
        $valid = $ed25519->verify($message, $tamperedSignature, $publicKey);
        $this->assertFalse($valid);
    }

    /**
     * 测试加密操作是否抛出异常
     */
    public function testEncryptThrowsException(): void
    {
        $ed25519 = new Ed25519();
        $this->expectException(AsymmetricCipherException::class);
        $ed25519->encrypt('test', 'dummy-key');
    }

    /**
     * 测试解密操作是否抛出异常
     */
    public function testDecryptThrowsException(): void
    {
        $ed25519 = new Ed25519();
        $this->expectException(AsymmetricCipherException::class);
        $ed25519->decrypt('test', 'dummy-key');
    }

    /**
     * 测试签名无效私钥
     */
    public function testSignWithInvalidPrivateKey(): void
    {
        // 检查sodium扩展或sodium_compat是否可用
        if (!extension_loaded('sodium') && !class_exists('ParagonIE_Sodium_Compat')) {
            self::markTestSkipped('libsodium扩展未加载且sodium_compat不可用，无法测试Ed25519');
        }

        $ed25519 = new Ed25519();
        $this->expectException(AsymmetricCipherException::class);
        $ed25519->sign('test', 'invalid-key');
    }

    /**
     * 测试验证无效公钥
     */
    public function testVerifyWithInvalidPublicKey(): void
    {
        // 检查sodium扩展或sodium_compat是否可用
        if (!extension_loaded('sodium') && !class_exists('ParagonIE_Sodium_Compat')) {
            self::markTestSkipped('libsodium扩展未加载且sodium_compat不可用，无法测试Ed25519');
        }

        $ed25519 = new Ed25519();

        // 获取签名长度常量
        $signBytes = defined('SODIUM_CRYPTO_SIGN_BYTES') ?
            SODIUM_CRYPTO_SIGN_BYTES :
            64; // Ed25519签名固定64字节

        $this->expectException(AsymmetricCipherException::class);
        $ed25519->verify('test', str_repeat('a', $signBytes), 'invalid-key');
    }

    /**
     * 测试验证无效签名
     */
    public function testVerifyWithInvalidSignature(): void
    {
        // 检查sodium扩展或sodium_compat是否可用
        if (!extension_loaded('sodium') && !class_exists('ParagonIE_Sodium_Compat')) {
            self::markTestSkipped('libsodium扩展未加载且sodium_compat不可用，无法测试Ed25519');
        }

        $ed25519 = new Ed25519();
        $keyPair = $ed25519->generateKeyPair();
        $publicKey = $keyPair['publicKey'];

        $this->expectException(AsymmetricCipherException::class);
        $ed25519->verify('test', 'invalid-signature', $publicKey);
    }
}
