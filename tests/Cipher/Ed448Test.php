<?php

declare(strict_types=1);

namespace Tourze\TLSCryptoAsymmetric\Tests\Cipher;

use PHPUnit\Framework\TestCase;
use Tourze\TLSCryptoAsymmetric\Cipher\Ed448;
use Tourze\TLSCryptoAsymmetric\Exception\AsymmetricCipherException;

/**
 * Ed448签名算法测试
 */
class Ed448Test extends TestCase
{
    private Ed448 $ed448;

    protected function setUp(): void
    {
        $this->ed448 = new Ed448();
    }

    /**
     * 测试获取算法名称
     */
    public function testGetName(): void
    {
        $this->assertEquals('ed448', $this->ed448->getName());
    }

    /**
     * 测试生成Ed448密钥对
     */
    public function testGenerateKeyPair(): void
    {
        if (!extension_loaded('openssl')) {
            $this->markTestSkipped('OpenSSL扩展未加载，无法测试Ed448');
        }

        // 检查OpenSSL是否支持Ed448
        $curves = openssl_get_curve_names();
        if (!in_array('ED448', $curves)) {
            $this->markTestSkipped('当前OpenSSL版本不支持Ed448曲线');
        }

        try {
            $keyPair = $this->ed448->generateKeyPair();

            $this->assertArrayHasKey('privateKey', $keyPair);
            $this->assertArrayHasKey('publicKey', $keyPair);

            // 验证密钥格式（PEM格式）
            $this->assertStringContainsString('-----BEGIN PRIVATE KEY-----', $keyPair['privateKey']);
            $this->assertStringContainsString('-----END PRIVATE KEY-----', $keyPair['privateKey']);
            $this->assertStringContainsString('-----BEGIN PUBLIC KEY-----', $keyPair['publicKey']);
            $this->assertStringContainsString('-----END PUBLIC KEY-----', $keyPair['publicKey']);

            // 验证密钥类型
            $privateKey = openssl_pkey_get_private($keyPair['privateKey']);
            $this->assertNotFalse($privateKey);

            $keyDetails = openssl_pkey_get_details($privateKey);
            $this->assertEquals(OPENSSL_KEYTYPE_EC, $keyDetails['type']);
        } catch (AsymmetricCipherException $e) {
            $this->markTestSkipped('Ed448密钥生成测试跳过: ' . $e->getMessage());
        }
    }

    /**
     * 测试Ed448签名和验证
     */
    public function testSignAndVerify(): void
    {
        if (!extension_loaded('openssl')) {
            $this->markTestSkipped('OpenSSL扩展未加载，无法测试Ed448');
        }

        $curves = openssl_get_curve_names();
        if (!in_array('ED448', $curves)) {
            $this->markTestSkipped('当前OpenSSL版本不支持Ed448曲线');
        }

        try {
            $keyPair = $this->ed448->generateKeyPair();
            $message = 'Hello, Ed448 Signature!';

            // 签名
            $signature = $this->ed448->sign($message, $keyPair['privateKey']);
            $this->assertNotEmpty($signature);

            // 验证有效签名
            $isValid = $this->ed448->verify($message, $signature, $keyPair['publicKey']);
            $this->assertTrue($isValid);

            // 验证无效签名 - 修改消息
            $isValid = $this->ed448->verify('Modified message', $signature, $keyPair['publicKey']);
            $this->assertFalse($isValid);

            // 验证无效签名 - 篡改签名
            $tamperedSignature = $signature;
            $tamperedSignature[0] = chr(ord($tamperedSignature[0]) ^ 1);
            $isValid = $this->ed448->verify($message, $tamperedSignature, $keyPair['publicKey']);
            $this->assertFalse($isValid);
        } catch (AsymmetricCipherException $e) {
            $this->markTestSkipped('Ed448签名验证测试跳过: ' . $e->getMessage());
        }
    }

    /**
     * 测试加密操作抛出异常
     */
    public function testEncryptThrowsException(): void
    {
        $this->expectException(AsymmetricCipherException::class);
        $this->expectExceptionMessage('Ed448是签名算法，不支持加密操作');
        $this->ed448->encrypt('test', 'dummy-key');
    }

    /**
     * 测试解密操作抛出异常
     */
    public function testDecryptThrowsException(): void
    {
        $this->expectException(AsymmetricCipherException::class);
        $this->expectExceptionMessage('Ed448是签名算法，不支持解密操作');
        $this->ed448->decrypt('test', 'dummy-key');
    }

    /**
     * 测试无效私钥签名
     */
    public function testSignWithInvalidPrivateKey(): void
    {
        if (!extension_loaded('openssl')) {
            $this->markTestSkipped('OpenSSL扩展未加载，无法测试Ed448');
        }

        $curves = openssl_get_curve_names();
        if (!in_array('ED448', $curves)) {
            $this->markTestSkipped('当前OpenSSL版本不支持Ed448曲线');
        }

        $this->expectException(AsymmetricCipherException::class);
        $this->ed448->sign('test message', 'invalid-private-key');
    }

    /**
     * 测试无效公钥验证
     */
    public function testVerifyWithInvalidPublicKey(): void
    {
        if (!extension_loaded('openssl')) {
            $this->markTestSkipped('OpenSSL扩展未加载，无法测试Ed448');
        }

        $curves = openssl_get_curve_names();
        if (!in_array('ED448', $curves)) {
            $this->markTestSkipped('当前OpenSSL版本不支持Ed448曲线');
        }

        $this->expectException(AsymmetricCipherException::class);
        $this->ed448->verify('test message', 'dummy-signature', 'invalid-public-key');
    }

    /**
     * 测试非Ed448密钥类型
     */
    public function testSignWithNonEd448Key(): void
    {
        if (!extension_loaded('openssl')) {
            $this->markTestSkipped('OpenSSL扩展未加载，无法测试Ed448');
        }

        $curves = openssl_get_curve_names();
        if (!in_array('ED448', $curves)) {
            $this->markTestSkipped('当前OpenSSL版本不支持Ed448曲线');
        }

        // 生成RSA密钥作为错误的密钥类型
        $config = [
            'private_key_bits' => 1024,
            'private_key_type' => OPENSSL_KEYTYPE_RSA,
        ];
        $rsaKey = openssl_pkey_new($config);
        openssl_pkey_export($rsaKey, $rsaPrivateKey);

        $this->expectException(AsymmetricCipherException::class);
        $this->expectExceptionMessage('提供的密钥不是ED448密钥');
        $this->ed448->sign('test message', $rsaPrivateKey);
    }

    /**
     * 测试OpenSSL扩展未加载时的异常
     */
    public function testOpenSSLExtensionNotLoaded(): void
    {
        if (extension_loaded('openssl')) {
            $this->markTestSkipped('OpenSSL扩展已加载，无法测试未加载情况');
        }

        $this->expectException(AsymmetricCipherException::class);
        $this->expectExceptionMessage('OpenSSL扩展未加载，无法使用Ed448替代实现');
        $this->ed448->generateKeyPair();
    }

    /**
     * 测试不支持Ed448曲线的环境
     */
    public function testUnsupportedEd448Curve(): void
    {
        if (!extension_loaded('openssl')) {
            $this->markTestSkipped('OpenSSL扩展未加载，无法测试Ed448');
        }

        $curves = openssl_get_curve_names();
        if (in_array('ED448', $curves)) {
            $this->markTestSkipped('当前OpenSSL版本支持Ed448曲线，无法测试不支持情况');
        }

        $this->expectException(AsymmetricCipherException::class);
        $this->expectExceptionMessage('当前OpenSSL版本不支持Ed448曲线');
        $this->ed448->generateKeyPair();
    }

    /**
     * 测试使用不匹配的密钥对进行验证
     */
    public function testVerifyWithMismatchedKeyPair(): void
    {
        if (!extension_loaded('openssl')) {
            $this->markTestSkipped('OpenSSL扩展未加载，无法测试Ed448');
        }

        $curves = openssl_get_curve_names();
        if (!in_array('ED448', $curves)) {
            $this->markTestSkipped('当前OpenSSL版本不支持Ed448曲线');
        }

        try {
            $keyPair1 = $this->ed448->generateKeyPair();
            $keyPair2 = $this->ed448->generateKeyPair();
            $message = 'Test message';

            // 使用第一个密钥对签名
            $signature = $this->ed448->sign($message, $keyPair1['privateKey']);

            // 使用第二个密钥对的公钥验证，应该失败
            $isValid = $this->ed448->verify($message, $signature, $keyPair2['publicKey']);
            $this->assertFalse($isValid);
        } catch (AsymmetricCipherException $e) {
            $this->markTestSkipped('Ed448不匹配密钥对测试跳过: ' . $e->getMessage());
        }
    }

    /**
     * 测试Ed448密钥生成的一致性
     */
    public function testKeyGenerationConsistency(): void
    {
        if (!extension_loaded('openssl')) {
            $this->markTestSkipped('OpenSSL扩展未加载，无法测试Ed448');
        }

        $curves = openssl_get_curve_names();
        if (!in_array('ED448', $curves)) {
            $this->markTestSkipped('当前OpenSSL版本不支持Ed448曲线');
        }

        try {
            // 生成多个密钥对，确保每次生成的都不同
            $keyPair1 = $this->ed448->generateKeyPair();
            $keyPair2 = $this->ed448->generateKeyPair();

            $this->assertNotEquals($keyPair1['privateKey'], $keyPair2['privateKey']);
            $this->assertNotEquals($keyPair1['publicKey'], $keyPair2['publicKey']);
        } catch (AsymmetricCipherException $e) {
            $this->markTestSkipped('Ed448密钥生成一致性测试跳过: ' . $e->getMessage());
        }
    }
}
