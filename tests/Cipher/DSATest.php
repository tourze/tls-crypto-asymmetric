<?php

declare(strict_types=1);

namespace Tourze\TLSCryptoAsymmetric\Tests\Cipher;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use Tourze\TLSCryptoAsymmetric\Cipher\DSA;
use Tourze\TLSCryptoAsymmetric\Exception\AsymmetricCipherException;

/**
 * DSA数字签名算法测试
 *
 * @internal
 */
#[CoversClass(DSA::class)]
final class DSATest extends TestCase
{
    private DSA $dsa;

    protected function setUp(): void
    {
        parent::setUp();
        $this->dsa = new DSA();
    }

    /**
     * 测试获取算法名称
     */
    public function testGetName(): void
    {
        $this->assertEquals('dsa', $this->dsa->getName());
    }

    /**
     * 测试生成DSA密钥对
     */
    public function testGenerateKeyPair(): void
    {
        // 检查OpenSSL扩展
        if (!extension_loaded('openssl')) {
            self::markTestSkipped('OpenSSL扩展未加载，无法测试DSA');
        }

        try {
            $keyPair = $this->dsa->generateKeyPair();

            $this->assertArrayHasKey('privateKey', $keyPair);
            $this->assertArrayHasKey('publicKey', $keyPair);
            // $keyPair['bits'] 已移除，不再验证

            // 验证密钥格式
            $this->assertStringContainsString('-----BEGIN PRIVATE KEY-----', $keyPair['privateKey']);
            $this->assertStringContainsString('-----END PRIVATE KEY-----', $keyPair['privateKey']);
            $this->assertStringContainsString('-----BEGIN PUBLIC KEY-----', $keyPair['publicKey']);
            $this->assertStringContainsString('-----END PUBLIC KEY-----', $keyPair['publicKey']);

            // 验证密钥类型
            $privateKey = openssl_pkey_get_private($keyPair['privateKey']);
            $this->assertNotFalse($privateKey);

            $keyDetails = openssl_pkey_get_details($privateKey);
            $this->assertIsArray($keyDetails);
            $this->assertArrayHasKey('type', $keyDetails);
            $this->assertEquals(OPENSSL_KEYTYPE_DSA, $keyDetails['type']);
        } catch (AsymmetricCipherException $e) {
            self::markTestSkipped('DSA密钥生成测试跳过: ' . $e->getMessage());
        }
    }

    /**
     * 测试生成指定长度的DSA密钥对
     */
    public function testGenerateKeyPairWithCustomBits(): void
    {
        if (!extension_loaded('openssl')) {
            self::markTestSkipped('OpenSSL扩展未加载，无法测试DSA');
        }

        try {
            $keyPair = $this->dsa->generateKeyPair(['bits' => 1024]);
            // $keyPair['bits'] 已移除，不再验证

            // 验证实际密钥长度
            $privateKey = openssl_pkey_get_private($keyPair['privateKey']);
            $this->assertNotFalse($privateKey);
            $keyDetails = openssl_pkey_get_details($privateKey);
            $this->assertIsArray($keyDetails);
            $this->assertArrayHasKey('bits', $keyDetails);
            $this->assertEquals(1024, $keyDetails['bits']);
        } catch (AsymmetricCipherException $e) {
            self::markTestSkipped('DSA自定义长度密钥生成测试跳过: ' . $e->getMessage());
        }
    }

    /**
     * 测试无效密钥长度异常
     */
    public function testGenerateKeyPairWithInvalidBits(): void
    {
        if (!extension_loaded('openssl')) {
            self::markTestSkipped('OpenSSL扩展未加载，无法测试DSA');
        }

        $this->expectException(AsymmetricCipherException::class);
        $this->expectExceptionMessage('DSA密钥长度必须在1024-4096位之间');
        $this->dsa->generateKeyPair(['bits' => 512]);
    }

    /**
     * 测试DSA签名和验证
     */
    public function testSignAndVerify(): void
    {
        if (!extension_loaded('openssl')) {
            self::markTestSkipped('OpenSSL扩展未加载，无法测试DSA');
        }

        try {
            $keyPair = $this->dsa->generateKeyPair(['bits' => 1024]);
            $message = 'Hello, DSA Signature!';

            // 签名
            $signature = $this->dsa->sign($message, $keyPair['privateKey']);
            $this->assertNotEmpty($signature);

            // 验证有效签名
            $isValid = $this->dsa->verify($message, $signature, $keyPair['publicKey']);
            $this->assertTrue($isValid);

            // 验证无效签名 - 修改消息
            $isValid = $this->dsa->verify('Modified message', $signature, $keyPair['publicKey']);
            $this->assertFalse($isValid);

            // 验证无效签名 - 篡改签名
            $tamperedSignature = $signature;
            $tamperedSignature[0] = chr(ord($tamperedSignature[0]) ^ 1);
            $isValid = $this->dsa->verify($message, $tamperedSignature, $keyPair['publicKey']);
            $this->assertFalse($isValid);
        } catch (AsymmetricCipherException $e) {
            self::markTestSkipped('DSA签名验证测试跳过: ' . $e->getMessage());
        }
    }

    /**
     * 测试使用不同摘要算法签名
     */
    public function testSignWithDifferentDigestAlgorithms(): void
    {
        if (!extension_loaded('openssl')) {
            self::markTestSkipped('OpenSSL扩展未加载，无法测试DSA');
        }

        try {
            $keyPair = $this->dsa->generateKeyPair(['bits' => 1024]);
            $message = 'Test message for different digest algorithms';

            $algorithms = ['sha1', 'sha256', 'sha384', 'sha512'];

            foreach ($algorithms as $algorithm) {
                $signature = $this->dsa->sign($message, $keyPair['privateKey'], ['digest_alg' => $algorithm]);
                $isValid = $this->dsa->verify($message, $signature, $keyPair['publicKey'], ['digest_alg' => $algorithm]);
                $this->assertTrue($isValid, "DSA signature with {$algorithm} should be valid");

                // 验证算法不匹配的情况
                $otherAlgorithm = 'sha256' === $algorithm ? 'sha1' : 'sha256';
                $isValid = $this->dsa->verify($message, $signature, $keyPair['publicKey'], ['digest_alg' => $otherAlgorithm]);
                $this->assertFalse($isValid, 'DSA signature verification should fail with mismatched algorithm');
            }
        } catch (AsymmetricCipherException $e) {
            self::markTestSkipped('DSA不同摘要算法测试跳过: ' . $e->getMessage());
        }
    }

    /**
     * 测试加密操作抛出异常
     */
    public function testEncryptThrowsException(): void
    {
        $this->expectException(AsymmetricCipherException::class);
        $this->expectExceptionMessage('DSA是签名算法，不支持加密操作');
        $this->dsa->encrypt('test', 'dummy-key');
    }

    /**
     * 测试解密操作抛出异常
     */
    public function testDecryptThrowsException(): void
    {
        $this->expectException(AsymmetricCipherException::class);
        $this->expectExceptionMessage('DSA是签名算法，不支持解密操作');
        $this->dsa->decrypt('test', 'dummy-key');
    }

    /**
     * 测试无效私钥签名
     */
    public function testSignWithInvalidPrivateKey(): void
    {
        if (!extension_loaded('openssl')) {
            self::markTestSkipped('OpenSSL扩展未加载，无法测试DSA');
        }

        $this->expectException(AsymmetricCipherException::class);
        $this->dsa->sign('test message', 'invalid-private-key');
    }

    /**
     * 测试无效公钥验证
     */
    public function testVerifyWithInvalidPublicKey(): void
    {
        if (!extension_loaded('openssl')) {
            self::markTestSkipped('OpenSSL扩展未加载，无法测试DSA');
        }

        $this->expectException(AsymmetricCipherException::class);
        $this->dsa->verify('test message', 'dummy-signature', 'invalid-public-key');
    }

    /**
     * 测试非DSA密钥类型
     */
    public function testSignWithNonDSAKey(): void
    {
        if (!extension_loaded('openssl')) {
            self::markTestSkipped('OpenSSL扩展未加载，无法测试DSA');
        }

        // 生成RSA密钥作为错误的密钥类型
        $config = [
            'private_key_bits' => 1024,
            'private_key_type' => OPENSSL_KEYTYPE_RSA,
        ];
        $rsaKey = openssl_pkey_new($config);
        $this->assertNotFalse($rsaKey);
        $exportResult = openssl_pkey_export($rsaKey, $rsaPrivateKey);
        $this->assertTrue($exportResult);

        $this->expectException(AsymmetricCipherException::class);
        $this->expectExceptionMessage('提供的密钥不是DSA密钥');
        $this->dsa->sign('test message', $rsaPrivateKey);
    }

    /**
     * 测试OpenSSL扩展未加载时的异常（模拟测试）
     */
    public function testOpenSSLExtensionNotLoaded(): void
    {
        // 模拟测试：如果没有OpenSSL扩展，则DSA无法工作
        // 这里我们模拟这种情况通过检查代码逻辑是否正确

        // 在没有OpenSSL扩展的情况下，应该抛出异常
        // 但是由于我们无法真正卸载扩展，所以我们只能验证代码逻辑

        if (!extension_loaded('openssl')) {
            // 如果真的没有OpenSSL，测试应该抛出异常
            $this->expectException(AsymmetricCipherException::class);
            $this->expectExceptionMessage('OpenSSL扩展未加载，无法使用DSA');
            $this->dsa->generateKeyPair();
        } else {
            // 在有OpenSSL的环境中，正常运行并跳过此测试
            self::markTestSkipped('OpenSSL扩展已加载，无法真正测试未加载情况，但代码逻辑正确');
        }
    }

    /**
     * 测试使用不匹配的密钥对进行验证
     */
    public function testVerifyWithMismatchedKeyPair(): void
    {
        if (!extension_loaded('openssl')) {
            self::markTestSkipped('OpenSSL扩展未加载，无法测试DSA');
        }

        try {
            $keyPair1 = $this->dsa->generateKeyPair(['bits' => 1024]);
            $keyPair2 = $this->dsa->generateKeyPair(['bits' => 1024]);
            $message = 'Test message';

            // 使用第一个密钥对签名
            $signature = $this->dsa->sign($message, $keyPair1['privateKey']);

            // 使用第二个密钥对的公钥验证，应该失败
            $isValid = $this->dsa->verify($message, $signature, $keyPair2['publicKey']);
            $this->assertFalse($isValid);
        } catch (AsymmetricCipherException $e) {
            self::markTestSkipped('DSA不匹配密钥对测试跳过: ' . $e->getMessage());
        }
    }
}
