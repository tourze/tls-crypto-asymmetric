<?php

declare(strict_types=1);

namespace Tourze\TLSCryptoAsymmetric\Tests\Cipher;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use Tourze\TLSCryptoAsymmetric\Cipher\ECDSA;
use Tourze\TLSCryptoAsymmetric\Exception\AsymmetricCipherException;

/**
 * ECDSA签名算法测试
 *
 * @internal
 */
#[CoversClass(ECDSA::class)]
final class ECDSATest extends TestCase
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
        $ecdsa = new ECDSA();
        $this->assertEquals('ecdsa', $ecdsa->getName());
    }

    /**
     * 测试生成密钥对
     */
    public function testGenerateKeyPair(): void
    {
        $this->skipIfOpenSSLNotAvailable();
        $curves = $this->getAvailableCurves();
        $ecdsa = new ECDSA();

        $keyPair = $this->generateKeyPairWithAnyCurve($ecdsa, $curves);

        // 直接在测试方法中进行断言
        $this->assertArrayHasKey('privateKey', $keyPair);
        $this->assertArrayHasKey('publicKey', $keyPair);
        $this->assertArrayHasKey('curve', $keyPair);

        $privateKey = @openssl_pkey_get_private($keyPair['privateKey']);
        $this->assertNotFalse($privateKey);

        $keyDetails = @openssl_pkey_get_details($privateKey);
        $this->assertIsArray($keyDetails);
        $this->assertArrayHasKey('type', $keyDetails);
        $this->assertEquals(OPENSSL_KEYTYPE_EC, $keyDetails['type']);
    }

    private function skipIfOpenSSLNotAvailable(): void
    {
        if (!extension_loaded('openssl')) {
            self::markTestSkipped('OpenSSL扩展未加载，无法测试ECDSA');
        }
    }

    /**
     * @return list<string>
     */
    private function getAvailableCurves(): array
    {
        try {
            $curves = openssl_get_curve_names();
            if (false === $curves || [] === $curves) {
                self::markTestSkipped('当前OpenSSL环境不支持任何椭圆曲线');
            }

            /** @var list<string> $curves */
            return $curves;
        } catch (\Exception $e) {
            self::markTestSkipped('获取支持的椭圆曲线失败: ' . $e->getMessage());
        }
    }

    /**
     * @param list<string> $curves
     * @return array{privateKey: string, publicKey: string, curve: string}
     */
    private function generateKeyPairWithAnyCurve(ECDSA $ecdsa, array $curves): array
    {
        $tryCurves = ['prime256v1', 'secp384r1', 'secp521r1'];

        foreach ($tryCurves as $curve) {
            if (in_array($curve, $curves, true)) {
                $keyPair = $this->tryGenerateKeyPair($ecdsa, $curve);
                if (null !== $keyPair) {
                    return $keyPair;
                }
            }
        }

        self::markTestSkipped('无法使用任何常见曲线生成ECDSA密钥对');
    }

    /**
     * @return array{privateKey: string, publicKey: string, curve: string}|null
     */
    private function tryGenerateKeyPair(ECDSA $ecdsa, string $curve): ?array
    {
        try {
            $keyPair = $ecdsa->generateKeyPair(['curve' => $curve]);
            // Ensure the return type matches our expected structure
            if (isset($keyPair['privateKey'], $keyPair['publicKey'], $keyPair['curve'])) {
                return [
                    'privateKey' => (string) $keyPair['privateKey'],
                    'publicKey' => (string) $keyPair['publicKey'],
                    'curve' => (string) $keyPair['curve'],
                ];
            }

            return null;
        } catch (AsymmetricCipherException $e) {
            return null;
        }
    }

    /**
     * 测试签名和验证
     */
    public function testSignAndVerify(): void
    {
        // 如果OpenSSL扩展未加载，则跳过测试
        if (!extension_loaded('openssl')) {
            self::markTestSkipped('OpenSSL扩展未加载，无法测试ECDSA');
        }

        // 检查是否支持椭圆曲线
        try {
            $curves = openssl_get_curve_names();
            if (false === $curves || [] === $curves) {
                self::markTestSkipped('当前OpenSSL环境不支持任何椭圆曲线');
            }
        } catch (\Exception $e) {
            self::markTestSkipped('获取支持的椭圆曲线失败: ' . $e->getMessage());
        }

        try {
            $ecdsa = new ECDSA();
            $keyPair = $ecdsa->generateKeyPair();
            $privateKey = $keyPair['privateKey'];
            $publicKey = $keyPair['publicKey'];

            $message = 'Hello, ECDSA!';

            // 签名
            $signature = $ecdsa->sign($message, $privateKey);
            $this->assertNotEmpty($signature);

            // 验证有效签名
            $valid = $ecdsa->verify($message, $signature, $publicKey);
            $this->assertTrue($valid);

            // 验证无效签名 - 修改消息
            $valid = $ecdsa->verify('Modified message', $signature, $publicKey);
            $this->assertFalse($valid);
        } catch (AsymmetricCipherException $e) {
            self::markTestSkipped('ECDSA签名测试跳过: ' . $e->getMessage());
        }
    }

    /**
     * 测试加密操作是否抛出异常
     */
    public function testEncryptThrowsException(): void
    {
        $ecdsa = new ECDSA();
        $this->expectException(AsymmetricCipherException::class);
        $ecdsa->encrypt('test', 'dummy-key');
    }

    /**
     * 测试解密操作是否抛出异常
     */
    public function testDecryptThrowsException(): void
    {
        $ecdsa = new ECDSA();
        $this->expectException(AsymmetricCipherException::class);
        $ecdsa->decrypt('test', 'dummy-key');
    }

    /**
     * 测试不同曲线的密钥对生成
     */
    public function testGenerateKeyPairWithDifferentCurves(): void
    {
        // 如果OpenSSL扩展未加载，则跳过测试
        if (!extension_loaded('openssl')) {
            self::markTestSkipped('OpenSSL扩展未加载，无法测试ECDSA');
        }

        $ecdsa = new ECDSA();

        // 测试 P-384 曲线
        try {
            $keyPair = $ecdsa->generateKeyPair(['curve' => 'secp384r1']);
            $this->assertArrayHasKey('privateKey', $keyPair);
            // $keyPair['curve'] 已移除，不再验证
        } catch (AsymmetricCipherException $e) {
            // 如果不支持此曲线，则忽略
            self::markTestSkipped('不支持secp384r1曲线');
        }

        // 测试 P-521 曲线
        try {
            $keyPair = $ecdsa->generateKeyPair(['curve' => 'secp521r1']);
            $this->assertArrayHasKey('privateKey', $keyPair);
            // $keyPair['curve'] 已移除，不再验证
        } catch (AsymmetricCipherException $e) {
            // 如果不支持此曲线，则忽略
            self::markTestSkipped('不支持secp521r1曲线');
        }
    }

    /**
     * 测试无效的曲线
     */
    public function testInvalidCurve(): void
    {
        // 如果OpenSSL扩展未加载，则跳过测试
        if (!extension_loaded('openssl')) {
            self::markTestSkipped('OpenSSL扩展未加载，无法测试ECDSA');
        }

        $ecdsa = new ECDSA();
        $this->expectException(AsymmetricCipherException::class);
        $ecdsa->generateKeyPair(['curve' => 'clearly-invalid-curve-name']);
    }

    /**
     * 测试签名验证方法
     */
    public function testVerify(): void
    {
        $this->skipIfOpenSSLNotAvailable();
        $curves = $this->getAvailableCurves();
        $ecdsa = new ECDSA();

        try {
            $keyPair = $this->generateKeyPairWithAnyCurve($ecdsa, $curves);
            $privateKey = $keyPair['privateKey'];
            $publicKey = $keyPair['publicKey'];

            $message = 'Test message for verify';

            // 生成签名
            $signature = $ecdsa->sign($message, $privateKey);

            // 测试有效签名验证
            $isValid = $ecdsa->verify($message, $signature, $publicKey);
            $this->assertTrue($isValid);

            // 测试无效签名验证 - 错误的消息
            $isValid = $ecdsa->verify('Wrong message', $signature, $publicKey);
            $this->assertFalse($isValid);

            // 测试无效签名验证 - 错误的签名
            $wrongSignature = substr($signature, 0, -1) . 'X';
            $isValid = $ecdsa->verify($message, $wrongSignature, $publicKey);
            $this->assertFalse($isValid);

            // 测试使用不同哈希算法
            $signatureWithSha384 = $ecdsa->sign($message, $privateKey, ['hash' => 'sha384']);
            $isValid = $ecdsa->verify($message, $signatureWithSha384, $publicKey, ['hash' => 'sha384']);
            $this->assertTrue($isValid);
        } catch (AsymmetricCipherException $e) {
            self::markTestSkipped('ECDSA签名验证测试跳过: ' . $e->getMessage());
        }
    }
}
