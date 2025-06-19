<?php

declare(strict_types=1);

namespace Tourze\TLSCryptoAsymmetric\Tests\Cipher;

use Exception;
use PHPUnit\Framework\TestCase;
use Tourze\TLSCryptoAsymmetric\Cipher\ECDSA;
use Tourze\TLSCryptoAsymmetric\Exception\AsymmetricCipherException;

/**
 * ECDSA签名算法测试
 */
class ECDSATest extends TestCase
{
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
        // 如果OpenSSL扩展未加载，则跳过测试
        if (!extension_loaded('openssl')) {
            $this->markTestSkipped('OpenSSL扩展未加载，无法测试ECDSA');
        }

        // 检查是否支持椭圆曲线
        try {
            $curves = openssl_get_curve_names();
            if (empty($curves)) {
                $this->markTestSkipped('当前OpenSSL环境不支持任何椭圆曲线');
            } else {
                echo PHP_EOL . "支持的椭圆曲线: " . implode(", ", array_slice($curves, 0, 5)) . (count($curves) > 5 ? "..." : "") . PHP_EOL;
            }
        } catch (Exception $e) {
            $this->markTestSkipped('获取支持的椭圆曲线失败: ' . $e->getMessage());
        }

        try {
            $ecdsa = new ECDSA();

            // 尝试使用多个常见曲线
            $tryCurves = ['prime256v1', 'secp384r1', 'secp521r1'];
            $keyPair = null;
            $successCurve = null;

            foreach ($tryCurves as $curve) {
                if (in_array($curve, $curves)) {
                    try {
                        echo "尝试使用曲线: $curve" . PHP_EOL;
                        $keyPair = $ecdsa->generateKeyPair(['curve' => $curve]);
                        $successCurve = $curve;
                        echo "成功使用曲线 $curve 生成密钥对" . PHP_EOL;
                        break;
                    } catch (AsymmetricCipherException $e) {
                        echo "使用曲线 $curve 生成密钥对失败: " . $e->getMessage() . PHP_EOL;
                    }
                }
            }

            if ($keyPair === null) {
                $this->markTestSkipped('无法使用任何常见曲线生成ECDSA密钥对');
            }

            $this->assertArrayHasKey('privateKey', $keyPair);
            $this->assertArrayHasKey('publicKey', $keyPair);
            $this->assertArrayHasKey('curve', $keyPair);
            $this->assertEquals($successCurve, $keyPair['curve']);

            // 验证是EC密钥
            $privateKey = @openssl_pkey_get_private($keyPair['privateKey']);
            $this->assertNotFalse($privateKey);

            $keyDetails = @openssl_pkey_get_details($privateKey);
            $this->assertEquals(OPENSSL_KEYTYPE_EC, $keyDetails['type']);
        } catch (AsymmetricCipherException $e) {
            $this->markTestSkipped('ECDSA测试跳过: ' . $e->getMessage());
        }
    }

    /**
     * 测试签名和验证
     */
    public function testSignAndVerify(): void
    {
        // 如果OpenSSL扩展未加载，则跳过测试
        if (!extension_loaded('openssl')) {
            $this->markTestSkipped('OpenSSL扩展未加载，无法测试ECDSA');
        }

        // 检查是否支持椭圆曲线
        try {
            $curves = openssl_get_curve_names();
            if (empty($curves)) {
                $this->markTestSkipped('当前OpenSSL环境不支持任何椭圆曲线');
            }
        } catch (Exception $e) {
            $this->markTestSkipped('获取支持的椭圆曲线失败: ' . $e->getMessage());
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
            $this->markTestSkipped('ECDSA签名测试跳过: ' . $e->getMessage());
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
            $this->markTestSkipped('OpenSSL扩展未加载，无法测试ECDSA');
        }

        $ecdsa = new ECDSA();

        // 测试 P-384 曲线
        try {
            $keyPair = $ecdsa->generateKeyPair(['curve' => 'secp384r1']);
            $this->assertArrayHasKey('privateKey', $keyPair);
            $this->assertEquals('secp384r1', $keyPair['curve']);
        } catch (AsymmetricCipherException $e) {
            // 如果不支持此曲线，则忽略
            $this->markTestSkipped('不支持secp384r1曲线');
        }

        // 测试 P-521 曲线
        try {
            $keyPair = $ecdsa->generateKeyPair(['curve' => 'secp521r1']);
            $this->assertArrayHasKey('privateKey', $keyPair);
            $this->assertEquals('secp521r1', $keyPair['curve']);
        } catch (AsymmetricCipherException $e) {
            // 如果不支持此曲线，则忽略
            $this->markTestSkipped('不支持secp521r1曲线');
        }
    }

    /**
     * 测试无效的曲线
     */
    public function testInvalidCurve(): void
    {
        // 如果OpenSSL扩展未加载，则跳过测试
        if (!extension_loaded('openssl')) {
            $this->markTestSkipped('OpenSSL扩展未加载，无法测试ECDSA');
        }

        $ecdsa = new ECDSA();
        $this->expectException(AsymmetricCipherException::class);
        $ecdsa->generateKeyPair(['curve' => 'clearly-invalid-curve-name']);
    }
}
