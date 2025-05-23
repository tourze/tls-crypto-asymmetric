<?php

declare(strict_types=1);

namespace Tourze\TLSCryptoAsymmetric\Tests\Signature;

use InvalidArgumentException;
use PHPUnit\Framework\TestCase;
use Tourze\TLSCryptoAsymmetric\Signature\SignatureVerifier;

/**
 * 签名验证器测试
 */
class SignatureVerifierTest extends TestCase
{
    private SignatureVerifier $verifier;

    protected function setUp(): void
    {
        $this->verifier = new SignatureVerifier();
    }

    /**
     * 测试获取支持的算法列表
     */
    public function testGetSupportedAlgorithms(): void
    {
        $algorithms = $this->verifier->getSupportedAlgorithms();
        
        $expectedAlgorithms = [
            'sha1WithRSAEncryption',
            'sha256WithRSAEncryption',
            'sha384WithRSAEncryption',
            'sha512WithRSAEncryption',
            'ecdsa-with-SHA1',
            'ecdsa-with-SHA256',
            'ecdsa-with-SHA384',
            'ecdsa-with-SHA512',
        ];
        
        $this->assertEquals($expectedAlgorithms, $algorithms);
    }

    /**
     * 测试检查算法是否受支持
     */
    public function testIsAlgorithmSupported(): void
    {
        // 测试支持的算法
        $this->assertTrue($this->verifier->isAlgorithmSupported('sha256WithRSAEncryption'));
        $this->assertTrue($this->verifier->isAlgorithmSupported('ecdsa-with-SHA256'));
        
        // 测试不支持的算法
        $this->assertFalse($this->verifier->isAlgorithmSupported('md5WithRSAEncryption'));
        $this->assertFalse($this->verifier->isAlgorithmSupported('unknown-algorithm'));
    }

    /**
     * 测试不支持的算法抛出异常
     */
    public function testVerifyWithUnsupportedAlgorithm(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('不支持的签名算法: unsupported-algorithm');
        
        $this->verifier->verify('test data', 'dummy signature', 'dummy key', 'unsupported-algorithm');
    }

    /**
     * 测试无效的算法标识符
     */
    public function testVerifyWithInvalidAlgorithmIdentifier(): void
    {
        // 不支持的算法会在isAlgorithmSupported检查时就抛出异常
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('不支持的签名算法: invalid-algorithm-format');
        
        $this->verifier->verify('test data', 'dummy signature', 'dummy key', 'invalid-algorithm-format');
    }

    /**
     * 测试验证过程中的异常处理
     */
    public function testVerifyHandlesExceptionsGracefully(): void
    {
        // 使用无效的公钥，应该返回false而不是抛出异常
        $isValid = $this->verifier->verify('test data', 'dummy signature', 'invalid key', 'sha256WithRSAEncryption');
        $this->assertFalse($isValid);
    }

    /**
     * 测试空数据和签名的处理
     */
    public function testVerifyWithEmptyDataAndSignature(): void
    {
        // 测试空数据
        $isValid = $this->verifier->verify('', 'dummy signature', 'dummy key', 'sha256WithRSAEncryption');
        $this->assertFalse($isValid);

        // 测试空签名
        $isValid = $this->verifier->verify('test data', '', 'dummy key', 'sha256WithRSAEncryption');
        $this->assertFalse($isValid);
    }

    /**
     * 测试算法解析功能
     */
    public function testAlgorithmParsing(): void
    {
        // 通过反射访问私有方法来测试算法解析
        $reflection = new \ReflectionClass($this->verifier);
        $parseMethod = $reflection->getMethod('parseAlgorithm');
        $parseMethod->setAccessible(true);

        $testCases = [
            'sha1WithRSAEncryption' => ['hash' => 'sha1', 'type' => 'rsa'],
            'sha256WithRSAEncryption' => ['hash' => 'sha256', 'type' => 'rsa'],
            'ecdsa-with-SHA256' => ['hash' => 'sha256', 'type' => 'ecdsa'],
            'ecdsa-with-SHA512' => ['hash' => 'sha512', 'type' => 'ecdsa'],
        ];

        foreach ($testCases as $algorithm => $expected) {
            $result = $parseMethod->invoke($this->verifier, $algorithm);
            $this->assertEquals($expected, $result, "Algorithm parsing failed for {$algorithm}");
        }
    }

    /**
     * 测试算法解析异常
     */
    public function testAlgorithmParsingException(): void
    {
        $reflection = new \ReflectionClass($this->verifier);
        $parseMethod = $reflection->getMethod('parseAlgorithm');
        $parseMethod->setAccessible(true);

        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('无法解析算法: unknown-algorithm');
        
        $parseMethod->invoke($this->verifier, 'unknown-algorithm');
    }

    /**
     * 测试SignatureVerifier基本功能
     */
    public function testSignatureVerifierBasicFunctionality(): void
    {
        // 测试verify方法在无效输入下返回false
        $testCases = [
            ['', '', '', 'sha256WithRSAEncryption'],
            ['data', '', '', 'sha256WithRSAEncryption'],
            ['data', 'sig', '', 'sha256WithRSAEncryption'],
            ['data', 'sig', 'key', 'ecdsa-with-SHA256'],
        ];

        foreach ($testCases as $case) {
            $result = $this->verifier->verify($case[0], $case[1], $case[2], $case[3]);
            $this->assertFalse($result, "Verify should return false for invalid inputs");
        }
    }
} 