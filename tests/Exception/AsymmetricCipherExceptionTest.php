<?php

declare(strict_types=1);

namespace Tourze\TLSCryptoAsymmetric\Tests\Exception;

use PHPUnit\Framework\TestCase;
use Tourze\TLSCryptoAsymmetric\Exception\AsymmetricCipherException;
use Tourze\TLSCryptoAsymmetric\Exception\CryptoException;

/**
 * AsymmetricCipherException测试
 */
class AsymmetricCipherExceptionTest extends TestCase
{
    /**
     * 测试异常基本功能
     */
    public function testBasicException(): void
    {
        $message = 'Test asymmetric cipher exception';
        $code = 1001;
        $previous = new \Exception('Previous exception');

        $exception = new AsymmetricCipherException($message, $code, $previous);

        $this->assertEquals($message, $exception->getMessage());
        $this->assertEquals($code, $exception->getCode());
        $this->assertSame($previous, $exception->getPrevious());
    }

    /**
     * 测试异常继承关系
     */
    public function testInheritance(): void
    {
        $exception = new AsymmetricCipherException('Test message');

        $this->assertInstanceOf(CryptoException::class, $exception);
        $this->assertInstanceOf(\Exception::class, $exception);
    }

    /**
     * 测试无参数构造
     */
    public function testNoArgumentsConstructor(): void
    {
        $exception = new AsymmetricCipherException();

        $this->assertEquals('', $exception->getMessage());
        $this->assertEquals(0, $exception->getCode());
        $this->assertNull($exception->getPrevious());
    }

    /**
     * 测试只传递消息参数
     */
    public function testMessageOnlyConstructor(): void
    {
        $message = 'Error occurred';
        $exception = new AsymmetricCipherException($message);

        $this->assertEquals($message, $exception->getMessage());
        $this->assertEquals(0, $exception->getCode());
        $this->assertNull($exception->getPrevious());
    }

    /**
     * 测试异常可以被捕获
     */
    public function testExceptionCanBeCaught(): void
    {
        $message = 'Test exception catching';
        $caught = false;

        try {
            throw new AsymmetricCipherException($message);
        } catch (AsymmetricCipherException $e) {
            $caught = true;
            $this->assertEquals($message, $e->getMessage());
        }

        $this->assertTrue($caught, 'AsymmetricCipherException should be caught');
    }

    /**
     * 测试异常可以被父类捕获
     */
    public function testExceptionCanBeCaughtByParent(): void
    {
        $message = 'Test parent exception catching';
        $caught = false;

        try {
            throw new AsymmetricCipherException($message);
        } catch (CryptoException $e) {
            $caught = true;
            $this->assertEquals($message, $e->getMessage());
        }

        $this->assertTrue($caught, 'AsymmetricCipherException should be caught by CryptoException');
    }

    /**
     * 测试异常可以被顶级Exception捕获
     */
    public function testExceptionCanBeCaughtByTopLevelException(): void
    {
        $message = 'Test top level exception catching';
        $caught = false;

        try {
            throw new AsymmetricCipherException($message);
        } catch (\Throwable $e) {
            $caught = true;
            $this->assertEquals($message, $e->getMessage());
        }

        $this->assertTrue($caught, 'AsymmetricCipherException should be caught by Exception');
    }

    /**
     * 测试异常堆栈跟踪
     */
    public function testExceptionStackTrace(): void
    {
        $exception = new AsymmetricCipherException('Stack trace test');

        $trace = $exception->getTrace();
        $this->assertNotEmpty($trace);

        // 验证栈顶是当前方法
        $this->assertEquals(__FUNCTION__, $trace[0]['function']);
        $this->assertEquals(__CLASS__, $trace[0]['class']);
    }

    /**
     * 测试异常字符串表示
     */
    public function testExceptionStringRepresentation(): void
    {
        $message = 'String representation test';
        $exception = new AsymmetricCipherException($message);

        $stringRepresentation = (string) $exception;
        $this->assertStringContainsString($message, $stringRepresentation);
        $this->assertStringContainsString('AsymmetricCipherException', $stringRepresentation);
    }
} 