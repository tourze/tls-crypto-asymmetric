<?php

declare(strict_types=1);

namespace Tourze\TLSCryptoAsymmetric\Tests\Exception;

use PHPUnit\Framework\TestCase;
use Tourze\TLSCryptoAsymmetric\Exception\CryptoException;

/**
 * CryptoException测试
 */
class CryptoExceptionTest extends TestCase
{
    /**
     * 测试异常基本功能
     */
    public function testBasicException(): void
    {
        $message = 'Test crypto exception';
        $code = 2001;
        $previous = new \Exception('Previous exception');

        $exception = new CryptoException($message, $code, $previous);

        $this->assertEquals($message, $exception->getMessage());
        $this->assertEquals($code, $exception->getCode());
        $this->assertSame($previous, $exception->getPrevious());
    }

    /**
     * 测试异常继承关系
     */
    public function testInheritance(): void
    {
        $exception = new CryptoException('Test message');

        $this->assertInstanceOf(\Exception::class, $exception);
    }

    /**
     * 测试无参数构造
     */
    public function testNoArgumentsConstructor(): void
    {
        $exception = new CryptoException();

        $this->assertEquals('', $exception->getMessage());
        $this->assertEquals(0, $exception->getCode());
        $this->assertNull($exception->getPrevious());
    }

    /**
     * 测试只传递消息参数
     */
    public function testMessageOnlyConstructor(): void
    {
        $message = 'Crypto error occurred';
        $exception = new CryptoException($message);

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
            throw new CryptoException($message);
        } catch (CryptoException $e) {
            $caught = true;
            $this->assertEquals($message, $e->getMessage());
        }

        $this->assertTrue($caught, 'CryptoException should be caught');
    }

    /**
     * 测试异常可以被Exception捕获
     */
    public function testExceptionCanBeCaughtByException(): void
    {
        $message = 'Test exception catching by Exception';
        $caught = false;

        try {
            throw new CryptoException($message);
        } catch (\Throwable $e) {
            $caught = true;
            $this->assertEquals($message, $e->getMessage());
        }

        $this->assertTrue($caught, 'CryptoException should be caught by Exception');
    }

    /**
     * 测试异常堆栈跟踪
     */
    public function testExceptionStackTrace(): void
    {
        $exception = new CryptoException('Stack trace test');

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
        $exception = new CryptoException($message);

        $stringRepresentation = (string) $exception;
        $this->assertStringContainsString($message, $stringRepresentation);
        $this->assertStringContainsString('CryptoException', $stringRepresentation);
    }

    /**
     * 测试异常文件和行号
     */
    public function testExceptionFileAndLine(): void
    {
        $exception = new CryptoException('File and line test');

        $this->assertEquals(__FILE__, $exception->getFile());
        $this->assertGreaterThan(0, $exception->getLine());
    }

    /**
     * 测试异常链
     */
    public function testExceptionChain(): void
    {
        $rootException = new \RuntimeException('Root cause');
        $cryptoException = new CryptoException('Crypto error', 0, $rootException);

        $this->assertSame($rootException, $cryptoException->getPrevious());

        // 测试异常链遍历
        $current = $cryptoException;
        $chainLength = 0;
        while ($current !== null) {
            $chainLength++;
            $current = $current->getPrevious();
        }

        $this->assertEquals(2, $chainLength);
    }
} 