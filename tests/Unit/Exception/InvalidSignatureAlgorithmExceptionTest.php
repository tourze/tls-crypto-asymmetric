<?php

declare(strict_types=1);

namespace Tourze\TLSCryptoAsymmetric\Tests\Unit\Exception;

use PHPUnit\Framework\TestCase;
use Tourze\TLSCryptoAsymmetric\Exception\CryptoException;
use Tourze\TLSCryptoAsymmetric\Exception\InvalidSignatureAlgorithmException;

class InvalidSignatureAlgorithmExceptionTest extends TestCase
{
    public function testExceptionIsInstanceOfCryptoException(): void
    {
        $exception = new InvalidSignatureAlgorithmException('Test message');
        
        $this->assertInstanceOf(CryptoException::class, $exception);
    }

    public function testExceptionCanBeCreatedWithMessage(): void
    {
        $message = 'Invalid signature algorithm specified';
        $exception = new InvalidSignatureAlgorithmException($message);
        
        $this->assertSame($message, $exception->getMessage());
    }

    public function testExceptionCanBeCreatedWithMessageAndCode(): void
    {
        $message = 'Unsupported algorithm';
        $code = 400;
        $exception = new InvalidSignatureAlgorithmException($message, $code);
        
        $this->assertSame($message, $exception->getMessage());
        $this->assertSame($code, $exception->getCode());
    }

    public function testExceptionCanBeCreatedWithPreviousException(): void
    {
        $previous = new \Exception('Previous exception');
        $exception = new InvalidSignatureAlgorithmException('Current exception', 0, $previous);
        
        $this->assertSame($previous, $exception->getPrevious());
    }
}