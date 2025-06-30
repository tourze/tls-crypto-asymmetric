<?php

declare(strict_types=1);

namespace Tourze\TLSCryptoAsymmetric\Tests\Unit\Exception;

use PHPUnit\Framework\TestCase;
use Tourze\TLSCryptoAsymmetric\Exception\CryptoException;
use Tourze\TLSCryptoAsymmetric\Exception\InvalidKeyPairException;

class InvalidKeyPairExceptionTest extends TestCase
{
    public function testExceptionIsInstanceOfCryptoException(): void
    {
        $exception = new InvalidKeyPairException('Test message');
        
        $this->assertInstanceOf(CryptoException::class, $exception);
    }

    public function testExceptionCanBeCreatedWithMessage(): void
    {
        $message = 'Invalid key pair provided';
        $exception = new InvalidKeyPairException($message);
        
        $this->assertSame($message, $exception->getMessage());
    }

    public function testExceptionCanBeCreatedWithMessageAndCode(): void
    {
        $message = 'Invalid key pair';
        $code = 500;
        $exception = new InvalidKeyPairException($message, $code);
        
        $this->assertSame($message, $exception->getMessage());
        $this->assertSame($code, $exception->getCode());
    }

    public function testExceptionCanBeCreatedWithPreviousException(): void
    {
        $previous = new \Exception('Previous exception');
        $exception = new InvalidKeyPairException('Current exception', 0, $previous);
        
        $this->assertSame($previous, $exception->getPrevious());
    }
}