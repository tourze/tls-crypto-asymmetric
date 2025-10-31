<?php

declare(strict_types=1);

namespace Tourze\TLSCryptoAsymmetric\Tests\Exception;

use PHPUnit\Framework\Attributes\CoversClass;
use Tourze\PHPUnitBase\AbstractExceptionTestCase;
use Tourze\TLSCryptoAsymmetric\Exception\CryptoException;
use Tourze\TLSCryptoAsymmetric\Exception\InvalidKeyPairException;

/**
 * InvalidKeyPairException测试
 *
 * @internal
 */
#[CoversClass(InvalidKeyPairException::class)]
final class InvalidKeyPairExceptionTest extends AbstractExceptionTestCase
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
