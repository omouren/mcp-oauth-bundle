<?php

declare(strict_types=1);

namespace Omouren\McpOauthBundle\Tests\Functional;

use Omouren\McpOauthBundle\Cimd\ClientIdMetadataResolver;
use Omouren\McpOauthBundle\Tests\Fixtures\TestKernel;
use Symfony\Bundle\FrameworkBundle\Test\KernelTestCase;
use Symfony\Component\HttpClient\NoPrivateNetworkHttpClient;

final class CimdHttpClientWiringTest extends KernelTestCase
{
    protected static function getKernelClass(): string
    {
        return TestKernel::class;
    }

    public function testResolverUsesNoPrivateNetworkHttpClient(): void
    {
        $resolver = self::getContainer()->get(ClientIdMetadataResolver::class);
        self::assertInstanceOf(ClientIdMetadataResolver::class, $resolver);

        $httpClient = (new \ReflectionProperty(ClientIdMetadataResolver::class, 'httpClient'))->getValue($resolver);

        self::assertInstanceOf(NoPrivateNetworkHttpClient::class, $httpClient);
    }
}
