<?php

declare(strict_types=1);

namespace Omouren\McpOauthBundle\Tests\Unit\DependencyInjection;

use Omouren\McpOauthBundle\DependencyInjection\PublicBaseUrlPass;
use Omouren\McpOauthBundle\McpOauthSettings;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Exception\LogicException;

final class PublicBaseUrlPassTest extends TestCase
{
    public function testFailsWithoutPublicBaseUrlNorTrustedHosts(): void
    {
        $this->expectException(LogicException::class);
        $this->expectExceptionMessage('Set "mcp_oauth.public_base_url"');

        (new PublicBaseUrlPass())->process($this->container(null, []));
    }

    public function testFailsWithEmptyPublicBaseUrl(): void
    {
        $this->expectException(LogicException::class);

        (new PublicBaseUrlPass())->process($this->container('', []));
    }

    /**
     * @return iterable<string, array{string|null, mixed}>
     */
    public static function safeConfigurations(): iterable
    {
        yield 'public base url' => ['https://admin.example.com', []];
        yield 'public base url from env' => ['%env(MCP_PUBLIC_BASE_URL)%', []];
        yield 'trusted hosts' => [null, ['^admin\.example\.com$']];
        yield 'trusted hosts from env' => [null, '%env(TRUSTED_HOSTS)%'];
    }

    #[DataProvider('safeConfigurations')]
    public function testAcceptsSafeConfiguration(?string $publicBaseUrl, mixed $trustedHosts): void
    {
        $this->expectNotToPerformAssertions();

        (new PublicBaseUrlPass())->process($this->container($publicBaseUrl, $trustedHosts));
    }

    public function testSkipsWhenBundleIsNotLoaded(): void
    {
        $this->expectNotToPerformAssertions();

        (new PublicBaseUrlPass())->process(new ContainerBuilder());
    }

    private function container(?string $publicBaseUrl, mixed $trustedHosts): ContainerBuilder
    {
        $container = new ContainerBuilder();
        $container->setParameter('kernel.trusted_hosts', $trustedHosts);
        $container->register(McpOauthSettings::class)->setArgument('$publicBaseUrl', $publicBaseUrl);

        return $container;
    }
}
