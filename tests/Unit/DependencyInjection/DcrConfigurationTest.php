<?php

declare(strict_types=1);

namespace Omouren\McpOauthBundle\Tests\Unit\DependencyInjection;

use Omouren\McpOauthBundle\McpOauthBundle;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Config\Definition\ConfigurationInterface;
use Symfony\Component\Config\Definition\Exception\InvalidConfigurationException;
use Symfony\Component\Config\Definition\Processor;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Extension\ConfigurationExtensionInterface;

final class DcrConfigurationTest extends TestCase
{
    public function testDefaults(): void
    {
        $config = $this->process([]);

        self::assertSame([], $config['dcr']['redirect_uri_schemes']);
        self::assertNull($config['dcr']['rate_limiter']);
    }

    public function testAcceptsCustomScheme(): void
    {
        $config = $this->process(['redirect_uri_schemes' => ['com.example.app', 'cursor']]);

        self::assertSame(['com.example.app', 'cursor'], $config['dcr']['redirect_uri_schemes']);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function forbiddenSchemes(): iterable
    {
        yield 'javascript' => ['javascript'];
        yield 'data' => ['data'];
        yield 'file' => ['file'];
        yield 'http' => ['http'];
        yield 'uppercase' => ['Cursor'];
        yield 'with colon' => ['cursor:'];
    }

    #[DataProvider('forbiddenSchemes')]
    public function testRejectsForbiddenScheme(string $scheme): void
    {
        $this->expectException(InvalidConfigurationException::class);
        $this->process(['redirect_uri_schemes' => [$scheme]]);
    }

    /**
     * @param array<string, mixed> $dcr
     *
     * @return array<string, mixed>
     */
    private function process(array $dcr): array
    {
        $extension = (new McpOauthBundle())->getContainerExtension();
        self::assertInstanceOf(ConfigurationExtensionInterface::class, $extension);
        $configuration = $extension->getConfiguration([], new ContainerBuilder());
        self::assertInstanceOf(ConfigurationInterface::class, $configuration);

        return (new Processor())->processConfiguration($configuration, [['login_route' => 'app_login', 'dcr' => $dcr]]);
    }
}
