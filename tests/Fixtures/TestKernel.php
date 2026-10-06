<?php

declare(strict_types=1);

namespace Omouren\McpOauthBundle\Tests\Fixtures;

use League\Bundle\OAuth2ServerBundle\Manager\ClientManagerInterface;
use Symfony\Bundle\FrameworkBundle\FrameworkBundle;
use Symfony\Bundle\FrameworkBundle\Kernel\MicroKernelTrait;
use Symfony\Bundle\SecurityBundle\SecurityBundle;
use Symfony\AI\McpBundle\McpBundle;
use Symfony\Bundle\TwigBundle\TwigBundle;
use Symfony\Component\DependencyInjection\Loader\Configurator\ContainerConfigurator;
use Omouren\McpOauthBundle\McpOauthBundle;
use Symfony\Component\HttpKernel\Kernel;
use Symfony\Component\Routing\Loader\Configurator\RoutingConfigurator;

final class TestKernel extends Kernel
{
    use MicroKernelTrait;

    public function registerBundles(): iterable
    {
        yield new FrameworkBundle();
        yield new SecurityBundle();
        yield new TwigBundle();
        yield new McpBundle();
        yield new McpOauthBundle();
    }

    public function getProjectDir(): string
    {
        return \dirname(__DIR__, 2);
    }

    protected function configureContainer(ContainerConfigurator $container): void
    {
        $container->extension('framework', [
            'secret' => 'test',
            'test' => true,
            'http_method_override' => false,
            'php_errors' => ['log' => true],
            'router' => ['utf8' => true],
            'http_client' => ['default_options' => ['timeout' => 1]],
            'session' => ['storage_factory_id' => 'session.storage.factory.mock_file'],
            'csrf_protection' => true,
            'handle_all_throwables' => true,
        ]);
        $container->extension('security', [
            'firewalls' => [
                'main' => [
                    'pattern' => '^/',
                    'security' => false,
                ],
            ],
        ]);
        $container->extension('twig', [
            'default_path' => '%kernel.project_dir%/templates',
        ]);
        $container->extension('mcp', [
            'servers' => [
                'default' => [
                    'transports' => ['http' => true],
                    'http' => ['path' => '/_mcp'],
                    'registry' => '*',
                ],
            ],
        ]);
        $mcpOauthConfig = [
            'login_route' => 'app_login',
            'public_base_url' => 'https://mcp.example.test',
        ];
        if ('dcr_hardened' === $this->environment) {
            $container->extension('framework', [
                'cache' => [
                    'pools' => ['cache.test_rate_limiter' => ['adapter' => 'cache.adapter.filesystem']],
                ],
                'rate_limiter' => [
                    'mcp_oauth_register' => [
                        'policy' => 'fixed_window',
                        'limit' => 2,
                        'interval' => '1 hour',
                        'cache_pool' => 'cache.test_rate_limiter',
                    ],
                ],
            ]);
            $mcpOauthConfig['dcr'] = [
                'redirect_uri_schemes' => ['com.example.app'],
                'rate_limiter' => 'mcp_oauth_register',
            ];
        }
        $container->extension('mcp_oauth', $mcpOauthConfig);
        $container->services()
            ->set(UnauthorizedProbeController::class)
                ->public()
            ->set(DummyLoginController::class)
                ->public()
            ->set(InMemoryClientManager::class)
            ->alias(ClientManagerInterface::class, InMemoryClientManager::class);
    }

    protected function configureRoutes(RoutingConfigurator $routes): void
    {
        $routes->import('@McpOauthBundle/config/routes.yaml');
        $routes->add('app_login', '/login')->controller(DummyLoginController::class);
        $routes->add('oauth2_authorize', '/oauth2/authorize')->controller(DummyLoginController::class);
        $routes->add('mcp_probe', '/_mcp')->controller(UnauthorizedProbeController::class)->methods(['GET']);
    }
}
