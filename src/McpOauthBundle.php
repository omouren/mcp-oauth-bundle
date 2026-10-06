<?php

declare(strict_types=1);

namespace Omouren\McpOauthBundle;

use Omouren\McpOauthBundle\Controller\DynamicClientRegistrationController;
use Omouren\McpOauthBundle\DependencyInjection\LeagueCompatibilityPass;
use Omouren\McpOauthBundle\DependencyInjection\McpHttpPathPass;
use Symfony\Component\Config\Definition\Configurator\DefinitionConfigurator;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Loader\Configurator\ContainerConfigurator;
use Symfony\Component\HttpKernel\Bundle\AbstractBundle;
use Symfony\Component\RateLimiter\RateLimiterFactoryInterface;

use function Symfony\Component\DependencyInjection\Loader\Configurator\service;

final class McpOauthBundle extends AbstractBundle
{
    public function configure(DefinitionConfigurator $definition): void
    {
        $definition->import('../config/definition.php');
    }

    /**
     * @param array<string, mixed> $config
     */
    public function loadExtension(array $config, ContainerConfigurator $container, ContainerBuilder $builder): void
    {
        $prefix = rtrim((string) $config['authorization_prefix'], '/');
        $builder->setParameter('mcp_oauth.authorization_prefix', $prefix);

        // $resourcePaths comes from mcp.servers.*.http.path, resolved by McpHttpPathPass.
        $builder->register(McpOauthSettings::class)
            ->setArguments([
                '$resourcePaths' => [],
                '$authorizationPrefix' => $prefix,
                '$scopes' => $config['scopes'],
                '$loginRoute' => $config['login_route'],
                '$redirectQueryParam' => $config['redirect_query_param'],
                '$consent' => $config['consent'],
                '$cimdEnabled' => $config['cimd']['enabled'],
                '$trustedDomains' => $config['cimd']['trusted_domains'],
                '$dcrEnabled' => $config['dcr']['enabled'],
                '$resourceIndicators' => $config['resource_indicators'],
                '$issuerIdentification' => $config['issuer_identification'],
                '$publicBaseUrl' => $config['public_base_url'],
                '$dcrRedirectUriSchemes' => $config['dcr']['redirect_uri_schemes'],
            ]);

        $container->import('../config/services.yaml');

        $rateLimiter = $config['dcr']['rate_limiter'];
        if (null !== $rateLimiter && !interface_exists(RateLimiterFactoryInterface::class)) {
            throw new \LogicException('The "mcp_oauth.dcr.rate_limiter" option requires symfony/rate-limiter. Run "composer require symfony/rate-limiter".');
        }

        // Set explicitly so autowiring never picks an unrelated limiter by argument name.
        $container->services()
            ->get(DynamicClientRegistrationController::class)
            ->arg('$rateLimiter', null === $rateLimiter ? null : service('limiter.'.$rateLimiter));
    }

    public function build(ContainerBuilder $container): void
    {
        $container->addCompilerPass(new McpHttpPathPass());
        $container->addCompilerPass(new LeagueCompatibilityPass());
    }
}
