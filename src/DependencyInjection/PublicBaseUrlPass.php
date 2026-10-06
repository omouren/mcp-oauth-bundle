<?php

declare(strict_types=1);

namespace Omouren\McpOauthBundle\DependencyInjection;

use Omouren\McpOauthBundle\McpOauthSettings;
use Symfony\Component\DependencyInjection\Compiler\CompilerPassInterface;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Exception\LogicException;

/**
 * Without public_base_url the issuer and resource URIs are built from the Host header,
 * and the metadata is served with public caching. That is only safe when Symfony
 * rejects unknown hosts (framework.trusted_hosts).
 */
final class PublicBaseUrlPass implements CompilerPassInterface
{
    public function process(ContainerBuilder $container): void
    {
        if (!$container->hasDefinition(McpOauthSettings::class)) {
            return;
        }

        $publicBaseUrl = $container->getDefinition(McpOauthSettings::class)->getArgument('$publicBaseUrl');
        if (null !== $publicBaseUrl && '' !== $publicBaseUrl) {
            return;
        }

        // An env placeholder (e.g. %env(TRUSTED_HOSTS)%) is a non-empty string at compile time.
        $trustedHosts = $container->hasParameter('kernel.trusted_hosts') ? $container->getParameter('kernel.trusted_hosts') : [];
        if ([] !== $trustedHosts && '' !== $trustedHosts) {
            return;
        }

        throw new LogicException('The MCP OAuth issuer would be built from the untrusted Host header. Set "mcp_oauth.public_base_url" to the public origin (e.g. "https://admin.example.com") or configure "framework.trusted_hosts".');
    }
}
