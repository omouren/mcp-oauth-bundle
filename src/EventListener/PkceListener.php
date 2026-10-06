<?php

declare(strict_types=1);

namespace Omouren\McpOauthBundle\EventListener;

use League\Bundle\OAuth2ServerBundle\Event\AuthorizationRequestResolveEvent;
use League\Bundle\OAuth2ServerBundle\OAuth2Events;
use League\OAuth2\Server\Exception\OAuthServerException;
use Omouren\McpOauthBundle\OAuth\McpRequestGuard;
use Symfony\Component\EventDispatcher\Attribute\AsEventListener;
use Symfony\Component\HttpFoundation\RequestStack;

/**
 * League only requires PKCE for public clients and falls back to `plain` when
 * code_challenge_method is missing. MCP requires S256 for every client.
 *
 * @see https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization
 */
#[AsEventListener(event: OAuth2Events::AUTHORIZATION_REQUEST_RESOLVE, priority: 32)]
final readonly class PkceListener
{
    public function __construct(
        private RequestStack $requestStack,
        private McpRequestGuard $mcpRequestGuard,
    ) {
    }

    public function __invoke(AuthorizationRequestResolveEvent $event): void
    {
        $request = $this->requestStack->getCurrentRequest();
        if (null === $request || !$this->mcpRequestGuard->isAuthorizePath($request)) {
            return;
        }

        if (!$this->mcpRequestGuard->targetsMcp($request, $event->getScopes())) {
            return;
        }

        if (null === $event->getCodeChallenge()) {
            throw OAuthServerException::invalidRequest('code_challenge', 'Code challenge must be provided for MCP clients.');
        }

        if ('S256' !== $event->getCodeChallengeMethod()) {
            throw OAuthServerException::invalidRequest('code_challenge_method', 'Code challenge method must be S256.');
        }
    }
}
