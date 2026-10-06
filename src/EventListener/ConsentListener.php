<?php

declare(strict_types=1);

namespace Omouren\McpOauthBundle\EventListener;

use League\Bundle\OAuth2ServerBundle\Event\AuthorizationRequestResolveEvent;
use League\Bundle\OAuth2ServerBundle\OAuth2Events;
use Omouren\McpOauthBundle\McpOauthSettings;
use Omouren\McpOauthBundle\OAuth\McpRequestGuard;
use Symfony\Component\EventDispatcher\Attribute\AsEventListener;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\RequestStack;
use Symfony\Component\HttpFoundation\Session\SessionInterface;
use Symfony\Component\Routing\Generator\UrlGeneratorInterface;

/**
 * Consent is bound to the exact authorize request it was shown for: the consent page only
 * displays server-side data and approval only matches the same query, so a crafted consent
 * URL can't relabel or pre-approve another client.
 */
#[AsEventListener(event: OAuth2Events::AUTHORIZATION_REQUEST_RESOLVE)]
final readonly class ConsentListener
{
    public const PENDING_SESSION_KEY = 'mcp_oauth.pending_consents';
    public const APPROVED_SESSION_KEY = 'mcp_oauth.consent_approved';

    private const MAX_PENDING = 5;

    public function __construct(
        private McpOauthSettings $settings,
        private RequestStack $requestStack,
        private UrlGeneratorInterface $urlGenerator,
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

        if ('auto' === $this->settings->consent) {
            $event->resolveAuthorization(AuthorizationRequestResolveEvent::AUTHORIZATION_APPROVED);

            return;
        }

        if (!$request->hasSession()) {
            return;
        }

        $session = $request->getSession();
        $query = self::normalize($request->query->all());

        $approved = $session->remove(self::APPROVED_SESSION_KEY);
        if ($approved === $query) {
            $event->resolveAuthorization(AuthorizationRequestResolveEvent::AUTHORIZATION_APPROVED);

            return;
        }

        // League leaves the redirect URI null when the request omits it and the client has a single one.
        $redirectUri = $event->getRedirectUri() ?? (string) ($event->getClient()->getRedirectUris()[0] ?? '');
        $consentId = $this->addPendingConsent($session, [
            'query' => $query,
            'client_name' => $event->getClient()->getName(),
            'redirect_host' => (string) parse_url($redirectUri, \PHP_URL_HOST),
        ]);

        $event->setResponse(new RedirectResponse($this->urlGenerator->generate('mcp_oauth_consent', ['consent_id' => $consentId])));
    }

    /**
     * @param array{query: array<mixed>, client_name: string, redirect_host: string} $consent
     */
    private function addPendingConsent(SessionInterface $session, array $consent): string
    {
        $pending = $session->get(self::PENDING_SESSION_KEY, []);
        if (!\is_array($pending)) {
            $pending = [];
        }

        $consentId = bin2hex(random_bytes(16));
        $pending[$consentId] = $consent;
        $session->set(self::PENDING_SESSION_KEY, \array_slice($pending, -self::MAX_PENDING, null, true));

        return $consentId;
    }

    /**
     * @param array<mixed> $values
     *
     * @return array<mixed>
     */
    private static function normalize(array $values): array
    {
        ksort($values);

        return array_map(static fn (mixed $value): mixed => \is_array($value) ? self::normalize($value) : $value, $values);
    }
}
