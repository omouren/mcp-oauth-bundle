<?php

declare(strict_types=1);

namespace Omouren\McpOauthBundle\Controller;

use League\Bundle\OAuth2ServerBundle\OAuth2Grants;
use League\Bundle\OAuth2ServerBundle\ValueObject\RedirectUri;
use Omouren\McpOauthBundle\McpOauthSettings;
use Omouren\McpOauthBundle\OAuth\LeagueClientSynchronizer;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\RateLimiter\RateLimiterFactoryInterface;

final readonly class DynamicClientRegistrationController
{
    private const LOOPBACK_HOSTS = ['localhost', '127.0.0.1', '[::1]'];

    private const MAX_BODY_BYTES = 16384;
    private const MAX_CLIENT_NAME_LENGTH = 200;
    private const MAX_REDIRECT_URIS = 10;
    private const MAX_REDIRECT_URI_LENGTH = 2000;
    private const MAX_SCOPE_LENGTH = 1000;
    private const MAX_SCOPES = 50;

    private const ALLOWED_GRANT_TYPES = [
        OAuth2Grants::AUTHORIZATION_CODE,
        OAuth2Grants::REFRESH_TOKEN,
    ];

    private const ALLOWED_TOKEN_ENDPOINT_AUTH_METHODS = [
        'none',
        'client_secret_post',
    ];

    public function __construct(
        private McpOauthSettings $settings,
        private LeagueClientSynchronizer $clientSynchronizer,
        private ?RateLimiterFactoryInterface $rateLimiter = null,
    ) {
    }

    public function __invoke(Request $request): JsonResponse
    {
        if (!$this->settings->dcrEnabled) {
            return new JsonResponse(['error' => 'invalid_request'], Response::HTTP_NOT_FOUND);
        }

        if (null !== $this->rateLimiter) {
            $limit = $this->rateLimiter->create($request->getClientIp() ?? 'unknown')->consume();
            if (!$limit->isAccepted()) {
                $response = $this->error('invalid_request', 'Too many client registrations. Try again later.', Response::HTTP_TOO_MANY_REQUESTS);
                $response->headers->set('Retry-After', (string) max(0, $limit->getRetryAfter()->getTimestamp() - time()));

                return $response;
            }
        }

        if (\strlen($request->getContent()) > self::MAX_BODY_BYTES) {
            return $this->error('invalid_client_metadata', \sprintf('Request body must not exceed %d bytes.', self::MAX_BODY_BYTES));
        }

        trigger_deprecation(
            'omouren/mcp-oauth-bundle',
            '0.1',
            'RFC 7591 Dynamic Client Registration is deprecated. Prefer Client ID Metadata Documents (CIMD).',
        );

        try {
            $payload = json_decode($request->getContent(), true, 512, \JSON_THROW_ON_ERROR);
        } catch (\JsonException) {
            return $this->error('invalid_client_metadata', 'Request body must be valid JSON.');
        }

        if (!\is_array($payload)) {
            return $this->error('invalid_client_metadata', 'Request body must be a JSON object.');
        }

        $name = $payload['client_name'] ?? 'MCP client';
        if (!\is_string($name) || '' === $name) {
            $name = 'MCP client';
        }
        if (mb_strlen($name) > self::MAX_CLIENT_NAME_LENGTH || 1 === preg_match('/\p{Cc}/u', $name)) {
            return $this->error(
                'invalid_client_metadata',
                \sprintf('client_name must be at most %d characters long and must not contain control characters.', self::MAX_CLIENT_NAME_LENGTH),
            );
        }

        $redirectUris = $payload['redirect_uris'] ?? null;
        if (!\is_array($redirectUris) || [] === $redirectUris || !array_is_list($redirectUris)) {
            return $this->error('invalid_redirect_uri', 'At least one redirect URI is required.');
        }
        if (\count($redirectUris) > self::MAX_REDIRECT_URIS) {
            return $this->error('invalid_redirect_uri', \sprintf('At most %d redirect URIs are allowed.', self::MAX_REDIRECT_URIS));
        }

        foreach ($redirectUris as $redirectUri) {
            if (!\is_string($redirectUri)) {
                return $this->error('invalid_redirect_uri', 'Redirect URIs must be strings.');
            }
            if (!$this->isAllowedRedirectUri($redirectUri)) {
                return $this->error('invalid_redirect_uri', \sprintf('Redirect URI "%s" is not allowed.', mb_substr($redirectUri, 0, 200)));
            }
        }

        $grantTypes = $this->normalizeGrantTypes($payload['grant_types'] ?? null);
        if ([] === $grantTypes) {
            return $this->error('invalid_client_metadata', 'At least one supported grant type is required.');
        }

        $responseTypes = $payload['response_types'] ?? ['code'];
        if (!\is_array($responseTypes) || !\in_array('code', $responseTypes, true)) {
            return $this->error('invalid_client_metadata', 'Only response type "code" is supported.');
        }

        $tokenEndpointAuthMethod = $payload['token_endpoint_auth_method'] ?? 'none';
        if (!\is_string($tokenEndpointAuthMethod) || !\in_array($tokenEndpointAuthMethod, self::ALLOWED_TOKEN_ENDPOINT_AUTH_METHODS, true)) {
            return $this->error(
                'invalid_client_metadata',
                'Supported token_endpoint_auth_method values are: none, client_secret_post.',
            );
        }

        $scope = $payload['scope'] ?? null;
        if ((\is_string($scope) && \strlen($scope) > self::MAX_SCOPE_LENGTH) || (\is_array($scope) && \count($scope) > self::MAX_SCOPES)) {
            return $this->error(
                'invalid_client_metadata',
                \sprintf('scope must be at most %d characters long and list at most %d scopes.', self::MAX_SCOPE_LENGTH, self::MAX_SCOPES),
            );
        }
        $scopes = $this->normalizeScopes($scope);

        $credentials = $this->clientSynchronizer->persistFromDcr(
            $name,
            $redirectUris,
            $tokenEndpointAuthMethod,
            $grantTypes,
            $scopes,
        );

        $response = [
            'client_id' => $credentials['client_id'],
            'client_id_issued_at' => time(),
            'client_secret_expires_at' => 0,
            'client_name' => $name,
            'redirect_uris' => $redirectUris,
            'grant_types' => $grantTypes,
            'response_types' => $responseTypes,
            'token_endpoint_auth_method' => $tokenEndpointAuthMethod,
            'scope' => implode(' ', $scopes),
        ];

        if (null !== $credentials['client_secret']) {
            $response['client_secret'] = $credentials['client_secret'];
        }

        return new JsonResponse($response, Response::HTTP_CREATED);
    }

    /**
     * @see https://datatracker.ietf.org/doc/html/rfc6749#section-3.1.2
     * @see https://datatracker.ietf.org/doc/html/rfc8252#section-7
     */
    private function isAllowedRedirectUri(string $redirectUri): bool
    {
        if ('' === $redirectUri || \strlen($redirectUri) > self::MAX_REDIRECT_URI_LENGTH || 1 === preg_match('/[\x00-\x20\x7f]/', $redirectUri)) {
            return false;
        }

        $parts = parse_url($redirectUri);
        if (false === $parts || !isset($parts['scheme']) || isset($parts['fragment']) || isset($parts['user']) || isset($parts['pass'])) {
            return false;
        }

        // League rejects anything its RedirectUri value object can't hold, so validate it here
        // instead of failing later at persistence time.
        try {
            new RedirectUri($redirectUri);
        } catch (\RuntimeException) {
            return false;
        }

        $scheme = strtolower($parts['scheme']);
        $host = strtolower($parts['host'] ?? '');

        return match ($scheme) {
            'https' => '' !== $host,
            'http' => \in_array($host, self::LOOPBACK_HOSTS, true),
            default => \in_array($scheme, $this->settings->dcrRedirectUriSchemes, true),
        };
    }

    /**
     * @return list<string>
     */
    private function normalizeGrantTypes(mixed $grantTypes): array
    {
        if (!\is_array($grantTypes)) {
            return self::ALLOWED_GRANT_TYPES;
        }

        return array_values(array_unique(array_filter(
            $grantTypes,
            static fn (mixed $grantType): bool => \is_string($grantType) && \in_array($grantType, self::ALLOWED_GRANT_TYPES, true),
        )));
    }

    /**
     * @return list<string>
     */
    private function normalizeScopes(mixed $scope): array
    {
        if (\is_string($scope) && '' !== trim($scope)) {
            $scopes = preg_split('/\s+/', trim($scope)) ?: [];
        } elseif (\is_array($scope)) {
            $scopes = array_filter($scope, \is_string(...));
        } else {
            return $this->settings->scopes;
        }

        $validated = array_values(array_unique(array_filter(
            $scopes,
            fn (string $requestedScope): bool => \in_array($requestedScope, $this->settings->scopes, true),
        )));

        return [] !== $validated ? $validated : $this->settings->scopes;
    }

    private function error(string $error, string $description, int $status = Response::HTTP_BAD_REQUEST): JsonResponse
    {
        return new JsonResponse([
            'error' => $error,
            'error_description' => $description,
        ], $status);
    }
}
