<?php

declare(strict_types=1);

namespace Omouren\McpOauthBundle\Controller;

use League\Bundle\OAuth2ServerBundle\OAuth2Grants;
use Omouren\McpOauthBundle\McpOauthSettings;
use Omouren\McpOauthBundle\OAuth\LeagueClientSynchronizer;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;

final readonly class DynamicClientRegistrationController
{
    private const ALLOWED_GRANT_TYPES = [
        OAuth2Grants::AUTHORIZATION_CODE,
        OAuth2Grants::REFRESH_TOKEN,
    ];

    public function __construct(
        private McpOauthSettings $settings,
        private LeagueClientSynchronizer $clientSynchronizer,
    ) {
    }

    public function __invoke(Request $request): JsonResponse
    {
        if (!$this->settings->dcrEnabled) {
            return new JsonResponse(['error' => 'invalid_request'], Response::HTTP_NOT_FOUND);
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

        $redirectUris = $payload['redirect_uris'] ?? null;
        if (!\is_array($redirectUris) || [] === $redirectUris) {
            return $this->error('invalid_redirect_uri', 'At least one redirect URI is required.');
        }

        foreach ($redirectUris as $redirectUri) {
            if (!\is_string($redirectUri) || !$this->isAllowedRedirectUri($redirectUri)) {
                return $this->error('invalid_redirect_uri', \sprintf('Redirect URI "%s" is not allowed.', (string) $redirectUri));
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
        if (!\is_string($tokenEndpointAuthMethod) || !\in_array($tokenEndpointAuthMethod, AuthorizationServerMetadataController::TOKEN_ENDPOINT_AUTH_METHODS, true)) {
            return $this->error(
                'invalid_client_metadata',
                \sprintf('Supported token_endpoint_auth_method values are: %s.', implode(', ', AuthorizationServerMetadataController::TOKEN_ENDPOINT_AUTH_METHODS)),
            );
        }

        $scopes = $this->normalizeScopes($payload['scope'] ?? null);

        try {
            $credentials = $this->clientSynchronizer->persistFromDcr(
                $name,
                $redirectUris,
                $tokenEndpointAuthMethod,
                $grantTypes,
                $scopes,
            );
        } catch (\Throwable) {
            return new JsonResponse(['error' => 'invalid_redirect_uri'], Response::HTTP_BAD_REQUEST);
        }

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

    private function isAllowedRedirectUri(string $redirectUri): bool
    {
        $parts = parse_url($redirectUri);
        if (false === $parts || !isset($parts['scheme'])) {
            return false;
        }

        $scheme = strtolower($parts['scheme']);
        if (!\in_array($scheme, ['http', 'https'], true)) {
            return true;
        }

        $host = strtolower($parts['host'] ?? '');

        return 'https' === $scheme
            || \in_array($host, ['localhost', '127.0.0.1', '[::1]', '::1'], true);
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

    private function error(string $error, string $description): JsonResponse
    {
        return new JsonResponse([
            'error' => $error,
            'error_description' => $description,
        ], Response::HTTP_BAD_REQUEST);
    }
}
