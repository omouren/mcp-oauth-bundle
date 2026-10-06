<?php

declare(strict_types=1);

namespace Omouren\McpOauthBundle\Controller;

use Omouren\McpOauthBundle\McpOauthSettings;
use Omouren\McpOauthBundle\OAuth\IssuerResolver;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;

final readonly class AuthorizationServerMetadataController
{
    /**
     * League reads client credentials from the Basic header or the request body,
     * so the token endpoint accepts both secret methods for any confidential client.
     */
    public const TOKEN_ENDPOINT_AUTH_METHODS = [
        'client_secret_basic',
        'client_secret_post',
        'none',
    ];

    public function __construct(
        private McpOauthSettings $settings,
        private IssuerResolver $issuerResolver,
    ) {
    }

    public function __invoke(Request $request): JsonResponse
    {
        $issuer = $this->issuerResolver->issuer($request);
        $payload = [
            'issuer' => $issuer,
            'authorization_endpoint' => $this->issuerResolver->authorizeUrl($request),
            'token_endpoint' => $this->issuerResolver->tokenUrl($request),
            'response_types_supported' => ['code'],
            'grant_types_supported' => ['authorization_code', 'refresh_token'],
            'code_challenge_methods_supported' => ['S256'],
            'token_endpoint_auth_methods_supported' => self::TOKEN_ENDPOINT_AUTH_METHODS,
            'scopes_supported' => $this->settings->scopes,
        ];

        if ($this->settings->issuerIdentification) {
            $payload['authorization_response_iss_parameter_supported'] = true;
        }
        if ($this->settings->cimdEnabled) {
            $payload['client_id_metadata_document_supported'] = true;
        }
        if ($this->settings->dcrEnabled) {
            $payload['registration_endpoint'] = $this->issuerResolver->registrationUrl($request);
        }

        $response = new JsonResponse($payload);
        $response->headers->set('Access-Control-Allow-Origin', '*');
        $response->headers->set('Cache-Control', 'public, max-age=3600');

        return $response;
    }
}
