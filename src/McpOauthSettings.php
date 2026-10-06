<?php

declare(strict_types=1);

namespace Omouren\McpOauthBundle;

final readonly class McpOauthSettings
{
    /**
     * @param list<string> $resourcePaths MCP HTTP paths from mcp.servers.*.http.path
     * @param list<string> $scopes
     * @param list<string> $trustedDomains
     * @param list<string> $dcrRedirectUriSchemes
     */
    public function __construct(
        public array $resourcePaths,
        public string $authorizationPrefix,
        public array $scopes,
        public string $loginRoute,
        public string $redirectQueryParam,
        public string $consent,
        public bool $cimdEnabled,
        public array $trustedDomains,
        public bool $dcrEnabled,
        public bool $resourceIndicators,
        public bool $issuerIdentification,
        public ?string $publicBaseUrl,
        public array $dcrRedirectUriSchemes = [],
    ) {
    }
}
