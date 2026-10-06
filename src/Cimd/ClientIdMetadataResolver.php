<?php

declare(strict_types=1);

namespace Omouren\McpOauthBundle\Cimd;

use Omouren\McpOauthBundle\McpOauthSettings;
use Psr\Cache\CacheItemPoolInterface;
use Symfony\Contracts\HttpClient\Exception\ExceptionInterface;
use Symfony\Contracts\HttpClient\HttpClientInterface;

/**
 * Fetches and validates a Client ID Metadata Document.
 *
 * @see https://datatracker.ietf.org/doc/html/draft-ietf-oauth-client-id-metadata-document-00
 * @see https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization/client-registration
 */
final readonly class ClientIdMetadataResolver
{
    /**
     * Recommended maximum by the CIMD draft, section 6.6.
     */
    public const MAX_DOCUMENT_BYTES = 5120;

    private const LOOPBACK_HOSTS = ['localhost', '127.0.0.1', '[::1]'];

    public function __construct(
        private HttpClientInterface $httpClient,
        private CacheItemPoolInterface $cache,
        private McpOauthSettings $settings,
    ) {
    }

    public function resolve(string $clientIdUrl): ClientIdMetadataDocument
    {
        $this->assertSafeUrl($clientIdUrl);
        $this->assertTrustedHost($clientIdUrl);

        $cacheKey = 'mcp_oauth_cimd_'.hash('sha256', $clientIdUrl);
        $item = $this->cache->getItem($cacheKey);
        if ($item->isHit() && $item->get() instanceof ClientIdMetadataDocument) {
            return $item->get();
        }

        $document = $this->parse($clientIdUrl, $this->fetch($clientIdUrl));
        $item->set($document);
        $item->expiresAfter(300);
        $this->cache->save($item);

        return $document;
    }

    /**
     * @return array<string, mixed>
     */
    private function fetch(string $url): array
    {
        try {
            $response = $this->httpClient->request('GET', $url, [
                'timeout' => 5,
                'max_duration' => 10,
                'max_redirects' => 0,
                'buffer' => false,
                'headers' => ['Accept' => 'application/json'],
            ]);

            // With max_redirects at 0, a 3xx is returned as is and fails here, so no hop is ever followed.
            if (200 !== $response->getStatusCode()) {
                throw new CimdException('Client metadata document HTTP status is not 200.');
            }

            $contentLength = $response->getHeaders(false)['content-length'][0] ?? null;
            if (null !== $contentLength && (int) $contentLength > self::MAX_DOCUMENT_BYTES) {
                $response->cancel();

                throw new CimdException('Client metadata document is too large.');
            }

            $body = '';
            foreach ($this->httpClient->stream($response) as $chunk) {
                $body .= $chunk->getContent();
                if (\strlen($body) > self::MAX_DOCUMENT_BYTES) {
                    $response->cancel();

                    throw new CimdException('Client metadata document is too large.');
                }
            }
        } catch (ExceptionInterface $e) {
            throw new CimdException('Unable to fetch client metadata document.', 0, $e);
        }

        try {
            $data = json_decode($body, true, 32, \JSON_THROW_ON_ERROR);
        } catch (\JsonException $e) {
            throw new CimdException('Client metadata document is not valid JSON.', 0, $e);
        }

        if (!\is_array($data)) {
            throw new CimdException('Client metadata document must be a JSON object.');
        }

        return $data;
    }

    /**
     * @param array<string, mixed> $payload
     */
    private function parse(string $expectedClientId, array $payload): ClientIdMetadataDocument
    {
        $clientId = $payload['client_id'] ?? null;
        $clientName = $payload['client_name'] ?? null;
        $redirectUris = $payload['redirect_uris'] ?? null;

        if (!\is_string($clientId) || '' === $clientId) {
            throw new CimdException('Metadata is missing client_id.');
        }
        if ($clientId !== $expectedClientId) {
            throw new CimdException('Metadata client_id does not match the document URL.');
        }
        if (!\is_string($clientName) || '' === $clientName) {
            throw new CimdException('Metadata is missing client_name.');
        }
        if (!\is_array($redirectUris) || [] === $redirectUris) {
            throw new CimdException('Metadata is missing redirect_uris.');
        }

        $uris = [];
        foreach ($redirectUris as $uri) {
            if (!\is_string($uri) || '' === $uri) {
                throw new CimdException('Metadata redirect_uris must be strings.');
            }
            if (!$this->isAllowedRedirectUri($uri)) {
                throw new CimdException(\sprintf('Metadata redirect URI "%s" is not allowed.', $uri));
            }
            $uris[] = $uri;
        }

        return new ClientIdMetadataDocument($clientId, $clientName, $uris);
    }

    private function assertTrustedHost(string $url): void
    {
        $host = parse_url($url, \PHP_URL_HOST);
        if (!\is_string($host) || !$this->hostIsTrusted($host)) {
            throw new CimdException('CIMD host is not in the trusted domain allowlist.');
        }
    }

    private function hostIsTrusted(string $host): bool
    {
        $host = strtolower($host);
        foreach ($this->settings->trustedDomains as $domain) {
            $domain = strtolower($domain);
            if ($host === $domain || str_ends_with($host, '.'.$domain)) {
                return true;
            }
        }

        return false;
    }

    private function assertSafeUrl(string $url): void
    {
        $parts = parse_url($url);
        if (false === $parts || !isset($parts['scheme'], $parts['host'])) {
            throw new CimdException('client_id is not a valid URL.');
        }

        if ('https' !== strtolower($parts['scheme'])) {
            throw new CimdException('CIMD client_id must use the https scheme.');
        }

        if (!isset($parts['path']) || '' === $parts['path'] || '/' === $parts['path']) {
            throw new CimdException('CIMD client_id must include a path component.');
        }

        $host = strtolower($parts['host']);
        if ($this->isBlockedHost($host)) {
            throw new CimdException('CIMD fetch to this host is not allowed.');
        }
    }

    /**
     * Only https, or http on a loopback host (RFC 8252 native apps), absolute and without fragment.
     */
    private function isAllowedRedirectUri(string $uri): bool
    {
        $parts = parse_url($uri);
        if (false === $parts || !isset($parts['scheme'], $parts['host']) || str_contains($uri, '#')) {
            return false;
        }

        $scheme = strtolower($parts['scheme']);
        if ('https' === $scheme) {
            return true;
        }

        return 'http' === $scheme && \in_array(strtolower($parts['host']), self::LOOPBACK_HOSTS, true);
    }

    private function isBlockedHost(string $host): bool
    {
        if ('localhost' === $host || str_ends_with($host, '.localhost') || str_ends_with($host, '.local')) {
            return true;
        }

        if (false !== filter_var($host, \FILTER_VALIDATE_IP)) {
            return $this->isPrivateIp($host);
        }

        return false;
    }

    private function isPrivateIp(string $ip): bool
    {
        return false === filter_var($ip, \FILTER_VALIDATE_IP, \FILTER_FLAG_NO_PRIV_RANGE | \FILTER_FLAG_NO_RES_RANGE);
    }
}
