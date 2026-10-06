<?php

declare(strict_types=1);

namespace Omouren\McpOauthBundle\Tests\Unit\Cimd;

use Omouren\McpOauthBundle\Cimd\CimdException;
use Omouren\McpOauthBundle\Cimd\ClientIdMetadataResolver;
use Omouren\McpOauthBundle\McpOauthSettings;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Cache\Adapter\ArrayAdapter;
use Symfony\Component\HttpClient\MockHttpClient;
use Symfony\Component\HttpClient\NoPrivateNetworkHttpClient;
use Symfony\Component\HttpClient\Response\MockResponse;
use Symfony\Contracts\HttpClient\HttpClientInterface;

final class ClientIdMetadataResolverTest extends TestCase
{
    public function testFetchesAndParsesDocument(): void
    {
        $url = 'https://claude.ai/oauth/client-metadata.json';
        $resolver = $this->resolver(new MockHttpClient([$this->documentResponse($url, 'Claude')]));

        $document = $resolver->resolve($url);

        self::assertSame($url, $document->clientId);
        self::assertSame('Claude', $document->clientName);
        self::assertSame(['https://claude.ai/api/mcp/auth_callback'], $document->redirectUris);
    }

    public function testCachesDocument(): void
    {
        $url = 'https://claude.ai/oauth/client-metadata.json';
        $http = new MockHttpClient([
            $this->documentResponse($url, 'Claude'),
        ]);
        $resolver = $this->resolver($http);

        $resolver->resolve($url);
        $again = $resolver->resolve($url);

        self::assertSame('Claude', $again->clientName);
        self::assertSame(1, $http->getRequestsCount());
    }

    public function testAllowsSubdomainOfTrustedHost(): void
    {
        $url = 'https://www.claude.ai/oauth/client-metadata.json';
        $document = $this->resolver(new MockHttpClient([$this->documentResponse($url, 'Claude')]))->resolve($url);

        self::assertSame('Claude', $document->clientName);
    }

    public function testRejectsMismatchedClientId(): void
    {
        $url = 'https://claude.ai/oauth/client-metadata.json';
        $http = new MockHttpClient([
            $this->documentResponse('https://evil.example/client.json', 'Evil'),
        ]);

        $this->expectException(CimdException::class);
        $this->expectExceptionMessage('does not match');
        $this->resolver($http)->resolve($url);
    }

    public function testRejectsUnknownHost(): void
    {
        $this->expectException(CimdException::class);
        $this->expectExceptionMessage('allowlist');
        $this->resolver(new MockHttpClient())->resolve('https://evil.example/client.json');
    }

    public function testRejectsHttp(): void
    {
        $this->expectException(CimdException::class);
        $this->expectExceptionMessage('https');
        $this->resolver(new MockHttpClient())->resolve('http://claude.ai/client.json');
    }

    public function testRejectsPrivateIp(): void
    {
        $this->expectException(CimdException::class);
        $this->expectExceptionMessage('not allowed');
        $this->resolver(new MockHttpClient())->resolve('https://127.0.0.1/client.json');
    }

    public function testRejectsUrlWithoutPath(): void
    {
        $this->expectException(CimdException::class);
        $this->expectExceptionMessage('path');
        $this->resolver(new MockHttpClient())->resolve('https://claude.ai');
    }

    public function testDoesNotFollowRedirects(): void
    {
        $http = new MockHttpClient([
            new MockResponse('', ['http_code' => 302, 'response_headers' => ['location' => 'https://127.0.0.1/stolen.json']]),
            $this->documentResponse('https://claude.ai/oauth/client-metadata.json', 'Claude'),
        ]);

        try {
            $this->resolver($http)->resolve('https://claude.ai/oauth/client-metadata.json');
            self::fail('A redirect must not be followed.');
        } catch (CimdException $e) {
            self::assertStringContainsString('not 200', $e->getMessage());
        }

        self::assertSame(1, $http->getRequestsCount());
    }

    public function testSendsTimeoutsAndDisablesRedirects(): void
    {
        $url = 'https://claude.ai/oauth/client-metadata.json';
        $response = $this->documentResponse($url, 'Claude');
        $this->resolver(new MockHttpClient([$response]))->resolve($url);

        self::assertSame(0, $response->getRequestOptions()['max_redirects']);
        self::assertSame(5.0, (float) $response->getRequestOptions()['timeout']);
        self::assertSame(10.0, (float) $response->getRequestOptions()['max_duration']);
    }

    public function testRejectsHostResolvingToPrivateIp(): void
    {
        $http = (new NoPrivateNetworkHttpClient(new MockHttpClient([
            $this->documentResponse('https://claude.ai/oauth/client-metadata.json', 'Claude'),
        ])))->withOptions(['resolve' => ['claude.ai' => '10.0.0.7']]);

        $this->expectException(CimdException::class);
        $this->expectExceptionMessage('Unable to fetch');
        $this->resolver($http)->resolve('https://claude.ai/oauth/client-metadata.json');
    }

    public function testRejectsDocumentLargerThanContentLengthLimit(): void
    {
        $body = str_repeat(' ', ClientIdMetadataResolver::MAX_DOCUMENT_BYTES + 1);
        $http = new MockHttpClient([
            new MockResponse($body, [
                'http_code' => 200,
                'response_headers' => ['content-length' => (string) \strlen($body)],
            ]),
        ]);

        $this->expectException(CimdException::class);
        $this->expectExceptionMessage('too large');
        $this->resolver($http)->resolve('https://claude.ai/oauth/client-metadata.json');
    }

    public function testRejectsStreamedDocumentLargerThanLimit(): void
    {
        $chunks = static function (): \Generator {
            yield '{"client_name": "';
            yield str_repeat('a', ClientIdMetadataResolver::MAX_DOCUMENT_BYTES);
            yield '"}';
        };
        $http = new MockHttpClient([new MockResponse($chunks(), ['http_code' => 200])]);

        $this->expectException(CimdException::class);
        $this->expectExceptionMessage('too large');
        $this->resolver($http)->resolve('https://claude.ai/oauth/client-metadata.json');
    }

    public function testRejectsNonObjectJson(): void
    {
        $http = new MockHttpClient([new MockResponse('"claude"', ['http_code' => 200])]);

        $this->expectException(CimdException::class);
        $this->expectExceptionMessage('JSON object');
        $this->resolver($http)->resolve('https://claude.ai/oauth/client-metadata.json');
    }

    #[DataProvider('unsafeRedirectUris')]
    public function testRejectsUnsafeRedirectUri(string $redirectUri): void
    {
        $url = 'https://claude.ai/oauth/client-metadata.json';
        $http = new MockHttpClient([$this->documentResponse($url, 'Claude', [$redirectUri])]);

        $this->expectException(CimdException::class);
        $this->expectExceptionMessage('is not allowed');
        $this->resolver($http)->resolve($url);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function unsafeRedirectUris(): iterable
    {
        yield 'javascript' => ['javascript://claude.ai/%0aalert(1)'];
        yield 'data' => ['data:text/html,<script>alert(1)</script>'];
        yield 'file' => ['file:///etc/passwd'];
        yield 'http on a public host' => ['http://claude.ai/callback'];
        yield 'fragment' => ['https://claude.ai/callback#token'];
        yield 'relative' => ['/callback'];
    }

    public function testAcceptsLoopbackHttpRedirectUris(): void
    {
        $url = 'https://claude.ai/oauth/client-metadata.json';
        $redirectUris = ['http://127.0.0.1:33418/callback', 'http://[::1]/callback', 'http://localhost:8080/callback'];
        $http = new MockHttpClient([$this->documentResponse($url, 'Claude Code', $redirectUris)]);

        self::assertSame($redirectUris, $this->resolver($http)->resolve($url)->redirectUris);
    }

    private function resolver(HttpClientInterface $http): ClientIdMetadataResolver
    {
        return new ClientIdMetadataResolver($http, new ArrayAdapter(), $this->settings());
    }

    /**
     * @param list<string> $redirectUris
     */
    private function documentResponse(string $clientId, string $name, array $redirectUris = ['https://claude.ai/api/mcp/auth_callback']): MockResponse
    {
        return new MockResponse(json_encode([
            'client_id' => $clientId,
            'client_name' => $name,
            'redirect_uris' => $redirectUris,
        ], \JSON_THROW_ON_ERROR), [
            'http_code' => 200,
            'response_headers' => ['content-type' => 'application/json'],
        ]);
    }

    private function settings(): McpOauthSettings
    {
        return new McpOauthSettings(
            resourcePaths: ['/_mcp'],
            authorizationPrefix: '/oauth2',
            scopes: ['mcp'],
            loginRoute: 'app_login',
            redirectQueryParam: '_target_path',
            consent: 'page',
            cimdEnabled: true,
            trustedDomains: ['claude.ai'],
            dcrEnabled: true,
            resourceIndicators: true,
            issuerIdentification: true,
            publicBaseUrl: null,
        );
    }
}
