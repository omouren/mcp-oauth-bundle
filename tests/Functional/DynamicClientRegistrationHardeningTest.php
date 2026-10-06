<?php

declare(strict_types=1);

namespace Omouren\McpOauthBundle\Tests\Functional;

use Omouren\McpOauthBundle\Tests\Fixtures\TestKernel;
use PHPUnit\Framework\Attributes\DataProvider;
use Psr\Cache\CacheItemPoolInterface;
use Symfony\Bundle\FrameworkBundle\KernelBrowser;
use Symfony\Bundle\FrameworkBundle\Test\WebTestCase;

final class DynamicClientRegistrationHardeningTest extends WebTestCase
{
    protected static function getKernelClass(): string
    {
        return TestKernel::class;
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function allowedRedirectUris(): iterable
    {
        yield 'https' => ['https://claude.ai/api/mcp/auth_callback'];
        yield 'https with query' => ['https://app.example.com/cb?tenant=1'];
        yield 'loopback IPv4 with port' => ['http://127.0.0.1:33418/callback'];
        yield 'loopback IPv6' => ['http://[::1]:8080/callback'];
        yield 'localhost' => ['http://localhost:3000/callback'];
    }

    #[DataProvider('allowedRedirectUris')]
    public function testAcceptsRedirectUri(string $redirectUri): void
    {
        $client = self::createClient();
        $this->register($client, ['redirect_uris' => [$redirectUri]]);

        self::assertResponseStatusCodeSame(201);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function rejectedRedirectUris(): iterable
    {
        yield 'javascript' => ['javascript://x/%0aalert(1)'];
        yield 'javascript without slashes' => ['javascript:alert(1)'];
        yield 'data' => ['data:text/html,<script>alert(1)</script>'];
        yield 'file' => ['file:///etc/passwd'];
        yield 'unconfigured custom scheme' => ['cursor://anysphere.cursor-mcp/oauth/callback'];
        yield 'non-loopback http' => ['http://evil.example/cb'];
        yield 'http on a host that starts with localhost' => ['http://localhost.evil.example/cb'];
        yield 'fragment' => ['https://claude.ai/cb#token'];
        yield 'userinfo' => ['https://user:pass@claude.ai/cb'];
        yield 'relative' => ['/callback'];
        yield 'whitespace' => ['https://claude.ai/c b'];
        yield 'https without host' => ['https:///cb'];
        yield 'too long' => ['https://claude.ai/'.str_repeat('a', 2000)];
    }

    #[DataProvider('rejectedRedirectUris')]
    public function testRejectsRedirectUri(string $redirectUri): void
    {
        $client = self::createClient();
        $this->register($client, ['redirect_uris' => [$redirectUri]]);

        self::assertResponseStatusCodeSame(400);
        self::assertSame('invalid_redirect_uri', $this->payload($client)['error']);
    }

    public function testRejectsTooManyRedirectUris(): void
    {
        $client = self::createClient();
        $uris = array_map(static fn (int $i): string => 'https://claude.ai/cb/'.$i, range(1, 11));
        $this->register($client, ['redirect_uris' => $uris]);

        self::assertResponseStatusCodeSame(400);
        self::assertSame('invalid_redirect_uri', $this->payload($client)['error']);
    }

    public function testRejectsNonStringRedirectUri(): void
    {
        $client = self::createClient();
        $this->register($client, ['redirect_uris' => [['nested']]]);

        self::assertResponseStatusCodeSame(400);
        self::assertSame('Redirect URIs must be strings.', $this->payload($client)['error_description']);
    }

    public function testRejectsTooLongClientName(): void
    {
        $client = self::createClient();
        $this->register($client, ['client_name' => str_repeat('a', 201)]);

        self::assertResponseStatusCodeSame(400);
        self::assertSame('invalid_client_metadata', $this->payload($client)['error']);
    }

    public function testAcceptsMultibyteClientNameAtTheLimit(): void
    {
        $client = self::createClient();
        $this->register($client, ['client_name' => str_repeat('é', 200)]);

        self::assertResponseStatusCodeSame(201);
    }

    public function testRejectsClientNameWithControlCharacters(): void
    {
        $client = self::createClient();
        $this->register($client, ['client_name' => "Claude\nAllow everything"]);

        self::assertResponseStatusCodeSame(400);
        self::assertSame('invalid_client_metadata', $this->payload($client)['error']);
    }

    public function testRejectsTooLongScope(): void
    {
        $client = self::createClient();
        $this->register($client, ['scope' => str_repeat('mcp ', 300)]);

        self::assertResponseStatusCodeSame(400);
        self::assertSame('invalid_client_metadata', $this->payload($client)['error']);
    }

    public function testRejectsOversizedBody(): void
    {
        $client = self::createClient();
        $this->register($client, ['software_statement' => str_repeat('a', 20000)]);

        self::assertResponseStatusCodeSame(400);
        self::assertSame('invalid_client_metadata', $this->payload($client)['error']);
    }

    public function testAcceptsConfiguredCustomScheme(): void
    {
        $client = self::createClient(['environment' => 'dcr_hardened']);
        $this->register($client, ['redirect_uris' => ['com.example.app:/oauth2redirect']]);

        self::assertResponseStatusCodeSame(201);
    }

    public function testRateLimitsRegistrationsPerIp(): void
    {
        $client = self::createClient(['environment' => 'dcr_hardened']);
        $pool = self::getContainer()->get('cache.test_rate_limiter');
        self::assertInstanceOf(CacheItemPoolInterface::class, $pool);
        $pool->clear();

        $this->register($client, [], '203.0.113.10');
        self::assertResponseStatusCodeSame(201);
        $this->register($client, [], '203.0.113.10');
        self::assertResponseStatusCodeSame(201);
        $this->register($client, [], '203.0.113.10');
        self::assertResponseStatusCodeSame(429);
        self::assertSame('invalid_request', $this->payload($client)['error']);
        self::assertGreaterThan(0, (int) $client->getResponse()->headers->get('Retry-After'));

        $this->register($client, [], '203.0.113.11');
        self::assertResponseStatusCodeSame(201);
    }

    /**
     * @param array<string, mixed> $metadata
     */
    private function register(KernelBrowser $client, array $metadata, string $ip = '127.0.0.1'): void
    {
        $client->request(
            'POST',
            '/oauth2/register',
            [],
            [],
            ['CONTENT_TYPE' => 'application/json', 'REMOTE_ADDR' => $ip],
            json_encode($metadata + [
                'client_name' => 'Test',
                'redirect_uris' => ['https://claude.ai/api/mcp/auth_callback'],
            ], \JSON_THROW_ON_ERROR),
        );
    }

    /**
     * @return array<string, mixed>
     */
    private function payload(KernelBrowser $client): array
    {
        return json_decode($client->getResponse()->getContent() ?: '', true, 512, \JSON_THROW_ON_ERROR);
    }
}
