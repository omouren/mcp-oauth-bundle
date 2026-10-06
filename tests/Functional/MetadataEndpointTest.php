<?php

declare(strict_types=1);

namespace Omouren\McpOauthBundle\Tests\Functional;

use Omouren\McpOauthBundle\Tests\Fixtures\TestKernel;
use Symfony\Bundle\FrameworkBundle\Test\WebTestCase;

final class MetadataEndpointTest extends WebTestCase
{
    protected static function getKernelClass(): string
    {
        return TestKernel::class;
    }

    public function testAuthorizationServerMetadata(): void
    {
        $client = self::createClient();
        $client->request('GET', '/.well-known/oauth-authorization-server');

        self::assertResponseIsSuccessful();
        $payload = json_decode($client->getResponse()->getContent() ?: '', true, 512, \JSON_THROW_ON_ERROR);

        self::assertSame('https://mcp.example.test', $payload['issuer']);
        self::assertSame(['S256'], $payload['code_challenge_methods_supported']);
        self::assertTrue($payload['client_id_metadata_document_supported']);
        self::assertTrue($payload['authorization_response_iss_parameter_supported']);
        self::assertSame(['authorization_code', 'refresh_token'], $payload['grant_types_supported']);
        self::assertNotContains('client_credentials', $payload['grant_types_supported']);
        self::assertSame(
            ['client_secret_basic', 'client_secret_post', 'none'],
            $payload['token_endpoint_auth_methods_supported'],
        );
        self::assertSame('https://mcp.example.test/oauth2/register', $payload['registration_endpoint']);
        self::assertSame('https://mcp.example.test/oauth2/authorize', $payload['authorization_endpoint']);
        self::assertSame('*', $client->getResponse()->headers->get('Access-Control-Allow-Origin'));
        self::assertStringContainsString('max-age=3600', (string) $client->getResponse()->headers->get('Cache-Control'));
    }

    public function testProtectedResourceMetadata(): void
    {
        $client = self::createClient();
        $client->request('GET', '/.well-known/oauth-protected-resource');

        self::assertResponseIsSuccessful();
        $payload = json_decode($client->getResponse()->getContent() ?: '', true, 512, \JSON_THROW_ON_ERROR);

        self::assertSame('https://mcp.example.test/_mcp', $payload['resource']);
        self::assertSame(['https://mcp.example.test'], $payload['authorization_servers']);
        self::assertSame(['header'], $payload['bearer_methods_supported']);
        self::assertSame(['mcp'], $payload['scopes_supported']);
    }

    public function testPathAwareProtectedResourceMetadata(): void
    {
        $client = self::createClient();
        $client->request('GET', '/.well-known/oauth-protected-resource/_mcp');

        self::assertResponseIsSuccessful();
        $payload = json_decode($client->getResponse()->getContent() ?: '', true, 512, \JSON_THROW_ON_ERROR);
        self::assertSame('https://mcp.example.test/_mcp', $payload['resource']);
    }

    public function testPathAwareAuthorizationServerMetadata(): void
    {
        $client = self::createClient();
        $client->request('GET', '/.well-known/oauth-authorization-server/oauth2');

        self::assertResponseIsSuccessful();
        $payload = json_decode($client->getResponse()->getContent() ?: '', true, 512, \JSON_THROW_ON_ERROR);
        self::assertSame('https://mcp.example.test', $payload['issuer']);
    }

    public function testWwwAuthenticateOnUnauthorizedResource(): void
    {
        $client = self::createClient();
        $client->request('GET', '/_mcp');

        self::assertResponseStatusCodeSame(401);
        $header = $client->getResponse()->headers->get('WWW-Authenticate');
        self::assertNotNull($header);
        self::assertStringContainsString('resource_metadata="https://mcp.example.test/.well-known/oauth-protected-resource/_mcp"', $header);
        self::assertStringContainsString('scope="mcp"', $header);
        self::assertStringNotContainsString('error=', $header);
        self::assertSame('WWW-Authenticate', $client->getResponse()->headers->get('Access-Control-Expose-Headers'));
        self::assertFalse($client->getResponse()->headers->has('Mcp-Session-Id'));
    }

    public function testAuthorizeRedirectsAnonymousUsersToLogin(): void
    {
        $client = self::createClient();
        $client->request('GET', '/oauth2/authorize?scope=mcp');

        self::assertResponseRedirects();
        self::assertStringContainsString('/login', (string) $client->getResponse()->headers->get('Location'));
        self::assertStringNotContainsString('iss=', (string) $client->getResponse()->headers->get('Location'));
        self::assertSame(
            'http://localhost/oauth2/authorize?scope=mcp',
            $client->getRequest()->getSession()->get('_security.main.target_path'),
        );
    }

    public function testAuthorizeWithoutMcpScopeIsIgnored(): void
    {
        $client = self::createClient();
        $client->request('GET', '/oauth2/authorize?scope=api');

        self::assertResponseIsSuccessful();
        self::assertSame('login', $client->getResponse()->getContent());
    }

    public function testTokenWithoutMcpAudienceIsRejectedOnResource(): void
    {
        $client = self::createClient();
        $jwt = $this->unsignedJwt(['aud' => 'not-the-mcp']);
        $client->request('GET', '/_mcp', server: ['HTTP_AUTHORIZATION' => 'Bearer '.$jwt]);

        self::assertResponseStatusCodeSame(401);
        $header = $client->getResponse()->headers->get('WWW-Authenticate');
        self::assertNotNull($header);
        self::assertStringContainsString('error="invalid_token"', $header);
    }

    /**
     * @param array<string, mixed> $payload
     */
    private function unsignedJwt(array $payload): string
    {
        $encode = static fn (array $data): string => rtrim(strtr(base64_encode(json_encode($data, \JSON_THROW_ON_ERROR)), '+/', '-_'), '=');

        return $encode(['alg' => 'none', 'typ' => 'JWT']).'.'.$encode($payload).'.x';
    }
}
