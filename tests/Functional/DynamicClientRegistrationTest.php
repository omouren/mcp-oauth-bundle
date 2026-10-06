<?php

declare(strict_types=1);

namespace Omouren\McpOauthBundle\Tests\Functional;

use Omouren\McpOauthBundle\Tests\Fixtures\TestKernel;
use Symfony\Bundle\FrameworkBundle\Test\WebTestCase;

final class DynamicClientRegistrationTest extends WebTestCase
{
    protected static function getKernelClass(): string
    {
        return TestKernel::class;
    }

    public function testRegistersConfidentialClientAndReturnsPlainSecret(): void
    {
        $deprecations = [];
        set_error_handler(static function (int $errno, string $errstr) use (&$deprecations): bool {
            if (\E_USER_DEPRECATED === $errno) {
                $deprecations[] = $errstr;
            }

            return false;
        });

        try {
            $client = self::createClient();
            $client->request(
                'POST',
                '/oauth2/register',
                [],
                [],
                ['CONTENT_TYPE' => 'application/json'],
                json_encode([
                    'client_name' => 'Test',
                    'redirect_uris' => ['https://claude.ai/api/mcp/auth_callback'],
                    'token_endpoint_auth_method' => 'client_secret_post',
                ], \JSON_THROW_ON_ERROR),
            );
        } finally {
            restore_error_handler();
        }

        self::assertNotEmpty($deprecations);
        self::assertStringContainsString('Dynamic Client Registration', $deprecations[0]);
        self::assertResponseStatusCodeSame(201);

        $payload = json_decode($client->getResponse()->getContent() ?: '', true, 512, \JSON_THROW_ON_ERROR);
        self::assertSame('client_secret_post', $payload['token_endpoint_auth_method']);
        self::assertMatchesRegularExpression('/^[a-f0-9]{32}$/', $payload['client_id']);
        self::assertMatchesRegularExpression('/^[a-f0-9]{64}$/', $payload['client_secret']);
        self::assertSame(0, $payload['client_secret_expires_at']);
    }

    public function testRegistersPublicClientWithoutSecret(): void
    {
        $client = self::createClient();
        $client->request(
            'POST',
            '/oauth2/register',
            [],
            [],
            ['CONTENT_TYPE' => 'application/json'],
            json_encode([
                'client_name' => 'Cursor',
                'redirect_uris' => ['http://127.0.0.1:3000/callback'],
                'token_endpoint_auth_method' => 'none',
            ], \JSON_THROW_ON_ERROR),
        );

        self::assertResponseStatusCodeSame(201);
        $payload = json_decode($client->getResponse()->getContent() ?: '', true, 512, \JSON_THROW_ON_ERROR);
        self::assertSame('none', $payload['token_endpoint_auth_method']);
        self::assertArrayNotHasKey('client_secret', $payload);
    }

    public function testRegistersConfidentialClientForBasicAuth(): void
    {
        $client = self::createClient();
        $client->request(
            'POST',
            '/oauth2/register',
            [],
            [],
            ['CONTENT_TYPE' => 'application/json'],
            json_encode([
                'client_name' => 'Test',
                'redirect_uris' => ['https://claude.ai/api/mcp/auth_callback'],
                'token_endpoint_auth_method' => 'client_secret_basic',
            ], \JSON_THROW_ON_ERROR),
        );

        self::assertResponseStatusCodeSame(201);
        $payload = json_decode($client->getResponse()->getContent() ?: '', true, 512, \JSON_THROW_ON_ERROR);
        self::assertSame('client_secret_basic', $payload['token_endpoint_auth_method']);
        self::assertMatchesRegularExpression('/^[a-f0-9]{64}$/', $payload['client_secret']);
    }

    public function testAcceptsEveryAdvertisedTokenEndpointAuthMethod(): void
    {
        $client = self::createClient();
        $client->request('GET', '/.well-known/oauth-authorization-server');
        $metadata = json_decode($client->getResponse()->getContent() ?: '', true, 512, \JSON_THROW_ON_ERROR);

        foreach ($metadata['token_endpoint_auth_methods_supported'] as $method) {
            $client->request(
                'POST',
                '/oauth2/register',
                [],
                [],
                ['CONTENT_TYPE' => 'application/json'],
                json_encode([
                    'redirect_uris' => ['https://claude.ai/api/mcp/auth_callback'],
                    'token_endpoint_auth_method' => $method,
                ], \JSON_THROW_ON_ERROR),
            );

            self::assertResponseStatusCodeSame(201, $method);
        }
    }

    public function testRejectsUnsupportedTokenEndpointAuthMethod(): void
    {
        $client = self::createClient();
        $client->request(
            'POST',
            '/oauth2/register',
            [],
            [],
            ['CONTENT_TYPE' => 'application/json'],
            json_encode([
                'redirect_uris' => ['https://claude.ai/api/mcp/auth_callback'],
                'token_endpoint_auth_method' => 'private_key_jwt',
            ], \JSON_THROW_ON_ERROR),
        );

        self::assertResponseStatusCodeSame(400);
        $payload = json_decode($client->getResponse()->getContent() ?: '', true, 512, \JSON_THROW_ON_ERROR);
        self::assertSame('invalid_client_metadata', $payload['error']);
        self::assertStringContainsString('client_secret_basic', $payload['error_description']);
    }

    public function testRejectsInvalidJson(): void
    {
        $client = self::createClient();
        $client->request(
            'POST',
            '/oauth2/register',
            [],
            [],
            ['CONTENT_TYPE' => 'application/json'],
            '{not-json',
        );

        self::assertResponseStatusCodeSame(400);
        $payload = json_decode($client->getResponse()->getContent() ?: '', true, 512, \JSON_THROW_ON_ERROR);
        self::assertSame('invalid_client_metadata', $payload['error']);
    }
}
