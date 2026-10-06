<?php

declare(strict_types=1);

namespace Omouren\McpOauthBundle\Tests\Unit\EventListener;

use League\Bundle\OAuth2ServerBundle\Event\AuthorizationRequestResolveEvent;
use League\Bundle\OAuth2ServerBundle\Model\ClientInterface;
use League\OAuth2\Server\Exception\OAuthServerException;
use League\OAuth2\Server\RequestTypes\AuthorizationRequest;
use Omouren\McpOauthBundle\EventListener\PkceListener;
use Omouren\McpOauthBundle\McpOauthSettings;
use Omouren\McpOauthBundle\OAuth\CanonicalResourceUri;
use Omouren\McpOauthBundle\OAuth\IssuerResolver;
use Omouren\McpOauthBundle\OAuth\McpRequestGuard;
use PHPUnit\Framework\TestCase;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\RequestStack;
use Symfony\Component\Security\Core\User\UserInterface;

final class PkceListenerTest extends TestCase
{
    private const CHALLENGE = 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM';

    public function testAcceptsS256Challenge(): void
    {
        $this->expectNotToPerformAssertions();

        $this->listener('/oauth2/authorize?scope=mcp')->__invoke($this->event(self::CHALLENGE, 'S256'));
    }

    public function testRejectsMissingChallengeEvenForConfidentialClients(): void
    {
        $this->expectException(OAuthServerException::class);
        $this->expectExceptionCode(3);

        try {
            $this->listener('/oauth2/authorize?scope=mcp')->__invoke($this->event(null, null));
        } catch (OAuthServerException $e) {
            self::assertSame('invalid_request', $e->getErrorType());
            self::assertSame('Code challenge must be provided for MCP clients.', $e->getHint());

            throw $e;
        }
    }

    public function testRejectsPlainChallenge(): void
    {
        $this->expectException(OAuthServerException::class);

        try {
            $this->listener('/oauth2/authorize?scope=mcp')->__invoke($this->event(self::CHALLENGE, 'plain'));
        } catch (OAuthServerException $e) {
            self::assertSame('Code challenge method must be S256.', $e->getHint());

            throw $e;
        }
    }

    public function testRejectsMissingChallengeWhenResourceTargetsMcp(): void
    {
        $this->expectException(OAuthServerException::class);

        $this->listener('/oauth2/authorize?resource='.rawurlencode('https://mcp.example.test/_mcp'))
            ->__invoke($this->event(null, null));
    }

    public function testIgnoresNonMcpAuthorizeRequests(): void
    {
        $this->expectNotToPerformAssertions();

        $this->listener('/oauth2/authorize?scope=api')->__invoke($this->event(null, null));
    }

    public function testIgnoresOtherPaths(): void
    {
        $this->expectNotToPerformAssertions();

        $this->listener('/other?scope=mcp')->__invoke($this->event(null, null));
    }

    private function listener(string $uri): PkceListener
    {
        $settings = new McpOauthSettings(
            resourcePaths: ['/_mcp'],
            authorizationPrefix: '/oauth2',
            scopes: ['mcp'],
            loginRoute: 'app_login',
            redirectQueryParam: '_target_path',
            consent: 'page',
            cimdEnabled: true,
            trustedDomains: [],
            dcrEnabled: true,
            resourceIndicators: true,
            issuerIdentification: true,
            publicBaseUrl: 'https://mcp.example.test',
        );
        $canonical = new CanonicalResourceUri();
        $requestStack = new RequestStack();
        $requestStack->push(Request::create('https://mcp.example.test'.$uri));

        return new PkceListener(
            $requestStack,
            new McpRequestGuard($settings, new IssuerResolver($settings, $canonical), $canonical),
        );
    }

    private function event(?string $codeChallenge, ?string $codeChallengeMethod): AuthorizationRequestResolveEvent
    {
        $authorizationRequest = new AuthorizationRequest();
        if (null !== $codeChallenge && null !== $codeChallengeMethod) {
            $authorizationRequest->setCodeChallenge($codeChallenge);
            $authorizationRequest->setCodeChallengeMethod($codeChallengeMethod);
        }

        $client = $this->createStub(ClientInterface::class);
        $client->method('isConfidential')->willReturn(true);

        return new AuthorizationRequestResolveEvent(
            $authorizationRequest,
            [],
            $client,
            $this->createStub(UserInterface::class),
        );
    }
}
