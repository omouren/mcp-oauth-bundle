<?php

declare(strict_types=1);

namespace Omouren\McpOauthBundle\Tests\Functional;

use League\Bundle\OAuth2ServerBundle\Event\AuthorizationRequestResolveEvent;
use League\Bundle\OAuth2ServerBundle\Model\Client;
use League\OAuth2\Server\RequestTypes\AuthorizationRequest;
use Omouren\McpOauthBundle\EventListener\ConsentListener;
use Omouren\McpOauthBundle\Tests\Fixtures\TestKernel;
use Symfony\Bundle\FrameworkBundle\KernelBrowser;
use Symfony\Bundle\FrameworkBundle\Test\WebTestCase;
use Symfony\Component\BrowserKit\Cookie;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\RequestStack;
use Symfony\Component\HttpFoundation\Session\SessionInterface;
use Symfony\Component\Security\Core\User\InMemoryUser;

final class ConsentTest extends WebTestCase
{
    private const AUTHORIZE_QUERY = [
        'client_id' => 'legit',
        'redirect_uri' => 'https://claude.ai/api/mcp/auth_callback',
        'response_type' => 'code',
        'scope' => 'mcp',
    ];

    protected static function getKernelClass(): string
    {
        return TestKernel::class;
    }

    public function testUnknownConsentIsRejected(): void
    {
        $client = self::createClient();
        $client->request('GET', '/oauth2/consent');

        self::assertResponseStatusCodeSame(400);
        self::assertResponseHeaderSame('X-Frame-Options', 'DENY');
    }

    public function testQueryCannotSpoofClientNameOrForgeApproval(): void
    {
        $client = self::createClient();
        $client->request('GET', '/oauth2/consent?'.http_build_query([
            'consent_id' => 'forged',
            'client_id' => 'evil',
            'redirect_uri' => 'https://evil.example/cb',
            'response_type' => 'code',
            'scope' => 'mcp',
            'client_name' => 'Claude',
            'redirect_host' => 'claude.ai',
        ]));

        self::assertResponseStatusCodeSame(400);
        $content = (string) $client->getResponse()->getContent();
        self::assertStringNotContainsString('Claude', $content);
        self::assertStringNotContainsString('claude.ai', $content);

        $client->request('POST', '/oauth2/consent?consent_id=forged&client_id=evil&scope=mcp');

        self::assertResponseStatusCodeSame(400);
        self::assertFalse($client->getRequest()->getSession()->has(ConsentListener::APPROVED_SESSION_KEY));
    }

    public function testApprovalReplaysStoredAuthorizeRequest(): void
    {
        $client = self::createClient();
        $this->seedPendingConsent($client, 'abc');

        $crawler = $client->request('GET', '/oauth2/consent?consent_id=abc&client_name=Evil');

        self::assertResponseIsSuccessful();
        self::assertResponseHeaderSame('X-Frame-Options', 'DENY');
        self::assertResponseHeaderSame('Content-Security-Policy', "frame-ancestors 'none'");
        self::assertSelectorTextContains('h1', 'Authorize Claude');
        self::assertStringNotContainsString('Evil', (string) $client->getResponse()->getContent());

        $client->submit($crawler->filter('form')->form());

        self::assertResponseRedirects('/oauth2/authorize?client_id=legit&redirect_uri=https://claude.ai/api/mcp/auth_callback&response_type=code&scope=mcp');
        $session = $client->getRequest()->getSession();
        self::assertSame(self::AUTHORIZE_QUERY, $session->get(ConsentListener::APPROVED_SESSION_KEY));
        self::assertSame([], $session->get(ConsentListener::PENDING_SESSION_KEY));
    }

    public function testApprovalRequiresValidCsrfToken(): void
    {
        $client = self::createClient();
        $this->seedPendingConsent($client, 'abc');

        $client->request('POST', '/oauth2/consent?consent_id=abc', ['_csrf_token' => 'nope']);

        self::assertResponseStatusCodeSame(403);
        self::assertFalse($client->getRequest()->getSession()->has(ConsentListener::APPROVED_SESSION_KEY));
    }

    public function testFullRoundTripApprovesTheSameAuthorizeRequestOnce(): void
    {
        $client = self::createClient();
        $authorizeUri = 'https://mcp.example.test/oauth2/authorize?'.http_build_query([
            'response_type' => 'code',
            'client_id' => 'legit',
            'redirect_uri' => 'https://claude.ai/api/mcp/auth_callback',
            'scope' => 'mcp',
            'state' => 'xyz',
            'code_challenge' => 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM',
            'code_challenge_method' => 'S256',
            'resource' => 'https://mcp.example.test/_mcp',
        ]);

        $session = $this->newSession($client);
        $consentStart = $this->resolveAuthorization($authorizeUri, $session);
        $session->save();

        self::assertFalse($consentStart->getAuthorizationResolution());
        $consentUrl = (string) $consentStart->getResponse()?->headers->get('Location');
        self::assertStringStartsWith('/oauth2/consent?consent_id=', $consentUrl);

        $crawler = $client->request('GET', $consentUrl);
        self::assertSelectorTextContains('h1', 'Authorize Claude');
        $client->submit($crawler->filter('form')->form());
        self::assertResponseStatusCodeSame(302);
        $replayUri = 'https://mcp.example.test'.$client->getResponse()->headers->get('Location');
        $session = $client->getRequest()->getSession();

        $approved = $this->resolveAuthorization($replayUri, $session);
        self::assertTrue($approved->getAuthorizationResolution());

        $replayed = $this->resolveAuthorization($replayUri, $session);
        self::assertFalse($replayed->getAuthorizationResolution());
        self::assertStringStartsWith('/oauth2/consent?consent_id=', (string) $replayed->getResponse()?->headers->get('Location'));
    }

    private function resolveAuthorization(string $uri, SessionInterface $session): AuthorizationRequestResolveEvent
    {
        $request = Request::create($uri);
        $request->setSession($session);
        $authorizationRequest = new AuthorizationRequest();
        $authorizationRequest->setRedirectUri((string) $request->query->get('redirect_uri'));
        $event = new AuthorizationRequestResolveEvent(
            $authorizationRequest,
            [],
            new Client('Claude', 'legit', null),
            new InMemoryUser('user', null),
        );

        $requestStack = self::getContainer()->get('request_stack');
        \assert($requestStack instanceof RequestStack);
        $listener = self::getContainer()->get(ConsentListener::class);
        \assert($listener instanceof ConsentListener);

        $requestStack->push($request);
        try {
            $listener($event);
        } finally {
            $requestStack->pop();
        }

        return $event;
    }

    private function newSession(KernelBrowser $client): SessionInterface
    {
        $session = self::getContainer()->get('session.factory')->createSession();
        \assert($session instanceof SessionInterface);
        $session->start();
        $client->getCookieJar()->set(new Cookie($session->getName(), $session->getId()));

        return $session;
    }

    private function seedPendingConsent(KernelBrowser $client, string $consentId): void
    {
        $session = $this->newSession($client);
        $session->set(ConsentListener::PENDING_SESSION_KEY, [
            $consentId => [
                'query' => self::AUTHORIZE_QUERY,
                'client_name' => 'Claude',
                'redirect_host' => 'claude.ai',
            ],
        ]);
        $session->save();
    }
}
