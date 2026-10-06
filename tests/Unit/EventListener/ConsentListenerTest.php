<?php

declare(strict_types=1);

namespace Omouren\McpOauthBundle\Tests\Unit\EventListener;

use League\Bundle\OAuth2ServerBundle\Event\AuthorizationRequestResolveEvent;
use League\Bundle\OAuth2ServerBundle\Model\Client;
use League\Bundle\OAuth2ServerBundle\ValueObject\RedirectUri;
use League\OAuth2\Server\RequestTypes\AuthorizationRequest;
use Omouren\McpOauthBundle\EventListener\ConsentListener;
use Omouren\McpOauthBundle\McpOauthSettings;
use Omouren\McpOauthBundle\OAuth\CanonicalResourceUri;
use Omouren\McpOauthBundle\OAuth\IssuerResolver;
use Omouren\McpOauthBundle\OAuth\McpRequestGuard;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\RequestStack;
use Symfony\Component\HttpFoundation\Session\Session;
use Symfony\Component\HttpFoundation\Session\Storage\MockArraySessionStorage;
use Symfony\Component\Routing\Generator\UrlGeneratorInterface;
use Symfony\Component\Security\Core\User\InMemoryUser;

final class ConsentListenerTest extends TestCase
{
    private const AUTHORIZE_URL = 'https://mcp.example.test/oauth2/authorize?scope=mcp&client_id=legit&redirect_uri=https%3A%2F%2Fclaude.ai%2Fcb&response_type=code';

    public function testRedirectsToConsentPageWithOnlyAnOpaqueId(): void
    {
        $request = $this->request(self::AUTHORIZE_URL);
        $event = $this->event();

        $this->listener($request)->__invoke($event);

        $response = $event->getResponse();
        self::assertInstanceOf(RedirectResponse::class, $response);
        self::assertMatchesRegularExpression('#^/oauth2/consent\?consent_id=[0-9a-f]{32}$#', (string) $response->headers->get('Location'));
        self::assertFalse($event->getAuthorizationResolution());

        $pending = $request->getSession()->get(ConsentListener::PENDING_SESSION_KEY);
        self::assertIsArray($pending);
        self::assertSame([
            'query' => ['client_id' => 'legit', 'redirect_uri' => 'https://claude.ai/cb', 'response_type' => 'code', 'scope' => 'mcp'],
            'client_name' => 'Claude',
            'redirect_host' => 'claude.ai',
        ], array_values($pending)[0]);
    }

    public function testApprovesOnlyTheAuthorizeRequestThatWasConsented(): void
    {
        $request = $this->request(self::AUTHORIZE_URL);
        $request->getSession()->set(ConsentListener::APPROVED_SESSION_KEY, [
            'client_id' => 'legit', 'redirect_uri' => 'https://claude.ai/cb', 'response_type' => 'code', 'scope' => 'mcp',
        ]);
        $event = $this->event();

        $this->listener($request)->__invoke($event);

        self::assertTrue($event->getAuthorizationResolution());
        self::assertNull($event->getResponse());
        self::assertFalse($request->getSession()->has(ConsentListener::APPROVED_SESSION_KEY));
    }

    /**
     * @return iterable<string, array{string, string}>
     */
    public static function tamperedParameters(): iterable
    {
        yield 'state' => ['state', 'attacker-state'];
        yield 'code_challenge' => ['code_challenge', 'attacker-challenge'];
        yield 'redirect_uri' => ['redirect_uri', 'https://evil.example/cb'];
    }

    #[DataProvider('tamperedParameters')]
    public function testApprovalIsBoundToEveryAuthorizeParameter(string $parameter, string $value): void
    {
        $approved = [
            'client_id' => 'legit',
            'code_challenge' => 'legit-challenge',
            'redirect_uri' => 'https://claude.ai/cb',
            'response_type' => 'code',
            'scope' => 'mcp',
            'state' => 'legit-state',
        ];
        $request = $this->request('https://mcp.example.test/oauth2/authorize?'.http_build_query([$parameter => $value] + $approved));
        $request->getSession()->set(ConsentListener::APPROVED_SESSION_KEY, $approved);
        $event = $this->event();

        $this->listener($request)->__invoke($event);

        self::assertFalse($event->getAuthorizationResolution());
        self::assertInstanceOf(RedirectResponse::class, $event->getResponse());
    }

    public function testApprovalIsUsedOnlyOnce(): void
    {
        $request = $this->request(self::AUTHORIZE_URL);
        $request->getSession()->set(ConsentListener::APPROVED_SESSION_KEY, [
            'client_id' => 'legit', 'redirect_uri' => 'https://claude.ai/cb', 'response_type' => 'code', 'scope' => 'mcp',
        ]);
        $listener = $this->listener($request);

        $first = $this->event();
        $listener($first);
        $second = $this->event();
        $listener($second);

        self::assertTrue($first->getAuthorizationResolution());
        self::assertFalse($second->getAuthorizationResolution());
        self::assertInstanceOf(RedirectResponse::class, $second->getResponse());
    }

    public function testApprovalForAnotherRequestIsDiscarded(): void
    {
        $request = $this->request('https://mcp.example.test/oauth2/authorize?scope=mcp&client_id=evil&redirect_uri=https%3A%2F%2Fevil.example%2Fcb&response_type=code');
        $request->getSession()->set(ConsentListener::APPROVED_SESSION_KEY, [
            'client_id' => 'legit', 'redirect_uri' => 'https://claude.ai/cb', 'response_type' => 'code', 'scope' => 'mcp',
        ]);
        $event = $this->event();

        $this->listener($request)->__invoke($event);

        self::assertFalse($event->getAuthorizationResolution());
        self::assertInstanceOf(RedirectResponse::class, $event->getResponse());
        self::assertFalse($request->getSession()->has(ConsentListener::APPROVED_SESSION_KEY));
    }

    public function testNonMcpAuthorizeLeavesApprovalAlone(): void
    {
        $request = $this->request('https://mcp.example.test/oauth2/authorize?scope=api&client_id=legit');
        $request->getSession()->set(ConsentListener::APPROVED_SESSION_KEY, ['client_id' => 'legit']);
        $event = $this->event();

        $this->listener($request)->__invoke($event);

        self::assertNull($event->getResponse());
        self::assertTrue($request->getSession()->has(ConsentListener::APPROVED_SESSION_KEY));
    }

    public function testAutoConsentApprovesWithoutConsentPage(): void
    {
        $request = $this->request(self::AUTHORIZE_URL);
        $event = $this->event();

        $this->listener($request, consent: 'auto')->__invoke($event);

        self::assertTrue($event->getAuthorizationResolution());
        self::assertFalse($request->getSession()->has(ConsentListener::PENDING_SESSION_KEY));
    }

    public function testFallsBackToRegisteredRedirectUriHost(): void
    {
        $request = $this->request('https://mcp.example.test/oauth2/authorize?scope=mcp&client_id=legit&response_type=code');
        $client = new Client('Claude', 'legit', null);
        $client->setRedirectUris(new RedirectUri('https://claude.ai/cb'));
        $event = new AuthorizationRequestResolveEvent(new AuthorizationRequest(), [], $client, new InMemoryUser('user', null));

        $this->listener($request)->__invoke($event);

        $pending = $request->getSession()->get(ConsentListener::PENDING_SESSION_KEY);
        self::assertIsArray($pending);
        self::assertSame('claude.ai', array_values($pending)[0]['redirect_host']);
    }

    private function request(string $uri): Request
    {
        $request = Request::create($uri);
        $request->setSession(new Session(new MockArraySessionStorage()));

        return $request;
    }

    private function event(): AuthorizationRequestResolveEvent
    {
        $authorizationRequest = new AuthorizationRequest();
        $authorizationRequest->setRedirectUri('https://claude.ai/cb');

        return new AuthorizationRequestResolveEvent(
            $authorizationRequest,
            [],
            new Client('Claude', 'legit', null),
            new InMemoryUser('user', null),
        );
    }

    private function listener(Request $request, string $consent = 'page'): ConsentListener
    {
        $settings = new McpOauthSettings(
            resourcePaths: ['/_mcp'],
            authorizationPrefix: '/oauth2',
            scopes: ['mcp'],
            loginRoute: 'app_login',
            redirectQueryParam: '_target_path',
            consent: $consent,
            cimdEnabled: true,
            trustedDomains: [],
            dcrEnabled: true,
            resourceIndicators: true,
            issuerIdentification: true,
            publicBaseUrl: 'https://mcp.example.test',
        );
        $canonical = new CanonicalResourceUri();
        $guard = new McpRequestGuard($settings, new IssuerResolver($settings, $canonical), $canonical);

        $requestStack = new RequestStack();
        $requestStack->push($request);

        $urls = $this->createMock(UrlGeneratorInterface::class);
        $urls->method('generate')->willReturnCallback(
            static fn (string $route, array $parameters): string => '/oauth2/consent?'.http_build_query($parameters),
        );

        return new ConsentListener($settings, $requestStack, $urls, $guard);
    }
}
