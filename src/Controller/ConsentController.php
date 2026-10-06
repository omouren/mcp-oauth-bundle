<?php

declare(strict_types=1);

namespace Omouren\McpOauthBundle\Controller;

use Omouren\McpOauthBundle\EventListener\ConsentListener;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Generator\UrlGeneratorInterface;
use Symfony\Component\Security\Csrf\CsrfToken;
use Symfony\Component\Security\Csrf\CsrfTokenManagerInterface;
use Twig\Environment;

final readonly class ConsentController
{
    public function __construct(
        private Environment $twig,
        private CsrfTokenManagerInterface $csrfTokenManager,
        private UrlGeneratorInterface $urlGenerator,
    ) {
    }

    public function __invoke(Request $request): Response
    {
        $session = $request->getSession();
        $consentId = (string) $request->query->get('consent_id', '');
        $pending = $session->get(ConsentListener::PENDING_SESSION_KEY, []);
        $consent = \is_array($pending) ? ($pending[$consentId] ?? null) : null;

        if (!\is_array($consent)) {
            return $this->secure(new Response('Unknown or expired consent request.', Response::HTTP_BAD_REQUEST));
        }

        if ($request->isMethod('POST')) {
            $token = (string) $request->request->get('_csrf_token', '');
            if (!$this->csrfTokenManager->isTokenValid(new CsrfToken('mcp_oauth_consent', $token))) {
                return $this->secure(new Response('Invalid CSRF token.', Response::HTTP_FORBIDDEN));
            }

            unset($pending[$consentId]);
            $session->set(ConsentListener::PENDING_SESSION_KEY, $pending);
            $session->set(ConsentListener::APPROVED_SESSION_KEY, $consent['query']);
            $target = $this->urlGenerator->generate('oauth2_authorize', $consent['query']);

            return $this->secure(new Response('', Response::HTTP_FOUND, ['Location' => $target]));
        }

        $html = $this->twig->render('@McpOauth/consent.html.twig', [
            'client_name' => $consent['client_name'],
            'redirect_host' => $consent['redirect_host'],
            'csrf_token' => $this->csrfTokenManager->getToken('mcp_oauth_consent')->getValue(),
        ]);

        return $this->secure(new Response($html));
    }

    private function secure(Response $response): Response
    {
        $response->headers->set('X-Frame-Options', 'DENY');
        $response->headers->set('Content-Security-Policy', "frame-ancestors 'none'");
        $response->headers->set('Cache-Control', 'no-store');

        return $response;
    }
}
