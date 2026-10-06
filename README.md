# McpOauthBundle

Claude, Cursor, and the MCP Inspector cannot complete OAuth against a Symfony MCP server that only has mcp-bundle and League. Neither implements [MCP Authorization 2026-07-28](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization):

- [`mcp/sdk`](https://github.com/modelcontextprotocol/php-sdk) and [`symfony/mcp-bundle`](https://github.com/symfony/mcp-bundle) expose JSON-RPC tools over HTTP. The SDK is an OAuth resource server at most: it validates Bearer tokens and may proxy to an upstream IdP. It will not issue tokens, run login or consent, or register clients. That is [explicitly out of scope](https://github.com/modelcontextprotocol/php-sdk/blob/main/adr/0001-oauth-authorization-server-out-of-scope.md).
- [`league/oauth2-server-bundle`](https://github.com/thephpleague/oauth2-server-bundle) (`^0.10 || ^1.2`) gives you `/authorize`, `/token`, PKCE, and JWT. It does not implement MCP discovery, CIMD, or resource indicators.

This bundle sits on top of both and adds RFC 8414 / 9728 discovery, CIMD, resource-bound tokens, RFC 9207 `iss`, and the WWW-Authenticate challenge that points clients at protected-resource metadata.

Install it next to mcp-bundle and League, set `login_route`, and clients can discover the authorization server, register via CIMD (or deprecated DCR), and call the MCP HTTP endpoint with a resource-bound Bearer token.

This bundle only touches MCP. Other routes and other League clients on the same authorization server are left alone. DCR still accepts public PKCE clients and confidential `client_secret_post` (Claude).

## Getting started

`composer require omouren/mcp-oauth-bundle` also installs mcp-bundle and League. You still configure those packages in your app.

Register the bundle and import its routes:

```php
// config/bundles.php
return [
    Omouren\McpOauthBundle\McpOauthBundle::class => ['all' => true],
];
```

```yaml
# config/routes.yaml
mcp_oauth:
    resource: '@McpOauthBundle/config/routes.yaml'

oauth2:
    resource: '@LeagueOAuth2ServerBundle/config/routes.php'   # 1.2+: config/routes.php ; 0.10: Resources/config/routes.php
    prefix: /oauth2   # must match mcp_oauth.authorization_prefix
```

That import covers well-known metadata, DCR `/register`, and consent. League `/authorize` and `/token` come from the `oauth2` import. If the prefix does not match `authorization_prefix`, RFC 8414 metadata advertises the wrong URLs.

Enable at least one MCP HTTP server. Those HTTP paths are the resources this bundle protects.

```yaml
# config/packages/mcp.yaml
mcp:
    servers:
        default:
            transports:
                http: true
            http:
                path: /_mcp   # keep this explicit: mcp-bundle 0.13+ defaults to /mcp/<name>
            registry: '*'
```

Point this bundle at your existing login (a Symfony route name, not a URL). `consent: auto` skips the consent page after login; the default `page` renders one at `{authorization_prefix}/consent`.

```yaml
# config/packages/mcp_oauth.yaml
mcp_oauth:
    login_route: app_login
    # consent: auto
```

The full option list is in [docs/configuration.md](docs/configuration.md).

Configure League yourself (keys, grants, scopes, persistence). Copy what you need:

```yaml
# config/packages/league_oauth2_server.yaml
league_oauth2_server:
    authorization_server:
        private_key: '%kernel.project_dir%/config/jwt/private.pem'
        encryption_key: '%env(OAUTH2_ENCRYPTION_KEY)%'
        enable_client_credentials_grant: false
        enable_password_grant: false
        enable_implicit_grant: false
        enable_auth_code_grant: true
        enable_refresh_token_grant: true
        require_code_challenge_for_public_clients: true
    resource_server:
        public_key: '%kernel.project_dir%/config/jwt/public.pem'
    scopes:
        available: [mcp]
        default: [mcp]
    persistence:
        doctrine:
            entity_manager: default
```

Keep `scopes.available` in sync with `mcp_oauth.scopes` (default `[mcp]`). RFC 8414 advertises `authorization_code` + `refresh_token` only: leave password / implicit / client_credentials off.

```bash
php bin/console league:oauth2-server:generate-keypair
```

If you use League's Doctrine persistence, run migrations for the `oauth2_*` tables.

Protect the MCP endpoint and leave token, register, and well-known public:

```yaml
# config/packages/security.yaml
security:
    firewalls:
        mcp:
            pattern: '^/_mcp'
            stateless: true
            oauth2: true
        oauth2_public:
            pattern: ^/(oauth2/(token|register)|\\.well-known)
            security: false
        main:
            pattern: ^/
            # your session login (form_login, access_token, …)

    access_control:
        - { path: '^/_mcp', roles: IS_AUTHENTICATED_FULLY }
        - { path: '^%mcp_oauth.authorization_prefix%/authorize', roles: PUBLIC_ACCESS }
        - { path: '^%mcp_oauth.authorization_prefix%/consent', roles: IS_AUTHENTICATED_REMEMBERED }
```

Behind a reverse proxy, set `mcp_oauth.public_base_url` to the public origin (and Symfony `trusted_proxies`) so issuer and resource URLs are not `http://127.0.0.1`.

## Isolation

Kernel listeners are registered globally, but they return immediately unless the request is MCP:

- exact `mcp.servers.*.http.path` (trailing slash allowed, not `/_mcp-admin`)
- exact `{authorization_prefix}/authorize` or `/token`, and the request targets MCP: RFC 8707 `resource` is the canonical MCP URI, or (if `resource` is absent) a `mcp_oauth.scopes` value is present

WWW-Authenticate and audience checks apply only to the MCP HTTP endpoint. Login redirect, `iss`, CIMD rewrite, and consent apply only to MCP authorize/token. Extra JWT `resource`/`aud` claims are added only when issuing an MCP token.

Well-known metadata (`/.well-known/oauth-authorization-server`, `/.well-known/oauth-protected-resource`) is mounted at the host root because RFC 8414 / 9728 require it. Those are this bundle's own routes.

If you share one League authorization server with non-MCP clients, do not put `mcp_oauth.scopes` in League `scopes.default`.

## Documentation

- [Option reference](docs/configuration.md)
- [RFC map](docs/rfc.md)
- [DCR deprecation](docs/deprecations.md)

## License

MIT
