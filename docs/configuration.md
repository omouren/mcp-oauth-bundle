# Configuration reference

Install, League wiring, and `security.yaml` live in the [Getting started](../README.md#getting-started) section of the README. This page is the `mcp_oauth` option list.

## Options

| Key | Type | Default | Required |
|---|---|---|---|
| `authorization_prefix` | string | `/oauth2` | no |
| `scopes` | string[] | `[mcp]` | no |
| `login_route` | string | | yes |
| `redirect_query_param` | string | `_target_path` | no |
| `consent` | `page` or `auto` | `page` | no |
| `cimd.enabled` | bool | `true` | no |
| `cimd.trusted_domains` | string[] | claude.ai, vscode.dev, cursor.com | no |
| `dcr.enabled` | bool | `true` | no |
| `dcr.redirect_uri_schemes` | string[] | `[]` | no |
| `dcr.rate_limiter` | string or null | `null` | no |
| `resource_indicators` | bool | `true` | no |
| `issuer_identification` | bool | `true` | no |
| `public_base_url` | string or null | `null` | no |

```yaml
mcp_oauth:
    # Used in metadata URLs and this bundle's register/consent paths.
    # Import League authorize/token with the same prefix.
    authorization_prefix: /oauth2

    # Advertised scopes_supported, and the scopes that mark authorize/token as MCP when RFC 8707 resource is absent.
    scopes: [mcp]

    # Required. Symfony route name of your login page, not a URL.
    login_route: app_login

    # Query parameter on the login URL that receives the MCP authorize request URI.
    # Keep _target_path for Symfony form_login; change it if your login reads another name.
    redirect_query_param: _target_path

    # page = Twig consent; auto = approve after login.
    consent: page

    cimd:
        enabled: true
        trusted_domains:
            - claude.ai
            - vscode.dev
            - cursor.com

    dcr:
        enabled: true   # Deprecated; see docs/deprecations.md
        # Extra redirect URI schemes for native apps (RFC 8252), e.g. com.example.app.
        # https and loopback http (127.0.0.1, [::1], localhost) are always accepted.
        redirect_uri_schemes: []
        # Name of a framework.rate_limiter limiter, applied per client IP.
        rate_limiter: ~

    resource_indicators: true
    issuer_identification: true

    public_base_url: ~   # e.g. https://mcp.example.com
```

`authorization_prefix` must match the prefix you use to import League routes. `scopes` must stay in sync with League `scopes.available`. Behind a reverse proxy, set `public_base_url` to the public origin (and Symfony `trusted_proxies`).

HTTP paths come from mcp-bundle `mcp.servers.*.http.path` (not from this bundle). Every HTTP server is a protected resource. The firewall `pattern` is written in the app (`^/_mcp`, or a regex covering several paths).

## DCR hardening

The register endpoint is public, so it only accepts:

- redirect URIs using `https`, loopback `http` (`127.0.0.1`, `[::1]`, `localhost`) or a scheme listed in `dcr.redirect_uri_schemes`; never `javascript:`, `data:`, `file:`, URIs with a fragment or with user info
- at most 10 redirect URIs of at most 2000 characters each
- a `client_name` of at most 200 characters without control characters
- a `scope` of at most 1000 characters (or 50 entries)
- a request body of at most 16 KB

To rate limit registrations per client IP, install `symfony/rate-limiter`, define a limiter and reference it by name:

```yaml
framework:
    rate_limiter:
        mcp_oauth_register:
            policy: sliding_window
            limit: 10
            interval: '1 hour'

mcp_oauth:
    dcr:
        rate_limiter: mcp_oauth_register
```

Over the limit, the endpoint returns `429` with a `Retry-After` header. The limiter keys on `Request::getClientIp()`, so configure Symfony `trusted_proxies` behind a reverse proxy; otherwise every client shares the proxy IP.

## DCR client authentication

The deprecated DCR endpoint accepts both public and confidential clients:

- `token_endpoint_auth_method: none` creates a public PKCE client
- `token_endpoint_auth_method: client_secret_post` creates a confidential client and returns `client_secret` once in the registration response

League 0.10 stores that secret using its plaintext-compatible repository. League 1.2+ stores a password hash while the DCR response still returns the plain secret required by the client. The token endpoint also supports `client_secret_basic` for already registered confidential clients.
