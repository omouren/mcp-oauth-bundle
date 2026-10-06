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

    resource_indicators: true
    issuer_identification: true

    public_base_url: ~   # e.g. https://mcp.example.com
```

`authorization_prefix` must match the prefix you use to import League routes. `scopes` must stay in sync with League `scopes.available`. Behind a reverse proxy, set `public_base_url` to the public origin (and Symfony `trusted_proxies`).

HTTP paths come from mcp-bundle `mcp.servers.*.http.path` (not from this bundle). Every HTTP server is a protected resource. The firewall `pattern` is written in the app (`^/_mcp`, or a regex covering several paths).

## DCR client authentication

The deprecated DCR endpoint accepts both public and confidential clients:

- `token_endpoint_auth_method: none` creates a public PKCE client
- `token_endpoint_auth_method: client_secret_basic` or `client_secret_post` creates a confidential client and returns `client_secret` once in the registration response

League 0.10 stores that secret using its plaintext-compatible repository. League 1.2+ stores a password hash while the DCR response still returns the plain secret required by the client. League does not bind a client to one method: the token endpoint reads the secret from the `Authorization: Basic` header or from the request body, so both methods work for every confidential client.
