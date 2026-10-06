# RFC map (MCP Authorization 2026-07-28)

Spec: [Authorization](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization), [Discovery](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization/authorization-server-discovery), [Client registration](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization/client-registration), [Security](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization/security-considerations).

| Spec | MCP | Where | Why |
|---|---|---|---|
| [OAuth 2.1](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1-13) + [RFC 7636](https://datatracker.ietf.org/doc/html/rfc7636) PKCE S256 | MUST (AS) | Advertised in AuthorizationServerMetadataController (`code_challenge_methods_supported`, grants). PkceListener rejects MCP authorize requests without an S256 `code_challenge`, also for confidential clients (League only requires PKCE for public clients and accepts `plain`). League grants are configured in the app (`league_oauth2_server`) | Clients refuse the authorization server if PKCE S256 is not advertised. Leave password, implicit, and client_credentials off in League. |
| [RFC 8414](https://datatracker.ietf.org/doc/html/rfc8414) | MUST (at least 8414 or OIDC Discovery) | `GET /.well-known/oauth-authorization-server` and the path-aware `/{path}` variant (same document). CORS `*` + Cache-Control | Clients discover authorize/token. The path-aware URL covers clients that append `/oauth2` from the authorize prefix. |
| [RFC 9728](https://datatracker.ietf.org/doc/html/rfc9728) | MUST (MCP server) | ProtectedResourceMetadataController, including `/.well-known/oauth-protected-resource/{path}`. CORS `*` | Clients find the authorization server via `authorization_servers` and the canonical `resource` URI. |
| [RFC 6750](https://datatracker.ietf.org/doc/html/rfc6750) + 9728 §5.1 | MUST Bearer; SHOULD `scope`/`error` on 401/403 | WwwAuthenticateListener, WwwAuthenticateHeader | 401 without a token points at `resource_metadata`. 401 with a Bearer adds `error=invalid_token`. 403 adds `error=insufficient_scope`. `Access-Control-Expose-Headers: WWW-Authenticate`. No `Mcp-Session-Id`. |
| [RFC 8707](https://datatracker.ietf.org/doc/html/rfc8707) | Clients MUST send `resource`; RS MUST check audience | AccessTokenAudienceListener (League 1.2+), AccessTokenRepositoryDecorator (League 0.10), ResourceAudienceListener, ResourceAudienceValidator | Bind the JWT to the MCP URL so a token for another API cannot be replayed here. |
| [RFC 9207](https://datatracker.ietf.org/doc/html/rfc9207) | SHOULD (AS; clients MUST validate) | AuthorizationResponseIssuer + IssuerParameterListener; metadata `authorization_response_iss_parameter_supported` | Mix-up defense: `iss` on authorize redirects (success and error). Applied to the Location header of any 3xx from `/authorize`. League converts PSR-7 302s into a generic Response, not RedirectResponse. |
| [CIMD](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-client-id-metadata-document-00) | SHOULD | ClientIdMetadataResolver + CimdRequestListener | HTTPS URL as `client_id`, domain allowlist, SSRF guard, and `client_id` must match the document URL. League's `oauth2_client.identifier` is VARCHAR(32), so the URL is hashed before League sees it. |
| [RFC 7591](https://datatracker.ietf.org/doc/html/rfc7591) | MAY, deprecated | DynamicClientRegistrationController | Back-compat with MCP before CIMD. `trigger_deprecation()` on every register. `application_type` is accepted and ignored (this is not an OIDC OP). |

## Out of scope

| Topic | Why |
|---|---|
| OpenID Connect Discovery (`/.well-known/openid-configuration`) | The AS MUST provide 8414 or OIDC; 8414 is enough. Clients may try OIDC if 8414 fails. |
| RFC 7662, mTLS, password, implicit, client_credentials | Not required, or forbidden by OAuth 2.1 for this profile. |
| MCP RPC (`server/discover`, `Mcp-Method`, `Mcp-Session-Id`) | Handled by symfony/mcp-bundle / the MCP SDK. The session header was removed in 2026-07-28. |
| [ext-auth extensions](https://github.com/modelcontextprotocol/ext-auth) | Optional, additive. |
| MCP client behavior (sending `resource`, validating `iss`) | This package is an AS + resource-server helper, not an MCP client. |
