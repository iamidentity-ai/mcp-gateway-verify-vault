# GitHub MCP upstream config (Phase 1, flavor B - no DB)

Fronts `github/github-mcp-server` (a SaaS MCP with its own API credential).
No-DB (`UPSTREAM_DB_BACKED=false`, actions have no credsPath) and `upstream_token`
auth mode (`UPSTREAM_AUTH_MODE=upstream_token`, `UPSTREAM_AUTH_TOKEN=<raw GitHub PAT>`)
so the Verify OBO is relocated to `X-Verify-OBO` and the PAT rides `Authorization`.

- get_me / list_issues: tier 1 (Token Exchange only, no push)
- add_issue_comment: tier 2 (one Verify MFA push, then /hitl/complete posts it)

Run: `GATEWAY_CONFIG_DIR=examples/upstreams/github UPSTREAM_DB_BACKED=false \
      UPSTREAM_AUTH_MODE=upstream_token UPSTREAM_AUTH_TOKEN=<pat> ...`
