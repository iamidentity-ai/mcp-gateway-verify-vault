# Rolling out DPoP token binding

Turn this on in stages. Each stage is independently verifiable, and the first two change nothing for your callers.

## Stage 1: bind the OBOs (outbound mode)

1. Re-run the Verify bootstrap with the flag:

   ```bash
   ENABLE_DPOP=true npm run bootstrap:verify
   ```

   This PUT rotates every app client secret it touches: the Token Exchange app, the Agent Identity app, and the UI app. Refresh all three after the run or the next call fails client authentication with `CSIAQ0155E` (a stale UI secret shows up as a login redirect loop). Read them without the Admin console via the admin API: `GET /v1.0/applications/{id}` returns `providers.oidc.properties.clientSecret`. Update `GATEWAY_EXCHANGE_CLIENT_SECRET` and `GATEWAY_AGENT_CLIENT_SECRET` in the gateway env, and `VERIFY_UI_CLIENT_SECRET` in any sign-in client. Or use `SECRETS_BACKEND=vault` so the gateway reads the live secret and nothing goes stale.

2. Restart the gateway with `TOKEN_BINDING_MODE=outbound`.

3. Prove it, both directions:

   ```bash
   npm run smoke:dpop
   ```

   `[1/2]` confirms OBOs carry `cnf.jkt`. `[2/2]` confirms a proof-less token call is rejected with `CSIAQ5168E`. If `[2/2]` fails, enforcement is off no matter what the app config page shows. The usual cause is a boolean where a string belongs; the bootstrap writes strings, a hand-edit may not have.

Callers are unaffected. Stop here if that is all you want; it already means a stolen gateway credential cannot run exchanges from another host.

## Stage 2: probe your tenant before full mode

Full mode needs user tokens to carry `cnf.jkt`, which means DPoP-binding the UI login app. Three behaviors vary by tenant configuration. Check all three BEFORE flipping anything, with a throwaway DPoP-bound user token (sign in through a DPoP-capable client such as gateway-agent-demo with `TOKEN_BINDING_MODE=dpop`).

**Probe A: does userinfo still accept the bound token as a plain bearer?**

```bash
curl -s -o /dev/null -w '%{http_code}\n' \
  -H "Authorization: Bearer $USER_TOKEN" \
  "$VERIFY_TENANT_URL/oauth2/userinfo"
```

Expect `200`. The gateway introspects by presenting the user token to userinfo without a proof (it cannot sign one; it does not hold the user's key). If your tenant returns `401` with `invalid_dpop_proof` here, STOP: full mode cannot work until the gateway's introspection is reworked to a client-credentialed introspect call. File that as an issue; do not enable full mode.

**Probe B: does token exchange accept a bound subject_token?**

Run any tier-1 tool through the gateway (outbound mode) while signed in with the bound user token. The exchange must return `ok`. The subject token rides in the form body, not the Authorization header, so this normally just works; confirm it on your tenant anyway.

**Probe C: does the step-up flow survive?**

Run one tier-2 write and approve the push. The challenge-token calls (factors, verification poll) present tokens at resource endpoints and are expected to pass unchanged. Confirm once.

## Stage 3: full mode

1. Bind the UI app: `ENABLE_DPOP=true ENABLE_DPOP_UI=true npm run bootstrap:verify`
2. Point a DPoP-capable client at the gateway. For gateway-agent-demo set `TOKEN_BINDING_MODE=dpop` in its environment. Users must sign in again (fresh tokens bind to the client's current key).
3. Set the gateway's `GATEWAY_PUBLIC_URL` to the URL callers actually use. Proofs bind to it; behind a tunnel the public hostname is the one that matters. The match is a byte-exact string compare of scheme, host, and path, so the client's base URL and `GATEWAY_PUBLIC_URL` must be the same string. `http://localhost:3014` and `http://127.0.0.1:3014` are different `htu` values even though they resolve to the same host, and a mismatch returns `401 htu_mismatch` on every call. In the local stack, point the demo's `GATEWAY_URL` and the gateway's `GATEWAY_PUBLIC_URL` at the same host string.
4. Restart the gateway with `TOKEN_BINDING_MODE=full`.
5. Verify enforcement with a bare replay: grab a live user token and

   ```bash
   curl -s -H "Authorization: Bearer $USER_TOKEN" \
     -H "Content-Type: application/json" \
     -d '{"name":"get_record","arguments":{"id":"REC-1001"}}' \
     "$GATEWAY_PUBLIC_URL/tool"
   ```

   Expect `401 {"error":"missing_dpop_proof"}`. The token alone, stolen from anywhere, no longer works.

## Operational notes

- **Client restarts sign users out.** The demo client keeps its key in memory. A restart mints a new key, and tokens bound to the old key stop validating. That is a re-login, not a bug. Persist the key if you need to survive restarts.
- **Clocks matter.** Proofs carry `iat` with a five-minute window on both Verify's side and the gateway's. Keep NTP healthy.
- **What stays uncovered.** The Vault leg does not enforce `cnf.jkt`; the OBO's short life, the single-use lease, and the SSF kill switch are the compensating controls. See [concepts/token-binding.md](../concepts/token-binding.md).
