# Benchmarking the gateway

A repeatable way to get a real before/after latency number, and to isolate the
effect of the introspection cache. No dependency is added to the repo - both
tools run via `npx`.

## What you are measuring

Every secured `/tool` call fans out to up to five external round-trips
(introspect -> token exchange -> Vault mint -> upstream MCP -> Vault revoke),
plus a Postgres connection in the naive upstream. **Total latency is dominated
by your Verify + Vault RTT**, not by gateway CPU - so measure against a real
tenant + Vault, and read the numbers as "what a caller experiences," not "gateway
overhead."

You need: the gateway running (`docker compose up` + bootstrap done), and one
user `access_token` from an OIDC login on your tenant (the same token the
quickstart uses). Export it:

```bash
export TOK="<user-access-token>"
export URL="http://127.0.0.1:3014/tool"
export BODY='{"name":"get_record","arguments":{"recordId":"REC-1001"}}'   # non-VIP: no push
```

## A/B: does the introspection cache help?

The clean experiment is to toggle only the cache and hold everything else
constant. `INTROSPECT_CACHE_TTL_MS=0` disables it; the default (15000) enables
it. Restart the gateway between runs.

```bash
# Run 1 - cache OFF (every call re-introspects against Verify)
INTROSPECT_CACHE_TTL_MS=0 <restart the gateway>          # e.g. set in ui/.env / compose env, then restart
npx autocannon -c 10 -d 15 -m POST \
  -H "Authorization: Bearer $TOK" -H 'Content-Type: application/json' \
  -b "$BODY" "$URL"

# Run 2 - cache ON (default 15s). Same load.
INTROSPECT_CACHE_TTL_MS=15000 <restart the gateway>
npx autocannon -c 10 -d 15 -m POST \
  -H "Authorization: Bearer $TOK" -H 'Content-Type: application/json' \
  -b "$BODY" "$URL"
```

Compare **req/sec** and **p50 / p99 latency** between the two runs. Because a
single caller reuses one token, the cache-ON run should serve introspection from
memory after the first hit, removing one Verify round-trip per call. The delta is
the introspection-cache win; everything else (exchange, mint, upstream, revoke)
is identical.

Notes:
- Use a **non-VIP** record id. A VIP id returns `202 pending` (a real push), which
  you cannot drive from a load test and which roughly doubles the round-trips.
- `autocannon` reports non-2xx separately - a spike there usually means the token
  expired mid-run; refresh `$TOK`.

## k6 variant (scripted assertions)

```javascript
// bench.js - run: npx --yes k6 run -e TOK="$TOK" bench.js
import http from 'k6/http';
import { check } from 'k6';

export const options = { vus: 10, duration: '15s' };

export default function () {
  const res = http.post(
    'http://127.0.0.1:3014/tool',
    JSON.stringify({ name: 'get_record', arguments: { recordId: 'REC-1001' } }),
    { headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${__ENV.TOK}` } },
  );
  check(res, { 'status 200': (r) => r.status === 200 });
}
```

k6 prints `http_req_duration` percentiles; run it once per cache setting and
compare the p50/p95.

## Reading the result honestly

- If Verify/Vault are a few ms away (same VPC), the cache saves a small slice; if
  Verify is a public-cloud hop, it saves a larger one. Either way it removes
  exactly **one** of the ~5 round-trips.
- The other agreed optimizations were assessed and NOT taken:
  **pool-by-dbUser** is a non-starter (per-call lease revocation makes every
  ephemeral `dbUser` unique, so a pool never gets reused - reusing it would mean
  reusing the lease, which defeats single-use dynamic credentials);
  **global McpServer reuse** is unsafe under concurrency (the server binds to one
  transport at a time), so only the zod-schema construction was hoisted to module
  load. Measure before optimizing further.
