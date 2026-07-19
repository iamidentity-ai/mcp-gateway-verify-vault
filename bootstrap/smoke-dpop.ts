/**
 * DPoP smoke: proves the tenant is ENFORCING, not just echoing.
 *
 * [1/2] POSITIVE through the running gateway: POST /tool (a tier-1 read),
 *       decode the OBO from the envelope's _diagnostic (requires the gateway
 *       to run with GATEWAY_DEBUG_OBO=true, a localhost-only affordance) and
 *       assert cnf.jkt is present.
 * [2/2] NEGATIVE direct to Verify: POST a proof-less token-exchange to
 *       /oauth2/token as the exchange client and assert HTTP 400 with
 *       CSIAQ5168E. Verify echoes cnf.jkt opportunistically whenever a proof
 *       IS sent (RFC 9449 section 5.2 allows it), so a positive check alone
 *       passes even with enforcement OFF. Only this negative probe proves the
 *       app requires proofs.
 *
 * Every positive assertion that proves a feature WORKS needs a paired
 * negative assertion that proves it is REQUIRED.
 */

function req(name: string): string {
  const v = process.env[name];
  if (!v) {
    console.error(`smoke-dpop: missing env ${name}`);
    process.exit(2);
  }
  return v;
}

const GATEWAY_URL = process.env['GATEWAY_URL'] || 'http://127.0.0.1:3014';
const VERIFY_TENANT_URL = req('VERIFY_TENANT_URL');
const CLIENT_ID = req('GATEWAY_EXCHANGE_CLIENT_ID');
const CLIENT_SECRET = req('GATEWAY_EXCHANGE_CLIENT_SECRET');
const SUBJECT = req('SMOKE_SUBJECT_TOKEN');
const TOOL = process.env['SMOKE_DPOP_TOOL'] || 'get_record';
const TOOL_ARGS = JSON.parse(process.env['SMOKE_DPOP_ARGS'] || '{"recordId":"REC-1001"}') as Record<string, unknown>;

function fail(msg: string): never {
  console.error(msg);
  process.exit(1);
}

function decodePayload(jwt: string): Record<string, unknown> {
  const parts = jwt.split('.');
  if (parts.length !== 3) fail(`smoke-dpop: OBO is not a JWT (${parts.length} segments)`);
  return JSON.parse(Buffer.from(parts[1]!, 'base64url').toString('utf8')) as Record<string, unknown>;
}

async function main(): Promise<void> {
  // [1/2] positive: the OBO the gateway minted is sender-constrained
  const toolRes = await fetch(`${GATEWAY_URL}/tool`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${SUBJECT}` },
    body: JSON.stringify({ name: TOOL, arguments: TOOL_ARGS }),
  });
  const envelope = (await toolRes.json()) as Record<string, any>;
  const obo: string | undefined = envelope?.['_diagnostic']?.obo ?? envelope?.['diag']?.obo;
  if (!obo) {
    fail(
      `[1/2] FAIL  no OBO in the /tool envelope (HTTP ${toolRes.status}). ` +
        `Run the gateway with GATEWAY_DEBUG_OBO=true (localhost only) and TOKEN_BINDING_MODE=outbound, ` +
        `and check the tool call itself succeeded: ${JSON.stringify(envelope).slice(0, 300)}`,
    );
  }
  const cnf = decodePayload(obo)['cnf'] as Record<string, unknown> | undefined;
  const jkt = typeof cnf?.['jkt'] === 'string' ? (cnf['jkt'] as string) : undefined;
  if (!jkt) {
    fail(
      '[1/2] FAIL  OBO has no cnf.jkt: Verify did not bind the token. ' +
        'Was bootstrap:verify re-run with ENABLE_DPOP=true, and is the gateway in TOKEN_BINDING_MODE=outbound?',
    );
  }
  console.log(`[1/2] PASS  OBO is sender-constrained, cnf.jkt=${jkt}`);

  // [2/2] negative: a proof-less token call must be REJECTED
  const res = await fetch(`${VERIFY_TENANT_URL}/oauth2/token`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      grant_type: 'urn:ietf:params:oauth:grant-type:token-exchange',
      client_id: CLIENT_ID,
      client_secret: CLIENT_SECRET,
      subject_token: SUBJECT,
      subject_token_type: 'urn:ietf:params:oauth:token-type:access_token',
      requested_token_type: 'urn:ietf:params:oauth:token-type:access_token',
      scope: 'records:read',
    }),
  });
  const body = await res.text();
  if (res.status === 400 && body.includes('CSIAQ5168E')) {
    console.log('[2/2] PASS  proof-less token call rejected with CSIAQ5168E: enforcement is ON');
    return;
  }
  if (res.ok) {
    fail(
      `[2/2] FAIL  Verify ACCEPTED a proof-less token call (HTTP ${res.status}). Enforcement is OFF ` +
        'even though cnf.jkt appears when proofs are sent. Re-run bootstrap:verify with ENABLE_DPOP=true ' +
        'and confirm the exchange app has dpopBoundAccessTokens as the STRING "true" (booleans are ignored).',
    );
  }
  fail(`[2/2] INCONCLUSIVE  HTTP ${res.status}: ${body.slice(0, 300)}`);
}

main().catch((err) => fail(`smoke-dpop: ${(err as Error).message}`));
