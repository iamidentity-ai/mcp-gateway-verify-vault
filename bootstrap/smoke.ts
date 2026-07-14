/**
 * bootstrap/smoke.ts — end-to-end proof against a RUNNING gateway.
 *
 *   GATEWAY_URL=http://127.0.0.1:3014 \
 *   SMOKE_SUBJECT_TOKEN=<a user access_token> \
 *   npm run smoke
 *
 * Exits non-zero if any assertion fails; prints a PASS/FAIL summary.
 *
 * ── How to get SMOKE_SUBJECT_TOKEN (a user access_token) ────────────────────
 * The gateway's subject_token is a normal user access_token from an OIDC login
 * on your tenant. This script does NOT try to log a user in programmatically
 * (that needs a browser + the user's factor). Grab one of:
 *   (a) Browser devtools: sign in to your UI, open Network, find a request the
 *       UI sends to the gateway (POST /tool) and copy the `Authorization:
 *       Bearer <...>` value — that IS the subject token.
 *   (b) ROPC, IF (and only if) you enabled the resource-owner-password grant on
 *       the UI app (off by default):
 *         curl -s -X POST "$VERIFY_TENANT_URL/v1.0/endpoint/default/token" \
 *           -d grant_type=password -d username=<u> -d password=<p> \
 *           -d client_id=<ui_client_id> -d client_secret=<ui_secret> \
 *           -d scope="openid records:read records:write" | jq -r .access_token
 * The token must belong to a user with a registered MFA (push) factor, or the
 * VIP step-up assertion below cannot park a real challenge.
 *
 * ── What it proves (positive AND negative) ──────────────────────────────────
 *   1. Tier-1 read on a NON-VIP id -> 200 ok + a real OBO + ephemeral cred.
 *   2. Read on a VIP id           -> 202 pending (step-up parked). The gateway
 *      DERIVES the VIP elevation (the caller never sends vip) and forces a push
 *      — a script can't tap a phone, so this asserts pending + a txId and tells
 *      you to approve manually to finish the flow.
 *   3. Tier-4 (delete)            -> 403 denied BEFORE Verify is contacted.
 *   4. Unknown tool               -> 403 denied (unknown_tool).
 */

const GATEWAY_URL = (process.env['GATEWAY_URL'] || 'http://127.0.0.1:3014').replace(/\/+$/, '');
const SUBJECT_TOKEN = process.env['SMOKE_SUBJECT_TOKEN'];
if (!SUBJECT_TOKEN) {
  console.error('Error: SMOKE_SUBJECT_TOKEN is required — see this script\'s header for how to obtain one.');
  process.exit(1);
}

// Seed ids (examples/db/seed.sql): REC-1001..1004 standard, REC-9001..9003 VIP.
const NONVIP_ID = process.env['SMOKE_NONVIP_ID'] || 'REC-1001';
const VIP_ID = process.env['SMOKE_VIP_ID'] || 'REC-9001';
const DELETE_ID = process.env['SMOKE_DELETE_ID'] || 'REC-1001';

interface ToolResponse {
  status: number;
  body: Record<string, unknown>;
}

async function callTool(name: string, args: Record<string, unknown>): Promise<ToolResponse> {
  const res = await fetch(`${GATEWAY_URL}/tool`, {
    method: 'POST',
    headers: { Authorization: `Bearer ${SUBJECT_TOKEN}`, 'Content-Type': 'application/json' },
    body: JSON.stringify({ name, arguments: args }),
  });
  const text = await res.text();
  let body: Record<string, unknown> = {};
  try {
    body = text ? (JSON.parse(text) as Record<string, unknown>) : {};
  } catch {
    body = { _raw: text.slice(0, 300) };
  }
  return { status: res.status, body };
}

interface Assertion {
  name: string;
  pass: boolean;
  detail: string;
}

const results: Assertion[] = [];
function record(name: string, pass: boolean, detail: string): void {
  results.push({ name, pass, detail });
  console.log(`${pass ? 'PASS' : 'FAIL'}  ${name} — ${detail}`);
}

async function assertTier1Read(): Promise<void> {
  const { status, body } = await callTool('get_record', { recordId: NONVIP_ID });
  const diag = (body['_diagnostic'] ?? {}) as Record<string, unknown>;
  // Proof the exchange + mint ran = the ephemeral Vault cred (you cannot mint
  // one without a valid OBO). The OBO's jti is shown for cross-system correlation.
  const hasCred = !!diag['cred'];
  // Security control: the raw OBO bearer token must NEVER be exposed to clients.
  const oboLeaked = 'obo' in diag;
  const pass = status === 200 && body['ok'] === true && hasCred && !oboLeaked;
  record(
    'tier-1 read (non-VIP) -> 200 ok + ephemeral cred, no raw OBO leak',
    pass,
    pass
      ? `200 ok; OBO jti=${String(diag['oboJti'] ?? 'n/a')}, cred path=${String((diag['cred'] as Record<string, unknown>)?.['path'] ?? 'n/a')}`
      : `got status=${status} ok=${String(body['ok'])} cred=${hasCred} oboLeaked=${oboLeaked} body=${JSON.stringify(body).slice(0, 200)}`,
  );
}

async function assertVipStepUp(): Promise<void> {
  const { status, body } = await callTool('get_record', { recordId: VIP_ID });
  const pass = status === 202 && body['pending'] === true && typeof body['txId'] === 'string';
  record(
    'VIP read -> 202 pending (gateway-forced step-up)',
    pass,
    pass
      ? `202 pending, txId=${String(body['txId'])} — APPROVE THE PUSH ON YOUR PHONE, then POST /hitl/complete {txId} to finish manually`
      : `got status=${status} pending=${String(body['pending'])} body=${JSON.stringify(body).slice(0, 200)}`,
  );
}

// A SIBLING read (detail) of the SAME VIP record must ALSO be gated — the
// gateway probes the parent record's VIP status via probeTool, so an agent
// cannot dodge the step-up by calling get_record_detail instead of get_record.
async function assertVipStepUpOnSiblingRead(): Promise<void> {
  const { status, body } = await callTool('get_record_detail', { recordId: VIP_ID });
  const pass = status === 202 && body['pending'] === true;
  record(
    'VIP DETAIL read (sibling tool) -> 202 pending (no VIP-bypass via a non-get_record tool)',
    pass,
    pass
      ? `202 pending — sibling reads are VIP-gated, not just get_record`
      : `LEAK? get_record_detail on a VIP id returned status=${status} pending=${String(body['pending'])} body=${JSON.stringify(body).slice(0, 200)}`,
  );
}

async function assertTier4Denied(): Promise<void> {
  const { status, body } = await callTool('delete_record', { recordId: DELETE_ID });
  const pass = status === 403 && body['denied'] === true && body['reason'] === 'policy_deny';
  record(
    'tier-4 delete -> 403 denied (blocked before Verify)',
    pass,
    pass ? `403 denied, reason=policy_deny` : `got status=${status} body=${JSON.stringify(body).slice(0, 200)}`,
  );
}

async function assertUnknownTool(): Promise<void> {
  const { status, body } = await callTool('this_tool_does_not_exist', {});
  const pass = status === 403 && body['denied'] === true && body['reason'] === 'unknown_tool';
  record(
    'unknown tool -> 403 denied (unknown_tool)',
    pass,
    pass ? `403 denied, reason=unknown_tool` : `got status=${status} body=${JSON.stringify(body).slice(0, 200)}`,
  );
}

async function main(): Promise<void> {
  console.log('══════════════════════════════════════════════════');
  console.log('  MCP Gateway — Smoke Test');
  console.log(`  Gateway: ${GATEWAY_URL}`);
  console.log('══════════════════════════════════════════════════\n');

  // Fail fast if the gateway isn't up.
  try {
    const health = await fetch(`${GATEWAY_URL}/healthz`);
    if (!health.ok) throw new Error(`healthz ${health.status}`);
  } catch (err) {
    console.error(`FATAL: gateway not reachable at ${GATEWAY_URL} (${(err as Error).message}). Start it first (npm run dev -w gateway).`);
    process.exit(1);
  }

  await assertTier1Read();
  await assertVipStepUp();
  await assertVipStepUpOnSiblingRead();
  await assertTier4Denied();
  await assertUnknownTool();

  const failed = results.filter((r) => !r.pass);
  console.log('\n══════════════════════════════════════════════════');
  console.log(`  ${results.length - failed.length}/${results.length} PASSED`);
  console.log('══════════════════════════════════════════════════');
  if (failed.length) {
    console.error(`FAILED: ${failed.map((f) => f.name).join('; ')}`);
    process.exit(1);
  }
  console.log('All assertions passed. (The VIP step-up is parked pending — approve it on your phone to see the full flow complete.)');
}

main().catch((err) => {
  console.error('\nFATAL:', (err as Error).message);
  process.exit(1);
});
