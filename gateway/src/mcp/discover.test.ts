/**
 * Tests for mcp/discover.ts — the `server/discover` pre-handler that lets a
 * 2026-07-28 client learn this gateway's real (legacy) protocol surface
 * instead of getting the SDK's `-32601 Method not found`.
 *
 * Coverage: isDiscoverRequest's request-shape gate (string/numeric id,
 * notification-no-id falls through, wrong method, arrays, non-objects,
 * missing/wrong jsonrpc version), and buildDiscoverResult's normative result
 * shape (resultType, a non-empty supportedVersions that excludes
 * '2026-07-28', capabilities, echoed serverInfo under the
 * io.modelcontextprotocol/serverInfo _meta key, instructions, ttlMs,
 * cacheScope).
 */
import { describe, it, expect } from 'vitest';
import { isDiscoverRequest, buildDiscoverResult } from './discover.js';

describe('isDiscoverRequest', () => {
  it('accepts a well-formed discover request with a string id', () => {
    expect(isDiscoverRequest({ jsonrpc: '2.0', id: 'd1', method: 'server/discover', params: {} })).toBe(true);
  });

  it('accepts a well-formed discover request with a numeric id', () => {
    expect(isDiscoverRequest({ jsonrpc: '2.0', id: 1, method: 'server/discover' })).toBe(true);
  });

  it('rejects a discover notification (no id) — not a request, falls through to the SDK', () => {
    expect(isDiscoverRequest({ jsonrpc: '2.0', method: 'server/discover' })).toBe(false);
  });

  it('rejects a body with a different method', () => {
    expect(isDiscoverRequest({ jsonrpc: '2.0', id: 1, method: 'tools/list' })).toBe(false);
  });

  it('rejects an array body (batch request)', () => {
    expect(isDiscoverRequest([{ jsonrpc: '2.0', id: 1, method: 'server/discover' }])).toBe(false);
  });

  it('rejects non-object bodies', () => {
    expect(isDiscoverRequest(null)).toBe(false);
    expect(isDiscoverRequest(undefined)).toBe(false);
    expect(isDiscoverRequest('server/discover')).toBe(false);
    expect(isDiscoverRequest(42)).toBe(false);
  });

  it('rejects an id that is neither a string nor a number', () => {
    expect(isDiscoverRequest({ jsonrpc: '2.0', id: null, method: 'server/discover' })).toBe(false);
    expect(isDiscoverRequest({ jsonrpc: '2.0', id: {}, method: 'server/discover' })).toBe(false);
  });

  it('rejects a body with no jsonrpc field at all, even with a correct method and id', () => {
    expect(isDiscoverRequest({ id: 1, method: 'server/discover' })).toBe(false);
  });

  it('rejects a body whose jsonrpc field is not exactly "2.0"', () => {
    expect(isDiscoverRequest({ jsonrpc: '1.0', id: 1, method: 'server/discover' })).toBe(false);
  });
});

describe('buildDiscoverResult', () => {
  const serverInfo = { name: 'test-gateway', version: '0.1.0' };
  const result = buildDiscoverResult(serverInfo);

  it('reports resultType: complete', () => {
    expect(result.resultType).toBe('complete');
  });

  it('reports a non-empty supportedVersions that does NOT include 2026-07-28', () => {
    expect(Array.isArray(result.supportedVersions)).toBe(true);
    expect(result.supportedVersions.length).toBeGreaterThan(0);
    expect(result.supportedVersions).not.toContain('2026-07-28');
  });

  it('reports tools-only capabilities (no resources/prompts)', () => {
    expect(result.capabilities).toEqual({ tools: {} });
  });

  it('echoes the given serverInfo under the io.modelcontextprotocol/serverInfo _meta key', () => {
    expect(result._meta).toEqual({ 'io.modelcontextprotocol/serverInfo': serverInfo });
  });

  it('reports the fixed cache/ttl fields', () => {
    expect(result.ttlMs).toBe(3600000);
    expect(result.cacheScope).toBe('public');
  });

  it('reports non-empty instructions describing the identity-aware behavior', () => {
    expect(typeof result.instructions).toBe('string');
    expect(result.instructions.length).toBeGreaterThan(0);
  });
});
