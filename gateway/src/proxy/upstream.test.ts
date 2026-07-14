/**
 * Tests for proxy/upstream.ts — MCP proxy to the upstream naive MCP.
 *
 * NO live upstream is ever contacted: deps.clientFactory is the injection
 * seam that lets the test observe (a) the URL + headers the transport would
 * be built with, and (b) the tool name/arguments passed to callTool, and
 * (c) that whatever callTool resolves to is propagated back verbatim,
 * without constructing a real @modelcontextprotocol/sdk Client/transport.
 *
 * Coverage:
 *   - clientFactory is invoked with the resolved URL + headers carrying the
 *     OBO as `Authorization: Bearer <obo>` and `X-DB-Username`/`X-DB-Password`
 *   - callTool is invoked with { name, arguments }
 *   - the client is connected with the transport before callTool
 *   - the client is closed after the call (success and failure)
 *   - the resolved callTool() result is returned verbatim
 *   - the default URL is http://127.0.0.1:3015/mcp; UPSTREAM_MCP_URL
 *     env override and deps.url override both work
 */
import { describe, it, expect, vi, afterEach } from 'vitest';
import { callUpstreamTool } from './upstream.js';

function makeBundle(result: unknown) {
  const connect = vi.fn().mockResolvedValue(undefined);
  const callTool = vi.fn().mockResolvedValue(result);
  const close = vi.fn().mockResolvedValue(undefined);
  return { connect, callTool, close };
}

afterEach(() => {
  delete process.env.UPSTREAM_MCP_URL;
  vi.restoreAllMocks();
});

describe('callUpstreamTool', () => {
  it('builds the client via clientFactory with the OBO bearer + X-DB-Username/X-DB-Password headers, calls the tool, propagates the result', async () => {
    const toolResult = { content: [{ type: 'text', text: '{"ok":true}' }] };
    const { connect, callTool, close } = makeBundle(toolResult);
    const clientFactory = vi.fn().mockReturnValue({
      client: { connect, callTool, close },
      transport: { fake: 'transport' },
    });

    const result = await callUpstreamTool(
      {
        name: 'get_record',
        arguments: { recordId: 'REC-1001' },
        obo: 'obo-jwt-abc',
        dbUser: 'v-records-xyz',
        dbPass: 'p4ss',
      },
      { clientFactory },
    );

    expect(result).toBe(toolResult);

    expect(clientFactory).toHaveBeenCalledTimes(1);
    const [url, headers] = clientFactory.mock.calls[0] as [string, Record<string, string>];
    expect(url).toBe('http://127.0.0.1:3015/mcp');
    expect(headers['Authorization']).toBe('Bearer obo-jwt-abc');
    expect(headers['X-DB-Username']).toBe('v-records-xyz');
    expect(headers['X-DB-Password']).toBe('p4ss');

    expect(connect).toHaveBeenCalledTimes(1);
    expect(connect).toHaveBeenCalledWith({ fake: 'transport' });

    expect(callTool).toHaveBeenCalledTimes(1);
    expect(callTool).toHaveBeenCalledWith({
      name: 'get_record',
      arguments: { recordId: 'REC-1001' },
    });

    expect(close).toHaveBeenCalledTimes(1);
  });

  it('closes the client even when callTool throws, and rethrows', async () => {
    const connect = vi.fn().mockResolvedValue(undefined);
    const callTool = vi.fn().mockRejectedValue(new Error('upstream boom'));
    const close = vi.fn().mockResolvedValue(undefined);
    const clientFactory = vi.fn().mockReturnValue({
      client: { connect, callTool, close },
      transport: {},
    });

    await expect(
      callUpstreamTool(
        {
          name: 'delete_record',
          arguments: { recordId: 'REC-1007' },
          obo: 'obo-jwt',
          dbUser: 'u',
          dbPass: 'p',
        },
        { clientFactory },
      ),
    ).rejects.toThrow('upstream boom');

    expect(close).toHaveBeenCalledTimes(1);
  });

  it('uses deps.url override in preference to the default / env', async () => {
    const { connect, callTool, close } = makeBundle({ ok: true });
    const clientFactory = vi.fn().mockReturnValue({ client: { connect, callTool, close }, transport: {} });

    await callUpstreamTool(
      { name: 't', arguments: {}, obo: 'o', dbUser: 'u', dbPass: 'p' },
      { clientFactory, url: 'http://127.0.0.1:9999/mcp' },
    );

    const [url] = clientFactory.mock.calls[0] as [string, Record<string, string>];
    expect(url).toBe('http://127.0.0.1:9999/mcp');
  });

  it('honors UPSTREAM_MCP_URL env var when deps.url is not passed', async () => {
    process.env.UPSTREAM_MCP_URL = 'http://127.0.0.1:4321/mcp';
    const { connect, callTool, close } = makeBundle({ ok: true });
    const clientFactory = vi.fn().mockReturnValue({ client: { connect, callTool, close }, transport: {} });

    await callUpstreamTool(
      { name: 't', arguments: {}, obo: 'o', dbUser: 'u', dbPass: 'p' },
      { clientFactory },
    );

    const [url] = clientFactory.mock.calls[0] as [string, Record<string, string>];
    expect(url).toBe('http://127.0.0.1:4321/mcp');
  });

  it('without an injected clientFactory, constructs a real SDK Client + StreamableHTTPClientTransport (mocked at the module level) with requestInit.headers', async () => {
    const mockConnect = vi.fn().mockResolvedValue(undefined);
    const mockCallTool = vi.fn().mockResolvedValue({ content: [] });
    const mockClose = vi.fn().mockResolvedValue(undefined);

    vi.doMock('@modelcontextprotocol/sdk/client/index.js', () => ({
      Client: vi.fn().mockImplementation(() => ({
        connect: mockConnect,
        callTool: mockCallTool,
        close: mockClose,
      })),
    }));
    const transportCtor = vi.fn().mockImplementation(() => ({ kind: 'real-transport' }));
    vi.doMock('@modelcontextprotocol/sdk/client/streamableHttp.js', () => ({
      StreamableHTTPClientTransport: transportCtor,
    }));

    vi.resetModules();
    const { callUpstreamTool: freshCallUpstreamTool } = await import('./upstream.js');

    await freshCallUpstreamTool({
      name: 'get_record_history',
      arguments: { recordId: 'REC-1003' },
      obo: 'obo-real',
      dbUser: 'db-user',
      dbPass: 'db-pass',
    });

    expect(transportCtor).toHaveBeenCalledTimes(1);
    const [urlArg, optionsArg] = transportCtor.mock.calls[0] as [URL, { requestInit?: { headers?: Record<string, string> } }];
    expect(urlArg.toString()).toBe('http://127.0.0.1:3015/mcp');
    expect(optionsArg.requestInit?.headers).toMatchObject({
      Authorization: 'Bearer obo-real',
      'X-DB-Username': 'db-user',
      'X-DB-Password': 'db-pass',
    });

    expect(mockConnect).toHaveBeenCalledTimes(1);
    expect(mockCallTool).toHaveBeenCalledWith({
      name: 'get_record_history',
      arguments: { recordId: 'REC-1003' },
    });
    expect(mockClose).toHaveBeenCalledTimes(1);

    vi.doUnmock('@modelcontextprotocol/sdk/client/index.js');
    vi.doUnmock('@modelcontextprotocol/sdk/client/streamableHttp.js');
    vi.resetModules();
  });
});
