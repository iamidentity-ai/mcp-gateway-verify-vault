# Diagrams

The five source diagrams for this project, as standalone [Mermaid](https://mermaid.js.org/)
`.mmd` files. Each is embedded inline (in a fenced `mermaid` block) wherever it is
referenced - the README and the concept pages - so you never have to leave the page to
see it. The `.mmd` files here are the single source: edit one place, paste it back into
the docs that embed it.

All five are rendered to the records example domain (the shipped `config/rar.json`). Point
the gateway at your own domain and the same shapes hold - only the labels change.

| File | Kind | What it shows | Referenced from |
|---|---|---|---|
| [`component-architecture.mmd`](component-architecture.mmd) | flowchart | The two MCP faces and the thin policy-enforcement point between them, plus the three external trust systems (IdP, Vault, CAEP transmitter). | [README](../../README.md#architecture) · [concepts/architecture](../concepts/architecture.md) |
| [`secured-tool-call.mmd`](secured-tool-call.mmd) | sequence | One tool call all the way through the six-step pipeline: introspect → gate → exchange+RAR → mint → upstream → revoke+audit. | [concepts/architecture](../concepts/architecture.md) · [concepts/token-exchange-and-rar](../concepts/token-exchange-and-rar.md) |
| [`elevated-discovery-stepup.mmd`](elevated-discovery-stepup.mmd) | sequence | The gateway-derived classification discovery probe and the policy-enforced step-up it forces - the agent cannot skip it. | [concepts/human-in-the-loop](../concepts/human-in-the-loop.md) |
| [`session-kill.mmd`](session-kill.mmd) | flowchart | The two-channel CAEP/SSF kill: three denials or one suspicious verdict → tenant-wide session revoke + local kill-gate. | [concepts/session-kill](../concepts/session-kill.md) |
| [`interchangeability.mmd`](interchangeability.mmd) | flowchart | The generic core vs. the five swappable per-domain surfaces - secure YOUR MCP by editing config, not code. | [README](../../README.md#secure-your-own-mcp) · [guides/bring-your-own-mcp](../guides/bring-your-own-mcp.md) |

## Rendering

GitHub, GitLab, and most Markdown viewers render fenced ` ```mermaid ` blocks natively -
nothing to install. To render the raw `.mmd` files to SVG/PNG locally:

```bash
npx -y @mermaid-js/mermaid-cli -i docs/diagrams/component-architecture.mmd -o out.svg
```

Every block is plain Mermaid with no theme directives, so it inherits the viewer's theme.
