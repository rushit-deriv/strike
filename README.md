# Strike – Autonomous Penetration Testing Agent for VS Code

Strike is a specialized transformation of the Cline extension, reoriented from general-purpose coding into an elite penetration testing agent. It embeds a stealth-first doctrine, a recon→verify→exploit workflow, cost-aware context management, and continuous documentation.

- Focus: penetration testing, research, recon workflows, controlled exploitation, reporting
- Mindset: stealth, hypothesis-driven attacks, minimal PoC, audit trail
- UI: dark blue hacker aesthetic, “Strike” branding

## Key Capabilities

- Stealth-first recon and mapping (passive first, then low-and-slow active)
- Recon → Scanning/Fuzzing → Vulnerability Assessment → Exploitation → Reporting
- Continuous documentation to `docs/pentest/` (journal, attack-surface, findings, artifacts)
- Cost-efficient prompt context (rolling digests; artifacts referenced by path)
- Efficient browser/research usage
- Minimal Python PoCs (requests/asyncio/selenium) with safety switches

## Architecture Overview

```mermaid
flowchart TD
    subgraph VSCode Extension
      A[Controller] --> B[Task]
      B --> C[ToolExecutor]
      B --> D[ContextManager]
      C --> E[BrowserSession]
      C --> F[UrlContentFetcher]
      B --> G[API Provider]
      B --> H[MessageStateHandler]
    end

    subgraph Pentest Docs (Workspace)
      I[docs/pentest/journal.md]
      J[docs/pentest/attack-surface.md]
      K[docs/pentest/findings.md]
      L[docs/pentest/artifacts/*]
    end

    C -->|save artifacts / append journal| M[DocumentationService]
    M --> I
    M --> J
    M --> K
    M --> L

    D -. builds .-> N[Compact Context Digest]
    N -. appended .-> G

    F -->|markdown of target pages| L
```

## Files Touched (Core)

- `src/core/prompts/system.ts`: Strike doctrine, phased workflow, context usage, PoC guidance
- `src/core/prompts/model_prompts/claude4.ts`: Model-specific pentest prompt
- `src/core/pentest/DocumentationService.ts`: Creates/updates pentest docs; artifact saver; journaling API
- `src/core/context/context-management/ContextManager.ts`: Builds compact digest from pentest docs and appends to prompt
- `src/core/task/index.ts`: Injects digest into system prompt per request
- `src/core/task/ToolExecutor.ts`: On `web_fetch`, saves content as artifact, journals action, returns short summary with path

## Usage

1) Install and build the extension as with Cline.
2) Start a task like: “Map the attack surface for target X.”
3) Approve tool calls to let Strike:
   - Save large outputs as artifacts
   - Update attack surface and journal
   - Keep the LLM prompt lean with compact digests
4) For exploitation, generate minimal PoCs, review, and approve as appropriate.

## Roadmap (Selected)

- Phase awareness in state + “Active Hypotheses & Next Steps” injection
- Perplexity & GitHub research adapters
- Safe runners for nmap/masscan/amass/ffuf/nuclei/dalfox/sqlmap/hydra/nikto
- Summarizers for larger tool outputs; priority-based findings injection

## Licensing & Attribution

This repository is a derivative work of the Cline project. The upstream project’s license included in this repository is Apache License 2.0 (see `LICENSE`). In practical terms:

- Commercial use is permitted
- Attribution and inclusion of the original license are required
- No copyleft requirements (you may distribute derivatives under different terms, provided Apache 2.0 conditions are met)
- Fork-friendly and redistribution-friendly

Compliance steps for this repository:

- Retain the original `LICENSE` file (Apache 2.0) from Cline in the repository
- Preserve attribution in documentation (this README) and any NOTICE-equivalent files
- Maintain existing license notices in source files where present
- Add your own copyright notice for new code contributed under this repository

If your distribution adds additional components under different terms, clearly indicate the licensing for those components in their directories and in the documentation.

## License

Apache 2.0 — see `LICENSE`. Strike modifications are provided under the same license unless otherwise noted.
