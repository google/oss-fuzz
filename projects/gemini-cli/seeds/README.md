Seed corpora for OSS-Fuzz (public-only)

This directory contains public, non-sensitive seed inputs used to bootstrap coverage for the fuzz targets in this project. All seeds must be derived from publicly available documentation or examples, and must not contain secrets, tokens, or data covered by VRP or private disclosures.

Structure:
- seeds/config/: JSON configuration examples aligned with docs/cli/configuration.md
- seeds/mcp/: MCP-style JSON-RPC request/response examples aligned with docs/tools/mcp-server.md

Provenance:
- All seeds are synthesized from public docs in https://github.com/google-gemini/gemini-cli and are safe for public distribution.

Notes:
- Keep seeds small and diverse; orient toward edge cases like empty structures, deeply nested objects, unexpected types, and boundary sizes.
- Do not include any private or VRP-related content.
