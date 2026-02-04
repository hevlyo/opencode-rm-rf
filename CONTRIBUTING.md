# Contributing

Thanks for helping improve ShellShield.

## Quick Start

1. Install dependencies:
   - `bun install`
2. Run tests:
   - `bun test`
3. Run locally:
   - `bun run src/index.ts --check "rm -rf /"`

## Adding a New Rule

1. Create a class in `src/parser/rules/` that implements `SecurityRule`.
2. Add TSDoc explaining the threat and rationale.
3. Add tests under `tests/`.
4. Run `bun test`.

## Code Style

- Keep logic small and composable.
- Prefer adding a focused rule over a large monolithic check.
- Add tests for false positives and false negatives.

