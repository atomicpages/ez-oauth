# Development Workflow

Commands

- Install: `bun install`
- Tests: `bun test`
- Run scripts: `bun run <script>`

Formatting and linting

- Biome configuration in `biome.json` (tabs, double quotes).
- Keep edits compatible with Biome defaults; do not add alternate formatters.

TypeScript

- `tsconfig.json` uses strict mode and bundler module resolution; avoid
  Node-specific APIs when possible.
