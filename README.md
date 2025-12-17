# Block Destructive Commands

A Claude Code hook that blocks destructive file deletion commands (`rm`, `shred`, `unlink`) and directs users to use `trash` instead. This ensures deleted files can be recovered from the system trash.

## Blocked Commands

- `rm` / `rm -rf` / `rm -f`
- `shred`
- `unlink`

## Allowed Commands

- `git rm` (tracked by git, recoverable)
- All other commands

## Installation

### Prerequisites

Install the `trash` CLI for recoverable file deletion:

```bash
# macOS
brew install trash

# Linux / npm (cross-platform)
npm install -g trash-cli
```

### Build the Hook

```bash
# Install dependencies
bun install

# Build standalone executable (no Bun required to run)
bun run build
```

The compiled binary will be at `dist/block-destructive-commands`.

### Configure Claude Code

Add to your `.claude/settings.json` or `.claude/settings.local.json`:

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash",
        "hooks": [
          {
            "type": "command",
            "command": "$CLAUDE_PROJECT_DIR/dist/block-destructive-commands"
          }
        ]
      }
    ]
  }
}
```

## Development

```bash
# Run tests
bun test

# Build for current platform
bun run build

# Build for all platforms
bun run build:all
```

### Cross-Platform Builds

```bash
bun run build:linux   # Linux x64
bun run build:macos   # macOS ARM64
bun run build:windows # Windows x64
```

## How It Works

The hook runs on every `Bash` tool call via the `PreToolUse` event:

1. Parses JSON input from Claude Code (stdin)
2. Strips quoted strings to avoid false positives (e.g., `echo 'rm test'`)
3. Checks for destructive patterns at command start or after shell operators (`&&`, `||`, `;`, `|`)
4. Returns exit code 2 with error message if blocked
5. Returns exit code 0 to allow the command

### Pattern Detection

The hook detects destructive commands:
- At the start of a command
- After shell operators (`&&`, `||`, `;`, `|`, `$(`, `` ` ``)
- After `sudo` or `xargs`

Safe patterns like `git rm` are explicitly allowed.
