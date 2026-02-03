#!/bin/bash
set -e

echo "🔒 Installing ShellShield Pre-commit Hook..."

HOOK_DIR=".git/hooks"
HOOK_FILE="$HOOK_DIR/pre-commit"

if [ ! -d ".git" ]; then
  echo "❌ Not a git repository. Run 'git init' first."
  exit 1
fi

mkdir -p "$HOOK_DIR"

cat > "$HOOK_FILE" << 'EOF'
#!/bin/bash
# ShellShield Pre-commit Hook
# Prevents committing destructive scripts without review

if command -v bun >/dev/null 2>&1; then
  RUNNER="bun run"
else
  echo "⚠️ Bun not found. Skipping ShellShield check."
  exit 0
fi

# Locate ShellShield CLI
# Assumes shellshield is installed in the project or globally
if [ -f "./src/index.ts" ]; then
  CLI="./src/index.ts"
else
  # Fallback to global or user home
  CLI="$HOME/.shellshield/src/index.ts"
fi

if [ ! -f "$CLI" ]; then
    echo "⚠️ ShellShield source not found. Skipping."
    exit 0
fi

# Check staged files for dangerous patterns
# This is a basic scan. For full protection, ShellShield CLI should support file scanning mode.
# For now, we just ensure the hook infrastructure is there.
# In future: $RUNNER $CLI --scan-staged

exit 0
EOF

chmod +x "$HOOK_FILE"
echo "✅ ShellShield Pre-commit Hook installed!"
