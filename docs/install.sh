#!/usr/bin/env bash
set -euo pipefail

DEFAULT_DIR="$HOME/.shellshield"
REPO_DIR=""

if [[ -n "${BASH_SOURCE[0]-}" && -f "${BASH_SOURCE[0]}" ]]; then
  REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
else
  REPO_DIR="$DEFAULT_DIR"
fi
HOOK_CMD="eval \"\$(bun run \"${REPO_DIR}/src/index.ts\" --init)\""
MARKER="# ShellShield"

if ! command -v bun >/dev/null 2>&1; then
  echo "Bun is required. Install with: curl -fsSL https://bun.sh/install | bash" >&2
  exit 1
fi

if ! command -v git >/dev/null 2>&1; then
  echo "Git is required. Install git and retry." >&2
  exit 1
fi

if [[ ! -d "$REPO_DIR/.git" ]]; then
  mkdir -p "$REPO_DIR"
  git clone https://github.com/hevlyo/ShellShield.git "$REPO_DIR" >/dev/null 2>&1
else
  git -C "$REPO_DIR" pull --ff-only >/dev/null 2>&1 || true
fi

if [[ -n "${ZSH_VERSION-}" ]]; then
  PROFILE="$HOME/.zshrc"
elif [[ -n "${BASH_VERSION-}" ]]; then
  PROFILE="$HOME/.bashrc"
else
  PROFILE="$HOME/.profile"
fi

touch "$PROFILE"

if grep -Fq "$MARKER" "$PROFILE"; then
  echo "ShellShield hook already present in $PROFILE"
  exit 0
fi

{
  echo ""
  echo "$MARKER"
  echo "$HOOK_CMD"
} >> "$PROFILE"

echo "ShellShield installed. Restart your shell or run:"
echo "  source \"$PROFILE\""
