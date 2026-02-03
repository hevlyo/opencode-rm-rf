#!/usr/bin/env bash
set -e

# Cores
RESET='\033[0m'
BOLD='\033[1m'
RED='\033[31m'
GREEN='\033[32m'
BLUE='\033[34m'
CYAN='\033[36m'

echo -e "${BLUE}${BOLD}"
echo "🛡️  ShellShield Installer"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo -e "${RESET}"

# 1. Verificar Dependências
echo -e "${CYAN}🔍 Checking requirements...${RESET}"

if ! command -v git >/dev/null 2>&1; then
  echo -e "${RED}❌ Git is required.${RESET}"
  echo "Please install git and try again."
  exit 1
fi

if ! command -v bun >/dev/null 2>&1; then
  echo -e "${RED}❌ Bun is required.${RESET}"
  echo "Please install bun: curl -fsSL https://bun.sh/install | bash"
  exit 1
fi

echo -e "${GREEN}✅ Dependencies found.${RESET}"

# 2. Clone/Update Repo
INSTALL_DIR="$HOME/.shellshield"
echo -e "\n${CYAN}📦 Installing to ${INSTALL_DIR}...${RESET}"

if [ -d "$INSTALL_DIR/.git" ]; then
  echo "Updating existing installation..."
  git -C "$INSTALL_DIR" fetch --quiet
  git -C "$INSTALL_DIR" reset --hard origin/main --quiet
elif [ -d "$INSTALL_DIR" ]; then
  echo "Directory $INSTALL_DIR exists but is not a git repo. Backing up..."
  mv "$INSTALL_DIR" "${INSTALL_DIR}.bak.$(date +%s)"
  git clone --depth 1 https://github.com/hevlyo/ShellShield.git "$INSTALL_DIR" --quiet
else
  git clone --depth 1 https://github.com/hevlyo/ShellShield.git "$INSTALL_DIR" --quiet
fi

# Instalar dependências do projeto
echo "Installing project dependencies..."
cd "$INSTALL_DIR"
bun install --production --silent

echo -e "${GREEN}✅ Installed successfully.${RESET}"

# 3. Configurar Shell
echo -e "\n${CYAN}🔌 Configuring shell integration...${RESET}"

# Detecta o shell do usuário (não o do script de instalação)
USER_SHELL=$(basename "$SHELL")
PROFILE=""

case "$USER_SHELL" in
  zsh)
    PROFILE="$HOME/.zshrc"
    ;;
  bash)
    # Preferência: .bashrc > .bash_profile
    if [ -f "$HOME/.bashrc" ]; then
      PROFILE="$HOME/.bashrc"
    else
      PROFILE="$HOME/.bash_profile"
    fi
    ;;
  *)
    echo -e "${RED}⚠️  Unsupported shell detected: $USER_SHELL${RESET}"
    echo "Please manually add the hook to your shell configuration."
    PROFILE="$HOME/.profile"
    ;;
esac

HOOK_SCRIPT='
# ShellShield Hook
if [ -f "$HOME/.shellshield/src/index.ts" ]; then
  eval "$(bun run "$HOME/.shellshield/src/index.ts" --init)"
fi
'

if [ -f "$PROFILE" ]; then
  if grep -q "ShellShield Hook" "$PROFILE"; then
    echo -e "Hook already present in ${BOLD}$PROFILE${RESET}"
  else
    echo "$HOOK_SCRIPT" >> "$PROFILE"
    echo -e "Hook added to ${BOLD}$PROFILE${RESET}"
  fi
else
  echo -e "${RED}⚠️  Could not find shell profile ($PROFILE).${RESET}"
  echo "Add this manually to your config:"
  echo "$HOOK_SCRIPT"
fi

echo -e "\n${GREEN}${BOLD}🎉 Done! Restart your shell to activate ShellShield.${RESET}"
echo -e "Try running: ${BOLD}rm -rf /${RESET} (it will be blocked)"

