# 🛡️ ShellShield

<p align="center">
  <strong>The ultimate safety shield for your terminal. Stop accidental destruction, before it happens.</strong>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Bun-1.0+-black?style=for-the-badge&logo=bun" alt="Bun">
  <img src="https://img.shields.io/badge/Security-Hardened-red?style=for-the-badge" alt="Security Hardened">
  <img src="https://img.shields.io/badge/License-MIT-blue?style=for-the-badge" alt="License MIT">
</p>

---

## 🧐 Why ShellShield?

We've all been there. A misplaced space in `rm -rf / tmp/`, a copy-paste from a malicious site, or a `curl | bash` that looked safe but used a **Cyrillic 'і'** instead of a Latin 'i'. 

**Your browser catches these attacks. Your terminal doesn't. ShellShield does.**

ShellShield is a high-performance, intelligent shell hook that guards your gate. It tokenizes every command using a real shell parser to intercept destructive actions, homograph attacks, and terminal injections before they execute.

---

## ✨ Features that Make You Unstoppable

### 🛡️ Intelligent Destruction Blocking
-   **Context-Aware**: Uses `shell-quote` to understand if `rm` is a command or just a string in `grep`.
-   **Recursive Analysis**: Dives deep into subshells (`sh -c "..."`) up to 5 levels.
-   **Smart Suggestions**: Blocks `rm -rf folder/` and suggests `trash folder/` automatically.
-   **Critical Path Guard**: Prevents `mv`, `cp`, or `rm` from modifying critical system paths like `/etc`, `/usr`, `/`, or `C:\Windows`.

### 🔐 Advanced Security Guard
-   **Interpreter RCE Defense**: Blocks remote code execution in `python`, `node`, `ruby`, `perl`, `php` (e.g., `python -c "$(curl ...)"`).
-   **Homograph Defense**: Blocks visually identical malicious domains (e.g., `іnstall.com` vs `install.com`).
-   **Injection Protection**: Intercepts ANSI escapes and hidden zero-width characters that manipulate your terminal output.
-   **Safe Pipe-to-Shell**: Flags dangerous `curl | bash` patterns, while allowing trusted domains (GitHub, Docker, etc.).
-   **Encoded Payload Guard**: Blocks `base64 -d | sh` and `xxd -r -p | sh` patterns.
-   **Credential Guard**: Detects and blocks commands containing plain-text passwords in URLs.

### 🚜 Terminal Governance
-   **Git Workflow Safety**: Prevents deleting files with uncommitted changes.
-   **Volume Threshold**: Intercepts accidental globs that target hundreds of files at once.
-   **Permissive Mode**: Optional "log-only" mode for non-blocking audits.
-   **Rotated Audit Log**: Keeps a scalable JSON trace of every blocked action in `~/.shellshield/audit.log` (auto-rotated at 1MB).

---

## 🚀 Quick Start

### 1. Install Bun
```bash
curl -fsSL https://bun.sh/install | bash
```

### 2. One‑command install (recommended)
```bash
curl -fsSL https://hevlyo.github.io/ShellShield/install.sh | bash
```

This installs ShellShield into `~/.shellshield` and wires your shell profile automatically.

### 3. OpenCode Integration (Optional)
Add as a `PreToolUse` hook in your `.opencode/settings.json`:
```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash",
        "hooks": [
          {
            "type": "command",
            "command": "bun run /path/to/shellshield/src/index.ts"
          }
        ]
      }
    ]
  }
}
```

---

## ⚙️ Configuration (Optional)

ShellShield works out of the box. The `.shellshield.json` file is **optional** and only needed for customization (home or project directory):

```json
{
  "blocked": ["rm", "shred", "custom-killer"],
  "allowed": ["ls", "cat"],
  "trustedDomains": ["my-company.com", "github.com"],
  "threshold": 100,
  "mode": "enforce"
}
```

### Modes
- `"mode": "enforce"` (Default): Blocks dangerous commands immediately.
- `"mode": "permissive"`: Logs warnings but **allows** execution. Useful for testing or CI environments.

### Environment Variables
- `SHELLSHIELD_THRESHOLD`: Max files per delete (Default: 50).
- `SHELLSHIELD_MODE`: Set to `permissive` to disable blocking globally.
- `SHELLSHIELD_SKIP=1`: Temporarily bypass all checks for the next command.

---

## 🛠️ Development & Testing

ShellShield is built with **TDD (Test-Driven Development)**. We have **90+ test cases** covering bypasses, security threats, and edge cases.

```bash
bun test
```

---

## 🤝 Credits & Inspiration
Originally inspired by the [claude-rm-rf](https://github.com/zcaceres/claude-rm-rf) project by Zach Caceres. Evolved into a complete security suite.

---
<p align="center">🛡️ Built for those who roll the boulder every day. Ship safe.</p>
