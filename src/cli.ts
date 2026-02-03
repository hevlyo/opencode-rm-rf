import { checkDestructive } from "./parser/analyzer";
import { logAudit } from "./audit";
import { getConfiguration } from "./config";
import { ToolInput } from "./types";
import { createInterface } from "readline";
import { printStats } from "./stats";

async function promptConfirmation(command: string, reason: string): Promise<boolean> {
  if (!process.stdin.isTTY) return false;

  const rl = createInterface({
    input: process.stdin,
    output: process.stderr,
  });

  return new Promise((resolve) => {
    rl.question(
      `\n⚠️  ShellShield ALERT: ${reason}\n` +
      `   Command: ${command}\n` +
      `   Are you sure you want to execute this? [y/N] `,
      (answer) => {
        rl.close();
        resolve(answer.toLowerCase() === "y" || answer.toLowerCase() === "yes");
      }
    );
  });
}

export async function main(): Promise<void> {
  const args = process.argv.slice(2);
  const config = getConfiguration();

  if (process.env.SHELLSHIELD_SKIP === "1") {
    process.exit(0);
  }

  if (args.includes("--init")) {
    const shell = process.env.SHELL?.split("/").pop() || "bash";
    if (shell === "zsh") {
      console.log(`
# ShellShield Zsh Integration
_shellshield_preexec() {
    # Skip if SHELLSHIELD_SKIP is set
    if [[ -n "$SHELLSHIELD_SKIP" ]]; then return 0; fi
    # Run shellshield check
    "${process.argv[1]}" --check "$1" || return $?
}
autoload -Uz add-zsh-hook
add-zsh-hook preexec _shellshield_preexec
          `);
    } else {
      console.log(`
# ShellShield Bash Integration
_shellshield_bash_preexec() {
    if [[ -n "$SHELLSHIELD_SKIP" ]]; then return 0; fi
    "${process.argv[1]}" --check "$BASH_COMMAND" || return $?
}
trap '_shellshield_bash_preexec' DEBUG
          `);
    }
    process.exit(0);
  }

  if (args.includes("--stats")) {
    printStats();
    process.exit(0);
  }

  if (args.includes("--check")) {
    const cmdIdx = args.indexOf("--check");
    const command = args[cmdIdx + 1];
    if (!command) process.exit(0);

    const result = checkDestructive(command);
    if (result.blocked) {
      if (config.mode === "permissive") {
        console.error(
          `⚠️  ShellShield WARNING: Command '${command}' would be blocked in enforce mode.\n` +
            `Reason: ${result.reason}\n` +
            `Suggestion: ${result.suggestion}`
        );
        logAudit(command, { ...result, blocked: false });
        process.exit(0);
      }
      if (config.mode === "interactive") {
        const confirmed = await promptConfirmation(command, result.reason);
        if (confirmed) {
           logAudit(command, { ...result, blocked: false });
           process.exit(0);
        }
      }

      showBlockedMessage(result.reason, result.suggestion);
      process.exit(2);
    }
    process.exit(0);
  }

  try {
    const input = await Bun.stdin.text();
    if (!input) process.exit(0);

    let command = "";
    try {
      const data: ToolInput = JSON.parse(input);
      command = data.tool_input?.command ?? "";
    } catch {
      command = input.trim();
    }

    if (!command) {
      process.exit(0);
    }

    const result = checkDestructive(command);
    logAudit(command, result);

    if (result.blocked) {
      if (config.mode === "permissive") {
        console.error(
          `⚠️  ShellShield WARNING: Command would be blocked in enforce mode.\n` +
            `Reason: ${result.reason}\n` +
            `Suggestion: ${result.suggestion}`
        );
        process.exit(0);
      }

      if (config.mode === "interactive") {
        const confirmed = await promptConfirmation(command, result.reason);
        if (confirmed) {
           logAudit(command, { ...result, blocked: false });
           process.exit(0);
        }
      }

      showBlockedMessage(result.reason, result.suggestion);
      process.exit(2);
    }

    process.exit(0);
  } catch (error) {
    if (process.env.DEBUG) console.error(error);
    process.exit(0);
  }
}


function showBlockedMessage(reason: string, suggestion: string) {
  console.error(
    `🛡️  ShellShield BLOCKED: ${reason}\n` +
      `━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n` +
      `ACTION REQUIRED: ${suggestion}\n` +
      `━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n` +
      `Bypass: SHELLSHIELD_SKIP=1 <command>\n` +
      `ShellShield - Keeping your terminal safe.`
  );
}
