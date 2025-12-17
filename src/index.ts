#!/usr/bin/env bun
/**
 * Block destructive file deletion commands and suggest using trash instead.
 * This is a Claude Code hook that runs on PreToolUse for Bash commands.
 */

interface ToolInput {
  tool_input?: {
    command?: string;
  };
}

/**
 * Remove quoted strings to avoid false positives on commands like echo 'rm test'.
 */
function stripQuotes(command: string): string {
  // Remove double-quoted strings (handles escapes)
  let stripped = command.replace(/"(?:[^"\\]|\\.)*"/g, '""');
  // Remove single-quoted strings (no escapes in single quotes)
  stripped = stripped.replace(/'[^']*'/g, "''");
  return stripped;
}

/**
 * Check if command contains actual destructive commands (not in quotes).
 */
function containsDestructiveCommand(command: string): boolean {
  const stripped = stripQuotes(command);

  // Check for safe patterns first (git rm is fine)
  if (/\bgit\s+rm\b/.test(stripped)) {
    return false;
  }

  // Patterns that indicate rm/shred/unlink being used as actual commands:
  // - At start of command
  // - After shell operators: &&, ||, ;, |, $(, `
  // - After sudo or xargs
  const destructivePatterns = [
    /(?:^|&&|\|\||;|\||\$\(|`)\s*rm\b/,
    /(?:^|&&|\|\||;|\||\$\(|`)\s*shred\b/,
    /(?:^|&&|\|\||;|\||\$\(|`)\s*unlink\b/,
    /\bsudo\s+rm\b/,
    /\bxargs\s+rm\b/,
  ];

  return destructivePatterns.some((pattern) => pattern.test(stripped));
}

async function main(): Promise<void> {
  try {
    const input = await Bun.stdin.text();
    const data: ToolInput = JSON.parse(input);
    const command = data.tool_input?.command ?? "";

    if (!command) {
      process.exit(0);
    }

    if (containsDestructiveCommand(command)) {
      console.error(
        "BLOCKED: Do not use destructive file deletion commands " +
          "(rm, shred, unlink). Use the 'trash' CLI instead:\n" +
          "  - trash file.txt\n" +
          "  - trash directory/\n\n" +
          "If trash is not installed:\n" +
          "  - macOS: brew install trash\n" +
          "  - Linux/npm: npm install -g trash-cli"
      );
      process.exit(2);
    }

    process.exit(0);
  } catch {
    // Parse errors allow through (match Python behavior)
    process.exit(0);
  }
}

main();
