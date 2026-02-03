#!/usr/bin/env bun
import { parse } from "shell-quote";
import { execSync } from "child_process";
import { appendFileSync, mkdirSync, existsSync } from "fs";
import { join, dirname, basename } from "path";
import { homedir } from "os";

interface ToolInput {
  tool_input?: {
    command?: string;
  };
}

const DEFAULT_BLOCKED = new Set(["rm", "shred", "unlink", "wipe", "srm"]);
const SHELL_COMMANDS = new Set(["sh", "bash", "zsh", "dash"]);
const CRITICAL_PATHS = new Set([
    "/", "/etc", "/usr", "/var", "/bin", "/sbin", "/lib", "/boot", "/root", "/dev", "/proc", "/sys"
]);
const SENSITIVE_PATTERNS = [
    /\/\.ssh\//,
    /\/\.bashrc$/,
    /\/\.zshrc$/,
    /\/\.profile$/,
    /\/\.gitconfig$/
];
const VOLUME_THRESHOLD = parseInt(process.env.SHELLSHIELD_THRESHOLD || "50", 10);

function isCriticalPath(path: string): boolean {
    if (path === "/") return true;
    const normalized = path.replace(/\/+$/, "");
    if (CRITICAL_PATHS.has(normalized)) return true;
    if (normalized === ".git" || normalized.endsWith("/.git")) return true;
    return false;
}

function isSensitivePath(path: string): boolean {
    const normalized = path.replace(/\/+$/, "");
    let fullPath = normalized;
    if (normalized.startsWith("~")) {
        const home = homedir();
        fullPath = normalized.replace("~", home);
    }
    for (const pattern of SENSITIVE_PATTERNS) {
        if (pattern.test(fullPath)) return true;
    }
    return false;
}

function hasHomograph(str: string): { detected: boolean; char?: string } {
    for (const char of str) {
        const code = char.charCodeAt(0);
        const isHidden = /[\u200B-\u200D\uFEFF]/.test(char);
        if (code > 127 && !isHidden) {
            return { detected: true, char };
        }
    }
    return { detected: false };
}

function hasTerminalInjection(str: string): boolean {
    const injectionPatterns = [
        /\x1b\[/, 
        /\u200B/, 
        /\u200C/, 
        /\u200D/, 
        /\uFEFF/  
    ];
    return injectionPatterns.some(p => p.test(str));
}

interface TerminalInjectionResult {
    detected: boolean;
    reason?: string;
}

function checkTerminalInjection(str: string): TerminalInjectionResult {
    if (/\x1b\[/.test(str)) {
        return { detected: true, reason: "TERMINAL INJECTION DETECTED" };
    }
    if (/[\u200B-\u200D\uFEFF]/.test(str)) {
        return { detected: true, reason: "HIDDEN CHARACTERS DETECTED" };
    }
    return { detected: false };
}

function getConfiguration() {
    const blocked = new Set(DEFAULT_BLOCKED);
    const allowed = new Set<string>();

    if (process.env.OPENCODE_BLOCK_COMMANDS) {
        process.env.OPENCODE_BLOCK_COMMANDS.split(",").forEach(cmd => blocked.add(cmd.trim().toLowerCase()));
    }

    if (process.env.OPENCODE_ALLOW_COMMANDS) {
        process.env.OPENCODE_ALLOW_COMMANDS.split(",").forEach(cmd => allowed.add(cmd.trim().toLowerCase()));
    }

    return { blocked, allowed };
}

interface BlockResult {
  blocked: boolean;
  reason?: string;
  suggestion?: string;
}

function hasUncommittedChanges(files: string[]): string[] {
    try {
        const results: string[] = [];
        for (const file of files) {
            if (file.startsWith("-")) continue;
            try {
                const isAbsolute = file.startsWith("/");
                const dir = isAbsolute ? dirname(file) : ".";
                const name = isAbsolute ? basename(file) : file;
                const status = execSync(`git -C "${dir}" status --porcelain "${name}" 2>/dev/null`, { encoding: "utf8" }).trim();
                if (status) results.push(file);
            } catch {
            }
        }
        return results;
    } catch {
        return [];
    }
}

function logAudit(command: string, result: BlockResult) {
    try {
        const auditDir = join(homedir(), ".shellshield");
        if (!existsSync(auditDir)) mkdirSync(auditDir, { recursive: true });
        const logPath = join(auditDir, "audit.log");
        const entry = {
            timestamp: new Date().toISOString(),
            command,
            blocked: result.blocked,
            reason: result.reason,
            cwd: process.cwd()
        };
        appendFileSync(logPath, JSON.stringify(entry) + "\n");
    } catch (e) {
    }
}

function checkDestructive(command: string, depth = 0): BlockResult {
  if (depth > 5) return { blocked: false };

  const homographRaw = hasHomograph(command);
  if (homographRaw.detected) {
      return { blocked: true, reason: "HOMOGRAPH ATTACK DETECTED", suggestion: `Suspicious character found: ${homographRaw.char}. This may be a visually similar domain masking a malicious source.` };
  }
  const injection = checkTerminalInjection(command);
  if (injection.detected) {
      return { blocked: true, reason: injection.reason!, suggestion: "Command contains ANSI escape sequences or hidden characters that can manipulate terminal output." };
  }

  const { blocked: configBlocked, allowed: configAllowed } = getConfiguration();
  const vars: Record<string, string> = {};
  
  const entries = parse(command, (key) => {
      return vars[key] || `$${key}`;
  });
  
  let nextMustBeCommand = true;

  for (let i = 0; i < entries.length; i++) {
    const entry = entries[i];

    if (typeof entry !== "string") {
        if (typeof entry === "object" && "op" in entry) {
            if (entry.op === "<(") {
                 if (i + 1 < entries.length) {
                     const next = entries[i + 1];
                     if (typeof next === "string" && (next === "curl" || next === "wget")) {
                         return { blocked: true, reason: "PROCESS SUBSTITUTION DETECTED", suggestion: "Executing remote scripts via process substitution is dangerous." };
                     }
                 }
            }
            nextMustBeCommand = true;
        }
        continue;
    }

    if (!nextMustBeCommand) {
        if (entry.includes("=") && !entry.startsWith("-")) {
            const [key, ...valParts] = entry.split("=");
            if (/^[a-zA-Z_][a-zA-Z0-9_]*$/.test(key)) {
                vars[key] = valParts.join("=");
            }
        }
        
        if ((entry === "-o" || entry === "-O" || entry === "--output") && i + 1 < entries.length) {
            const outputPath = entries[i + 1];
            if (typeof outputPath === "string" && isSensitivePath(outputPath)) {
                return { blocked: true, reason: "SENSITIVE PATH TARGETED", suggestion: `Command is attempting to write directly to a critical configuration file: ${outputPath}` };
            }
        }
        continue;
    }

    nextMustBeCommand = false;

    if (entry.includes("=") && !entry.startsWith("-")) {
        const [key, ...valParts] = entry.split("=");
        if (/^[a-zA-Z_][a-zA-Z0-9_]*$/.test(key)) {
            vars[key] = valParts.join("=");
        }
        nextMustBeCommand = true;
        continue;
    }

    const normalizedEntry = entry.toLowerCase();

    if (normalizedEntry === "curl" || normalizedEntry === "wget") {
        const remaining = entries.slice(i + 1);
        const args = remaining.filter(e => typeof e === "string") as string[];
        
        for (const arg of args) {
            if (/^https?:\/\/[^/]+:[^/]+@/.test(arg)) {
                return { blocked: true, reason: "CREDENTIAL EXPOSURE DETECTED", suggestion: "Commands should not include credentials in URLs. Use environment variables or netrc." };
            }
        }

        const pipeIdx = remaining.findIndex(e => typeof e === "object" && "op" in e && e.op === "|");
        if (pipeIdx !== -1) {
            const nextPart = remaining[pipeIdx + 1];
            if (typeof nextPart === "string" && SHELL_COMMANDS.has(nextPart.split("/").pop()?.toLowerCase() ?? "")) {
                if (args.some(a => a.startsWith("http://"))) {
                    return { blocked: true, reason: "INSECURE TRANSPORT DETECTED", suggestion: "Piping plain HTTP content to a shell is dangerous. Use HTTPS." };
                }
                if (args.some(a => a === "-k" || a === "--insecure" || a === "--no-check-certificate")) {
                    return { blocked: true, reason: "INSECURE TRANSPORT DETECTED", suggestion: "Piping to a shell with certificate validation disabled is extremely dangerous." };
                }
                return { blocked: true, reason: "PIPE-TO-SHELL DETECTED", suggestion: "Executing remote scripts directly via pipe is dangerous. Download and review the script first." };
            }
        }
    }

    if (normalizedEntry === "bash" || normalizedEntry === "sh" || normalizedEntry === "zsh") {
        const remaining = entries.slice(i + 1);
        if (remaining.some(e => typeof e === "string" && (e.includes("<(curl") || e.includes("<(wget") || e.includes("< <(curl") || e.includes("< <(wget")))) {
             return { blocked: true, reason: "PROCESS SUBSTITUTION DETECTED", suggestion: "Executing remote scripts via process substitution is dangerous." };
        }
    }

    if (["sudo", "xargs", "command", "env"].includes(normalizedEntry)) {
      nextMustBeCommand = true;
      continue;
    }

    if (normalizedEntry === "git" && i + 1 < entries.length) {
      const next = entries[i + 1];
      if (typeof next === "string" && next.toLowerCase() === "rm") {
        i++;
        continue;
      }
    }

    const basenamePart = entry.split("/").pop() ?? "";
    const cmdName = entry.startsWith("\\") ? entry.slice(1) : basenamePart;

    let resolvedCmd = cmdName.toLowerCase();
    if (cmdName.startsWith("$")) {
        const varName = cmdName.slice(1);
        resolvedCmd = (vars[varName] || cmdName).split("/").pop()?.toLowerCase() ?? "";
    }

    if (configAllowed.has(resolvedCmd)) {
        continue;
    }

    if (configBlocked.has(resolvedCmd) || resolvedCmd === "dd") {
        const args = entries.slice(i + 1).filter(e => typeof e === "string") as string[];
        
        if (resolvedCmd === "dd") {
            if (args.some(a => a.toLowerCase().startsWith("of="))) {
                return { blocked: true, reason: "Destructive dd detected", suggestion: "be careful with dd of=" };
            }
            continue; 
        }

        for (const arg of args) {
            if (!arg.startsWith("-") && isCriticalPath(arg)) {
                return { blocked: true, reason: "CRITICAL PATH PROTECTED", suggestion: `Permanent deletion of ${arg} is prohibited.` };
            }
        }

        const targetFiles = args.filter(a => !a.startsWith("-"));
        if (targetFiles.length > VOLUME_THRESHOLD) {
            return { blocked: true, reason: "VOLUME THRESHOLD EXCEEDED", suggestion: `You are trying to delete ${targetFiles.length} files. Use a more specific command.` };
        }

        const uncommitted = hasUncommittedChanges(targetFiles);
        if (uncommitted.length > 0) {
            return { blocked: true, reason: "UNCOMMITTED CHANGES DETECTED", suggestion: `Commit changes to these files first: ${uncommitted.join(", ")}` };
        }

        let suggestion = "trash <files>";
        if (resolvedCmd === "rm") {
            if (targetFiles.length > 0) {
                suggestion = `trash ${targetFiles.join(" ")}`;
            }
        }
        return { blocked: true, reason: `Destructive command '${resolvedCmd}' detected`, suggestion };
    }

    if (resolvedCmd === "find") {
        const remaining = entries.slice(i + 1);
        if (remaining.some(e => typeof e === "string" && e.toLowerCase() === "-delete")) {
            return { blocked: true, reason: "find -delete detected", suggestion: "trash <files>" };
        }
        const execIdx = remaining.findIndex(e => typeof e === "string" && e.toLowerCase() === "-exec");
        if (execIdx !== -1 && execIdx + 1 < remaining.length) {
            const execCmd = remaining[execIdx + 1];
            if (typeof execCmd === "string" && configBlocked.has(execCmd.split("/").pop()?.toLowerCase() ?? "")) {
                return { blocked: true, reason: `find -exec ${execCmd} detected`, suggestion: "trash <files>" };
            }
        }
    }

    if (SHELL_COMMANDS.has(resolvedCmd)) {
        const cIdx = entries.slice(i + 1).findIndex(e => typeof e === "string" && e === "-c");
        if (cIdx !== -1 && i + 1 + cIdx + 1 < entries.length) {
            const subshellCmd = entries[i + 1 + cIdx + 1];
            if (typeof subshellCmd === "string") {
                const result = checkDestructive(subshellCmd, depth + 1);
                if (result.blocked) return result;
            }
        }
    }
  }

  return { blocked: false };
}

async function main(): Promise<void> {
  try {
    const input = await Bun.stdin.text();
    if (!input) process.exit(0);
    
    const data: ToolInput = JSON.parse(input);
    const command = data.tool_input?.command ?? "";

    if (!command) {
      process.exit(0);
    }

    const result = checkDestructive(command);
    logAudit(command, result);

    if (result.blocked) {
      console.error(
        `🛡️  ShellShield BLOCKED: ${result.reason}\n` +
        `━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n` +
        `ACTION REQUIRED: ${result.suggestion}\n` +
        `━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n` +
        `ShellShield - Keeping your terminal safe.`
      );
      process.exit(2);
    }

    process.exit(0);
  } catch {
    process.exit(0);
  }
}

main();
