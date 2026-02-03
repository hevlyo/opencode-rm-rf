import { appendFileSync, existsSync, mkdirSync, statSync, renameSync } from "fs";
import { join } from "path";
import { homedir, hostname } from "os";
import { BlockResult } from "./types";
import { createHash } from "crypto";

export function logAudit(command: string, result: BlockResult): void {
  try {
    const auditDir = join(homedir(), ".shellshield");
    if (!existsSync(auditDir)) mkdirSync(auditDir, { recursive: true });
    const logPath = join(auditDir, "audit.log");

    if (existsSync(logPath)) {
      try {
        const stats = statSync(logPath);
        if (stats.size > 1 * 1024 * 1024) {
          const backupPath = join(auditDir, "audit.log.1");
          renameSync(logPath, backupPath);
        }
      } catch {}
    }

    const commandHash = createHash("sha256").update(command).digest("hex").slice(0, 12);
    
    const entry = {
      id: commandHash,
      timestamp: new Date().toISOString(),
      user: process.env.USER || "unknown",
      host: hostname(),
      command,
      blocked: result.blocked,
      severity: result.blocked ? "high" : "info",
      reason: result.blocked ? result.reason : undefined,
      cwd: process.cwd(),
    };
    appendFileSync(logPath, JSON.stringify(entry) + "\n");
  } catch {
    return;
  }
}
