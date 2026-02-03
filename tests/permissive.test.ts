import { describe, expect, test } from "bun:test";
import { exec } from "child_process";
import { promisify } from "util";

import { join, resolve } from "path";

const execAsync = promisify(exec);
const PROJECT_ROOT = resolve(import.meta.dir, "..");
const CLI_PATH = join(PROJECT_ROOT, "src", "index.ts");

describe("Permissive Mode", () => {
  test("should not block destructive command when SHELLSHIELD_MODE=permissive", async () => {
    try {
      const { stdout, stderr } = await execAsync(
        `SHELLSHIELD_MODE=permissive /home/hevlyo/.bun/bin/bun "${CLI_PATH}" --check "rm /etc/passwd"`
      );
      expect(stderr).toContain("ShellShield WARNING");
      expect(stderr).toContain("would be blocked");
    } catch (error: any) {
      console.error(error.stderr); 
      throw new Error(`Command failed with code ${error.code}`);
    }
  });

  test("should block destructive command when SHELLSHIELD_MODE=enforce", async () => {
    try {
      await execAsync(
        `SHELLSHIELD_MODE=enforce /home/hevlyo/.bun/bin/bun "${CLI_PATH}" --check "rm /etc/passwd"`
      );
      throw new Error("Command should have failed");
    } catch (error: any) {
      expect(error.code).toBe(2);
      expect(error.stderr).toContain("ShellShield BLOCKED");
    }
  });

   test("should default to enforce mode", async () => {
    try {
      await execAsync(
        `/home/hevlyo/.bun/bin/bun "${CLI_PATH}" --check "rm /etc/passwd"`
      );
      throw new Error("Command should have failed");
    } catch (error: any) {
      expect(error.code).toBe(2);
      expect(error.stderr).toContain("ShellShield BLOCKED");
    }
  });
});
