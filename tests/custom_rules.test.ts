import { describe, expect, test } from "bun:test";
import { checkDestructive } from "../src/parser/analyzer";

describe("Custom Rules Configuration", () => {
  const customContext = {
    blocked: new Set<string>(),
    allowed: new Set<string>(),
    trustedDomains: [],
    threshold: 100,
    customRules: [
      { pattern: "^docker rm", suggestion: "Do not remove docker containers manually" },
      { pattern: "delete_db\\.sh", suggestion: "Database deletion is restricted" }
    ]
  };

  test("blocks command matching custom regex", () => {
    const result = checkDestructive("docker rm my-container", 0, customContext);
    expect(result.blocked).toBe(true);
    expect(result.reason).toBe("CUSTOM RULE VIOLATION");
    expect(result.suggestion).toBe("Do not remove docker containers manually");
  });

  test("blocks command matching partial regex", () => {
    const result = checkDestructive("./scripts/delete_db.sh --force", 0, customContext);
    expect(result.blocked).toBe(true);
    expect(result.reason).toBe("CUSTOM RULE VIOLATION");
  });

  test("allows command not matching custom rules", () => {
    const result = checkDestructive("ls -la", 0, customContext);
    expect(result.blocked).toBe(false);
  });
});
