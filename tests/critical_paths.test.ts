import { describe, expect, test } from "bun:test";
import { checkDestructive } from "../src/parser/analyzer";

describe("Critical Path Verification", () => {
  test("blocks deleting /etc/passwd (nested)", () => {
    const result = checkDestructive("rm /etc/passwd");
    expect(result.blocked).toBe(true);
  });

  test("blocks deleting /usr/bin/python", () => {
    const result = checkDestructive("rm /usr/bin/python");
    expect(result.blocked).toBe(true);
  });
});
