import { describe, expect, test } from "bun:test";
import { checkDestructive } from "../src/parser/analyzer";

describe("MV Command Protection", () => {
  test("allows safe moves", () => {
    const result = checkDestructive("mv file.txt new_file.txt");
    expect(result.blocked).toBe(false);
  });

  test("blocks moving to /etc", () => {
    const result = checkDestructive("mv malicious.sh /etc/profile");
    expect(result.blocked).toBe(true);
  });

  test("blocks moving to /", () => {
    const result = checkDestructive("mv file /");
    expect(result.blocked).toBe(true);
  });

   test("blocks moving to C:\\Windows", () => {
    const result = checkDestructive("mv virus.exe 'C:\\Windows\\System32'");
    expect(result.blocked).toBe(true);
  });
});
