import { describe, expect, test } from "bun:test";
import { scoreUrlRisk } from "../src/security/validators";

describe("URL risk scoring", () => {
  test("returns 100 for invalid urls", () => {
    const result = scoreUrlRisk("not a url", ["example.com"]);
    expect(result.score).toBe(100);
    expect(result.reasons).toContain("INVALID_URL");
  });

  test("trusted https url stays low", () => {
    const result = scoreUrlRisk("https://github.com/openai", ["github.com"]);
    expect(result.trusted).toBe(true);
    expect(result.score).toBeLessThan(20);
  });

  test("penalizes credentials and encoded urls", () => {
    const result = scoreUrlRisk("https://user:pass@xn--exmple-cua.com", ["github.com"]);
    expect(result.score).toBeGreaterThanOrEqual(40);
    expect(result.reasons).toContain("CREDENTIALS_IN_URL");
    expect(result.reasons).toContain("PUNYCODE_DOMAIN");
  });

  test("penalizes ip hosts, homographs, and long urls", () => {
    const longPath = "/".padEnd(140, "a");
    const result = scoreUrlRisk(`https://127.0.0.1${longPath}`, ["example.com"]);
    expect(result.reasons).toContain("IP_ADDRESS_HOST");
    expect(result.reasons).toContain("LONG_URL");

    const homograph = scoreUrlRisk("https://exаmple.com", ["example.com"]);
    expect(homograph.reasons).toContain("HOMOGRAPH_MIXED_SCRIPTS");
  });
});
