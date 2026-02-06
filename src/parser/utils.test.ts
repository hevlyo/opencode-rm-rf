import { describe, expect, test } from "bun:test";
import { normalizeCommandName, resolveVariable, filterFlags, getTrashSuggestion } from "./utils";

describe("Parser Utils", () => {
  test("normalizeCommandName handles empty input", () => {
    expect(normalizeCommandName("")).toBe("");
  });

  test("resolveVariable handles invalid format", () => {
    expect(resolveVariable("NOT_A_VAR", {})).toBeNull();
    expect(resolveVariable("$", {})).toBeNull();
    expect(resolveVariable("${}", {})).toBeNull();
  });

  test("resolveVariable handles empty result", () => {
    expect(resolveVariable("$EMPTY", { EMPTY: "" })).toBeNull();
  });

  test("resolveVariable handles fallback with empty value", () => {
    expect(resolveVariable("${UNDEFINED:-fallback}", {})).toBe("fallback");
  });

  test("filterFlags identifies flags correctly", () => {
    expect(filterFlags(["-f", "--force", "file.txt"])).toEqual(["file.txt"]);
  });

  test("getTrashSuggestion handles empty file list", () => {
    expect(getTrashSuggestion([])).toBe("trash <files>");
  });
});
