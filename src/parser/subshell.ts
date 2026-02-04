import { BlockResult } from "../types";
import { ParsedEntry } from "./types";

export function checkSubshellCommand(
  entries: ParsedEntry[],
  startIndex: number,
  checkCommand: (command: string) => BlockResult | null
): BlockResult | null {
  const remaining = entries.slice(startIndex);
  const cIdx = remaining.findIndex((entry) => {
    if (typeof entry !== "string") return false;
    const flag = entry.toLowerCase();
    return flag === "-c" || flag === "-command";
  });
  if (cIdx === -1 || startIndex + cIdx + 1 >= entries.length) return null;

  const subshellCmd = entries[startIndex + cIdx + 1];
  if (typeof subshellCmd !== "string") return null;

  return checkCommand(subshellCmd);
}
