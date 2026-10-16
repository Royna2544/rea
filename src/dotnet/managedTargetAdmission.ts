import type { BinaryTarget } from "../domain/binaryTargetTypes.js";

/**
 * Why the managed readers decline an already resolved target, or null when they
 * may read it. Every managed consumer asks the resolved target instead of
 * re-interpreting the COFF machine: the managed output contracts enumerate x86,
 * x86-64, ARM and ARM64 images only, so a MIPS PE is declined as a capability
 * limit, not reported as malformed input.
 */
export const managedTargetRefusal = (target: BinaryTarget): string | null =>
  target.kind === "executable" &&
  target.format === "pe" &&
  target.architecture === "mips"
    ? "Managed static triage does not admit MIPS PE targets; its output contracts cover x86, x86-64, ARM and ARM64 images."
    : null;
