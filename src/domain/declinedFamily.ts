import {
  isElfMetadataArchitecture,
  type BinaryTarget,
  type ElfMetadataArchitecture,
} from "./binaryTargetTypes.js";

/** How a provider names a family whose lane belongs to Ghidra. */
export interface DeclinedFamily {
  readonly label: string;
  /** Extra sentence for lanes whose Ghidra route depends on the host; null when none. */
  readonly routing: string | null;
}

const FAMILY_LABELS: Record<ElfMetadataArchitecture, string> = {
  mips: "MIPS",
  riscv: "RISC-V",
  powerpc: "PowerPC",
};

/**
 * Name a target for providers that decline its family by name instead of
 * guessing a loader. A PE is named by its COFF machine because that, not the
 * family, selected the Ghidra lane. Callers decide whether to decline with
 * `isElfMetadataArchitecture`; this only words the refusal.
 */
export const declinedFamilyDescription = (
  target: Extract<BinaryTarget, { readonly kind: "executable" }>,
): DeclinedFamily => {
  const family = isElfMetadataArchitecture(target.architecture)
    ? FAMILY_LABELS[target.architecture]
    : target.architecture;
  if (target.format !== "pe") return { label: family, routing: null };
  const machine =
    target.peMachine === undefined
      ? ""
      : ` (COFF machine 0x${target.peMachine.toString(16).padStart(4, "0")})`;
  return {
    label: `${family} PE${machine}`,
    routing: `REA's Ghidra ${family} PE lane runs on Linux and macOS hosts only.`,
  };
};

/** Join a refusal with its optional host-specific routing sentence. */
export const declinedFamilyReason = (
  sentence: string,
  declined: DeclinedFamily,
): string =>
  declined.routing === null ? sentence : `${sentence} ${declined.routing}`;
