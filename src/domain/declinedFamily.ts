import {
  isElfMetadataArchitecture,
  type BinaryTarget,
  type ElfMetadataArchitecture,
} from "./binaryTargetTypes.js";

/** How a provider names a family whose lane belongs to Ghidra. */
export interface DeclinedFamily {
  /** Family name alone. */
  readonly family: string;
  /** Family name plus any declaration that selected the lane, such as a COFF machine. */
  readonly label: string;
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
  if (target.format !== "pe") return { family, label: family };
  const machine =
    target.peMachine === undefined
      ? ""
      : ` (COFF machine 0x${target.peMachine.toString(16).padStart(4, "0")})`;
  return { family, label: `${family} PE${machine}` };
};
