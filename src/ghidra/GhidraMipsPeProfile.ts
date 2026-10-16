import type { GhidraLanguageOverride } from "../config/ghidraLanguageOverride.js";
import type { BinaryTarget } from "../domain/binaryTargetTypes.js";
import type { JsonValue } from "../domain/jsonValue.js";
import { PE_MACHINE_MIPS_R4000 } from "../domain/peMachine.js";

/**
 * Ghidra 12.1.4's `MIPS.opinion` maps PE machine 358 (0x0166, R4000) to
 * `MIPS:LE:32:default` with the `windows` compiler specification. REA pins that
 * pair instead of accepting the loader's choice so the committed profile, the
 * session readback and a different Ghidra mapping all compare against one owner.
 */
const MIPS_PE_LANGUAGE: GhidraLanguageOverride = {
  languageId: "MIPS:LE:32:default",
  compilerSpecId: "windows",
};

/** Which lane a MIPS PE belongs to is the COFF machine, never the family name. */
export const isGhidraMipsPeTarget = (target: BinaryTarget): boolean =>
  target.kind === "executable" &&
  target.format === "pe" &&
  target.architecture === "mips";

const hex16 = (machine: number): string =>
  `0x${machine.toString(16).padStart(4, "0")}`;

/**
 * Keep family recognition separate from the deliberately bounded Ghidra lane.
 * Returns null both for admitted MIPS PE targets and for targets of any other
 * kind, so callers combine it with the ELF MIPS and other lane checks.
 */
export const ghidraMipsPeUnsupportedReason = (
  target: BinaryTarget,
): string | null => {
  if (
    target.kind !== "executable" ||
    target.format !== "pe" ||
    target.architecture !== "mips"
  )
    return null;
  if (target.peMachine === undefined)
    return "The MIPS PE COFF machine was not observed; a family name alone does not select the ISA, word size or byte order.";
  if (target.peMachine !== PE_MACHINE_MIPS_R4000)
    return `This Ghidra MIPS PE lane is verified for COFF machine ${hex16(PE_MACHINE_MIPS_R4000)} (R4000) only; machine ${hex16(target.peMachine)} selects an unverified ISA, word size or instruction set.`;
  if (
    target.executableRole !== "application" &&
    target.executableRole !== "shared-library"
  )
    return "This Ghidra MIPS PE lane accepts PE applications and DLLs, not non-executable or unclassified images.";
  if (target.managed !== false)
    return "This Ghidra MIPS PE lane accepts native PE applications and DLLs; managed or unclassified PE targets are unsupported.";
  return null;
};

/** Pin the language only for targets admitted by the same lane boundary. */
export const ghidraMipsPeLanguage = (
  target: BinaryTarget,
): GhidraLanguageOverride | undefined =>
  isGhidraMipsPeTarget(target) && ghidraMipsPeUnsupportedReason(target) === null
    ? MIPS_PE_LANGUAGE
    : undefined;

/**
 * Commit the COFF machine that selected the lane. Evidence subjects and
 * snapshots carry only the `mips` family, so the profile is where distinct MIPS
 * machines stay distinguishable.
 */
export const ghidraMipsPeProfileParameters = (
  target: BinaryTarget,
): Readonly<Record<string, JsonValue>> =>
  isGhidraMipsPeTarget(target) && ghidraMipsPeUnsupportedReason(target) === null
    ? {
        pe_machine: PE_MACHINE_MIPS_R4000,
        mips_support_lane: "pe32-coff-r4000-le-windows-cspec-v1",
        mips_abi_basis: "coff-machine-language-assumption-v1",
        instruction_context_evidence: "per-address-isa-mode-v1",
      }
    : {};

/** The pinned language is an analysis convention, not proof of the producer. */
export const ghidraMipsPeLimitations = (
  target: BinaryTarget,
): readonly string[] =>
  isGhidraMipsPeTarget(target)
    ? [
        `MIPS PE: REA pins Ghidra's \`${MIPS_PE_LANGUAGE.languageId}\` language with the \`${MIPS_PE_LANGUAGE.compilerSpecId}\` compiler specification for COFF machine ${hex16(PE_MACHINE_MIPS_R4000)} (R4000). The COFF machine is a header declaration, not proof of the MIPS32 ISA level the language models. MIPS III 64-bit instructions are not modeled: on Ghidra 12.1.4 a \`daddu\` is listed without semantics, the decompiler reports an unimplemented instruction and truncates control flow there, and a \`dsll\` delay slot was not decoded.`,
        "Ghidra's `windows` and `default` compiler specifications for this language share `mips32le.cspec`; Windows calling-convention fidelity is an assumption of this lane, not a verified fact.",
        "Admission reads the COFF machine, characteristics and CLI directory only. The subsystem and operating system (for example Windows CE) are not inspected, and PE base relocations are recorded by Ghidra without being applied: the image is analyzed at its preferred base.",
      ]
    : [];
