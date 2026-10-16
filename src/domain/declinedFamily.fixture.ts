import { parseExecutableHeader } from "./binaryTarget.js";
import { elf, pe } from "./binaryTarget.fixture.js";
import type { BinaryTarget } from "./binaryTargetTypes.js";

type ExecutableTarget = Extract<BinaryTarget, { readonly kind: "executable" }>;
type PeTarget = Extract<BinaryTarget, { readonly format: "pe" }>;

/** The target a provider receives for generated header bytes, from the production header parser. */
const parsedTarget = (bytes: Buffer): ExecutableTarget => {
  const parsed = parseExecutableHeader(bytes, "x64");
  if (!parsed.ok) throw new Error(parsed.error);
  return {
    path: "/fixture/target",
    sha256: "a".repeat(64),
    kind: "executable",
    ...parsed.value,
  };
};

const parsedPeTarget = (bytes: Buffer): PeTarget => {
  const target = parsedTarget(bytes);
  if (target.format !== "pe")
    throw new Error(`expected a PE target, parsed ${target.format}`);
  return target;
};

/** Parsed executables for providers that decline a family by name. */
export const declinedFamilyFixtures = {
  elfMips: (): ExecutableTarget => parsedTarget(elf(1, 1, 8)),
  elfRiscv: (): ExecutableTarget => parsedTarget(elf(2, 1, 243)),
  elfPowerPc: (): ExecutableTarget => parsedTarget(elf(1, 2, 20)),
  /** Windows CE MIPS (COFF machine 0x0166), a native application. */
  peMips: (): PeTarget => parsedPeTarget(pe(0x0166)),
  /** A MIPS PE whose COFF machine is unavailable, as for a target built without header facts. */
  peMipsWithoutMachine: (): PeTarget => {
    const { peMachine: _observed, ...target } = parsedPeTarget(pe(0x0166));
    return target;
  },
  /** Control: an x86 PE that no provider declines by family. */
  peX86: (): PeTarget => parsedPeTarget(pe(0x014c)),
};
