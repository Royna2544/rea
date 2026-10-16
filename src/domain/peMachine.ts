import type {
  HeaderArchitecture,
  PeArchitecture,
} from "./binaryTargetTypes.js";

/** IMAGE_FILE_MACHINE_R4000: little-endian MIPS, the Windows CE MIPS machine. */
export const PE_MACHINE_MIPS_R4000 = 0x0166;

/** A decoded COFF machine and whether it carried a ReadyToRun OS override. */
export interface PeMachine {
  readonly architecture: PeArchitecture;
  readonly nativeOsOverride: boolean;
}

/**
 * Machines ReadyToRun can target. Only this table is retried under an OS
 * override: ReadyToRun has no MIPS target, so XOR-ing an override into a MIPS
 * machine must not decode as managed MIPS.
 */
const readyToRunArchitectureForMachine = (
  machine: number,
): HeaderArchitecture | undefined => {
  switch (machine) {
    case 0x014c:
      return "x86";
    case 0x8664:
      return "x86_64";
    case 0x01c0:
    case 0x01c2:
    case 0x01c4:
      return "arm";
    case 0xaa64:
      return "arm64";
  }
  return undefined;
};

/**
 * Every other COFF MIPS machine (R3000, R10000, WCE v2, MIPS16, FPU variants)
 * stays undecoded: each selects a different ISA or word size, and none has
 * been verified.
 */
const architectureForMachine = (machine: number): PeArchitecture | undefined =>
  machine === PE_MACHINE_MIPS_R4000
    ? "mips"
    : readyToRunArchitectureForMachine(machine);

/**
 * ReadyToRun images compiled for a non-Windows OS store the COFF machine XORed
 * with IMAGE_FILE_MACHINE_NATIVE_OS_OVERRIDE (dotnet/runtime
 * src/coreclr/inc/pedecoder.h): Apple, FreeBSD, OpenBSD, Linux, NetBSD, SunOS.
 */
const NATIVE_OS_OVERRIDES = [0x4644, 0xadc4, 0xadc5, 0x7b79, 0x1993, 0x1992];

/**
 * Decode a COFF machine. Only managed images carry an OS override, so callers
 * must reject `nativeOsOverride` when the image has no CLI header.
 */
export const decodePeMachine = (machine: number): PeMachine | undefined => {
  const direct = architectureForMachine(machine);
  if (direct !== undefined)
    return { architecture: direct, nativeOsOverride: false };
  for (const override of NATIVE_OS_OVERRIDES) {
    const architecture = readyToRunArchitectureForMachine(machine ^ override);
    if (architecture !== undefined)
      return { architecture, nativeOsOverride: true };
  }
  return undefined;
};
