import { describe, expect, it } from "vitest";

import { decodePeMachine, PE_MACHINE_MIPS_R4000 } from "./peMachine.js";

// IMAGE_FILE_MACHINE_NATIVE_OS_OVERRIDE values from dotnet/runtime pedecoder.h.
const APPLE = 0x4644;
const FREEBSD = 0xadc4;
const OPENBSD = 0xadc5;
const LINUX = 0x7b79;
const NETBSD = 0x1993;
const SUNOS = 0x1992;

describe("COFF machine decoding", () => {
  it.each([
    ["x86", 0x014c, "x86"],
    ["x86-64", 0x8664, "x86_64"],
    ["ARM", 0x01c0, "arm"],
    ["ARM Thumb", 0x01c2, "arm"],
    ["ARMNT", 0x01c4, "arm"],
    ["ARM64", 0xaa64, "arm64"],
    ["MIPS R4000 little-endian (Windows CE)", 0x0166, "mips"],
  ] as const)(
    "decodes the direct %s machine",
    (_label, machine, architecture) => {
      expect(decodePeMachine(machine)).toEqual({
        architecture,
        nativeOsOverride: false,
      });
    },
  );

  it.each([
    ["R3000 big-endian", 0x0160],
    ["R3000", 0x0162],
    ["R10000", 0x0168],
    ["WCE v2", 0x0169],
    ["MIPS16", 0x0266],
    ["MIPS with FPU", 0x0366],
    ["MIPS16 with FPU", 0x0466],
  ] as const)("does not decode the %s MIPS machine", (_label, machine) => {
    expect(decodePeMachine(machine)).toBeUndefined();
  });

  it.each([
    ["x86 under Apple", 0x014c, APPLE, "x86"],
    ["x86-64 under FreeBSD", 0x8664, FREEBSD, "x86_64"],
    ["ARM under OpenBSD", 0x01c0, OPENBSD, "arm"],
    ["ARM64 under Linux", 0xaa64, LINUX, "arm64"],
    ["ARM Thumb under NetBSD", 0x01c2, NETBSD, "arm"],
    ["ARMNT under SunOS", 0x01c4, SUNOS, "arm"],
  ] as const)(
    "decodes %s as a ReadyToRun OS-override machine",
    (_label, machine, override, architecture) => {
      expect(decodePeMachine(machine ^ override)).toEqual({
        architecture,
        nativeOsOverride: true,
      });
    },
  );

  // ReadyToRun has no MIPS target: an OS override must not turn the MIPS
  // machine into a managed MIPS (or any other) architecture.
  it.each([
    ["Apple", APPLE, 0x4722],
    ["FreeBSD", FREEBSD, 0xaca2],
    ["OpenBSD", OPENBSD, 0xaca3],
    ["Linux", LINUX, 0x7a1f],
    ["NetBSD", NETBSD, 0x18f5],
    ["SunOS", SUNOS, 0x18f4],
  ] as const)(
    "does not decode the %s OS-override image of the MIPS machine",
    (_label, override, image) => {
      expect(PE_MACHINE_MIPS_R4000 ^ override).toBe(image);
      expect(decodePeMachine(image)).toBeUndefined();
    },
  );
});
