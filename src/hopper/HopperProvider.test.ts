import { describe, expect, it } from "vitest";

import { parseConfig } from "../config/parseConfig.js";
import { declinedFamilyFixtures } from "../domain/declinedFamily.fixture.js";
import { silentLogger } from "../logger.js";
import { HopperProvider } from "./HopperProvider.js";

describe("Hopper provider capabilities", () => {
  it("declines headerless raw-binary targets with a Ghidra-directed reason", () => {
    const config = parseConfig({});
    if (!config.ok) throw new Error("expected valid configuration");
    const provider = new HopperProvider(config.value, silentLogger, {});
    expect(
      provider.inspectTargetSupport({
        path: "/tmp/ecu.bin",
        sha256: "a".repeat(64),
        kind: "executable",
        format: "raw-binary",
        architecture: "arm",
        availableArchitectures: ["arm"],
        entryPoint: "0x8000000",
        entryPointSource: "0x8000000",
      }),
    ).toMatchObject({
      status: "unsupported",
      code: "target_format_unsupported",
      reason: expect.stringContaining("Ghidra"),
    });
  });
  it("declines DOS MZ targets with a provider-specific support reason", () => {
    const config = parseConfig({});
    if (!config.ok) throw new Error("expected valid configuration");
    const provider = new HopperProvider(config.value, silentLogger, {});
    expect(
      provider.inspectTargetSupport({
        path: "/tmp/legacy.exe",
        sha256: "a".repeat(64),
        kind: "executable",
        format: "dos-mz",
        architecture: "x86",
        availableArchitectures: ["x86"],
      }),
    ).toMatchObject({
      status: "unsupported",
      code: "target_format_unsupported",
      reason: expect.stringContaining("Ghidra"),
    });
  });
});

describe("Hopper provider family refusals", () => {
  const hopperProvider = (): HopperProvider => {
    const config = parseConfig({});
    if (!config.ok) throw new Error("expected valid configuration");
    return new HopperProvider(config.value, silentLogger, {});
  };

  it.each([
    ["MIPS", declinedFamilyFixtures.elfMips, "mips"],
    ["RISC-V", declinedFamilyFixtures.elfRiscv, "riscv"],
    ["PowerPC", declinedFamilyFixtures.elfPowerPc, "powerpc"],
  ] as const)(
    "declines ELF %s targets without a host routing sentence",
    (family, target, architecture) => {
      expect(hopperProvider().inspectTargetSupport(target())).toEqual({
        status: "unsupported",
        code: "architecture_unsupported",
        reason: `REA's Hopper adapter does not admit ${family} targets.`,
        diagnostics: {
          target_kind: "executable",
          target_format: "elf",
          architecture,
        },
      });
    },
  );

  it("declines a MIPS PE by its COFF machine and names the host-limited Ghidra lane", () => {
    expect(
      hopperProvider().inspectTargetSupport(declinedFamilyFixtures.peMips()),
    ).toEqual({
      status: "unsupported",
      code: "architecture_unsupported",
      reason:
        "REA's Hopper adapter does not admit MIPS PE (COFF machine 0x0166) targets. REA's Ghidra MIPS PE lane runs on Linux and macOS hosts only.",
      diagnostics: {
        target_kind: "executable",
        target_format: "pe",
        architecture: "mips",
      },
    });
  });

  it("still admits an x86 PE", () => {
    expect(
      hopperProvider().inspectTargetSupport(declinedFamilyFixtures.peX86()),
    ).toEqual({
      status: "supported",
      code: null,
      reason: null,
      diagnostics: {
        target_kind: "executable",
        target_format: "pe",
        architecture: "x86",
      },
    });
  });
});
