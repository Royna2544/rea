import { describe, expect, it } from "vitest";

import { parseConfig } from "../config/parseConfig.js";
import { declinedFamilyFixtures } from "../domain/declinedFamily.fixture.js";
import { IdaProvider } from "./IdaProvider.js";

const idaProvider = (): IdaProvider => {
  const config = parseConfig({});
  if (!config.ok) throw new Error("expected valid configuration");
  return new IdaProvider(config.value, {});
};

describe("IDA provider target support", () => {
  it("declines headerless raw-binary targets", () => {
    const provider = idaProvider();
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
});

describe("IDA provider family refusals", () => {
  const routeToGhidra = "Select a supported Ghidra profile instead.";

  it.each([
    ["MIPS", declinedFamilyFixtures.elfMips],
    ["RISC-V", declinedFamilyFixtures.elfRiscv],
    ["PowerPC", declinedFamilyFixtures.elfPowerPc],
  ] as const)("declines ELF %s targets by family", (family, target) => {
    expect(idaProvider().inspectTargetSupport(target())).toEqual({
      status: "unsupported",
      code: "architecture_unsupported",
      reason: `REA's IDA adapter has no verified ${family} lane. ${routeToGhidra}`,
      diagnostics: { target_kind: "executable", target_format: "elf" },
    });
  });

  it("declines a MIPS PE by its COFF machine", () => {
    expect(
      idaProvider().inspectTargetSupport(declinedFamilyFixtures.peMips()),
    ).toEqual({
      status: "unsupported",
      code: "architecture_unsupported",
      reason: `REA's IDA adapter has no verified MIPS PE (COFF machine 0x0166) lane. ${routeToGhidra}`,
      diagnostics: { target_kind: "executable", target_format: "pe" },
    });
  });

  it("still admits an x86 PE", () => {
    expect(
      idaProvider().inspectTargetSupport(declinedFamilyFixtures.peX86()),
    ).toEqual({
      status: "supported",
      code: null,
      reason: null,
      diagnostics: { target_kind: "executable", target_format: "pe" },
    });
  });
});
