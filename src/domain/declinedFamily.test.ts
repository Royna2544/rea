import { describe, expect, it } from "vitest";
import { declinedFamilyDescription } from "./declinedFamily.js";
import { declinedFamilyFixtures } from "./declinedFamily.fixture.js";

describe("declined family wording", () => {
  it.each([
    ["MIPS", declinedFamilyFixtures.elfMips],
    ["RISC-V", declinedFamilyFixtures.elfRiscv],
    ["PowerPC", declinedFamilyFixtures.elfPowerPc],
  ] as const)("names an ELF %s target by its family", (label, target) => {
    expect(declinedFamilyDescription(target())).toEqual({
      family: label,
      label,
    });
  });

  it("names a MIPS PE by its COFF machine and keeps the family separate", () => {
    expect(declinedFamilyDescription(declinedFamilyFixtures.peMips())).toEqual({
      family: "MIPS",
      label: "MIPS PE (COFF machine 0x0166)",
    });
  });

  it("keeps the family name when the MIPS PE COFF machine was not observed", () => {
    expect(
      declinedFamilyDescription(declinedFamilyFixtures.peMipsWithoutMachine()),
    ).toEqual({ family: "MIPS", label: "MIPS PE" });
  });
});
