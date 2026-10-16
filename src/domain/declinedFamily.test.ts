import { describe, expect, it } from "vitest";

import {
  declinedFamilyDescription,
  declinedFamilyReason,
} from "./declinedFamily.js";
import { declinedFamilyFixtures } from "./declinedFamily.fixture.js";

const MIPS_PE_ROUTING =
  "REA's Ghidra MIPS PE lane runs on Linux and macOS hosts only.";

describe("declined family wording", () => {
  it.each([
    ["MIPS", declinedFamilyFixtures.elfMips],
    ["RISC-V", declinedFamilyFixtures.elfRiscv],
    ["PowerPC", declinedFamilyFixtures.elfPowerPc],
  ] as const)(
    "names an ELF %s target by family with no routing sentence",
    (label, target) => {
      const declined = declinedFamilyDescription(target());

      expect(declined).toEqual({ family: label, label, routing: null });
      expect(declinedFamilyReason("Declined.", declined)).toBe("Declined.");
    },
  );

  it("names a MIPS PE by its COFF machine and routes it to the host-limited Ghidra lane", () => {
    const declined = declinedFamilyDescription(declinedFamilyFixtures.peMips());

    expect(declined).toEqual({
      family: "MIPS",
      label: "MIPS PE (COFF machine 0x0166)",
      routing: MIPS_PE_ROUTING,
    });
    const reason = declinedFamilyReason(
      `Adapter does not admit ${declined.label} targets.`,
      declined,
    );
    expect(reason).toBe(
      `Adapter does not admit MIPS PE (COFF machine 0x0166) targets. ${MIPS_PE_ROUTING}`,
    );
    expect(reason.split(MIPS_PE_ROUTING)).toHaveLength(2);
  });

  it("keeps the family name when the MIPS PE COFF machine was not observed", () => {
    expect(
      declinedFamilyDescription(declinedFamilyFixtures.peMipsWithoutMachine()),
    ).toEqual({ family: "MIPS", label: "MIPS PE", routing: MIPS_PE_ROUTING });
  });
});
