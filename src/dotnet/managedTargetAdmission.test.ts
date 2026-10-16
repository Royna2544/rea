import { describe, expect, it } from "vitest";
import { declinedFamilyFixtures } from "../domain/declinedFamily.fixture.js";
import { managedTargetRefusal } from "./managedTargetAdmission.js";

describe("managed target admission", () => {
  it("declines a MIPS PE from the resolved target as a capability limit", () => {
    for (const target of [
      declinedFamilyFixtures.peMips(),
      declinedFamilyFixtures.peMipsWithoutMachine(),
    ])
      expect(managedTargetRefusal(target)).toBe(
        "Managed static triage does not admit MIPS PE targets; its output contracts cover x86, x86-64, ARM and ARM64 images.",
      );
  });

  it("leaves other PE and non-PE targets to the managed readers", () => {
    expect(managedTargetRefusal(declinedFamilyFixtures.peX86())).toBeNull();
    // An ELF MIPS target is not a PE; the provider's own format check refuses it.
    expect(managedTargetRefusal(declinedFamilyFixtures.elfMips())).toBeNull();
  });
});
