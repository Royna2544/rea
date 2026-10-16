import { describe, expect, it } from "vitest";

import { inspectManagedArtifactBytes } from "./ManagedArtifactInspector.js";
import { inspectManagedMembersBytes } from "./ManagedMemberInspector.js";
import { inspectManagedNativeBoundariesBytes } from "./ManagedNativeBoundaryInspector.js";
import {
  buildManagedPeFixture,
  buildNativePeFixture,
  managedPeFixtureTarget,
} from "./ManagedPe.fixture.js";

describe("managed artifact failure classification", () => {
  it("distinguishes native, malformed, and unsupported metadata", () => {
    const nativeBytes = buildNativePeFixture();
    const native = inspectManagedArtifactBytes(
      nativeBytes,
      managedPeFixtureTarget(nativeBytes),
    );
    expect(native).toMatchObject({
      classification: { status: "not-managed" },
      metadata: { status: "absent" },
      coverage: { state: "unavailable" },
    });

    const malformedBytes = buildManagedPeFixture({
      corruptMetadataSignature: true,
    });
    const malformed = inspectManagedArtifactBytes(
      malformedBytes,
      managedPeFixtureTarget(malformedBytes),
    );
    expect(malformed.classification.status).toBe("malformed");
    expect(malformed.coverage.issues).toEqual([
      expect.objectContaining({ code: "invalid-metadata-root" }),
    ]);

    const unsupportedTableBytes = buildManagedPeFixture({
      metadataValidMaskExtra: 1n << 50n,
    });
    const unsupportedTable = inspectManagedArtifactBytes(
      unsupportedTableBytes,
      managedPeFixtureTarget(unsupportedTableBytes),
    );
    expect(unsupportedTable.coverage.issues).toEqual([
      expect.objectContaining({ code: "invalid-tables" }),
    ]);
  });

  it("rejects a ReadyToRun OS-override machine without a CLI directory", () => {
    const bytes = buildNativePeFixture();
    bytes.writeUInt16LE(0x014c ^ 0x7b79, bytes.readUInt32LE(0x3c) + 4);
    expect(() =>
      inspectManagedArtifactBytes(bytes, managedPeFixtureTarget(bytes)),
    ).toThrow("Unsupported PE machine 0x7a35");
  });

  // Managed output contracts enumerate x86, x86-64, ARM and ARM64 only.
  it.each([
    ["with a CLI directory", () => buildManagedPeFixture()],
    ["without a CLI directory", () => buildNativePeFixture()],
  ] as const)(
    "refuses the MIPS PE machine %s as unsupported managed input",
    (_label, build) => {
      const bytes = build();
      bytes.writeUInt16LE(0x0166, bytes.readUInt32LE(0x3c) + 4);
      expect(() =>
        inspectManagedArtifactBytes(bytes, managedPeFixtureTarget(bytes)),
      ).toThrow("Managed inspection does not admit the MIPS PE machine 0x0166");
    },
  );

  // ReadyToRun has no MIPS target, so no OS override decodes the MIPS machine.
  it.each([
    ["Apple", 0x4722],
    ["FreeBSD", 0xaca2],
    ["OpenBSD", 0xaca3],
    ["Linux", 0x7a1f],
    ["NetBSD", 0x18f5],
    ["SunOS", 0x18f4],
  ] as const)(
    "rejects the %s OS-override image of the MIPS machine as an unsupported PE machine",
    (_label, machine) => {
      const bytes = buildManagedPeFixture({ readyToRun: true });
      bytes.writeUInt16LE(machine, bytes.readUInt32LE(0x3c) + 4);
      expect(() =>
        inspectManagedArtifactBytes(bytes, managedPeFixtureTarget(bytes)),
      ).toThrow(`Unsupported PE machine 0x${machine.toString(16)}`);
    },
  );

  it("keeps malformed reference and attribute issues across inventory callers", () => {
    const bytes = buildManagedPeFixture({
      references: [
        "System.Runtime",
        "System.Runtime",
        "UnityEngine.CoreModule",
      ],
      malformedAssemblyReferenceRows: [3],
      malformedCustomAttributeRows: [1],
    });
    const target = managedPeFixtureTarget(bytes);
    const artifact = inspectManagedArtifactBytes(bytes, target);
    const members = inspectManagedMembersBytes(bytes, target);
    const boundaries = inspectManagedNativeBoundariesBytes(bytes, target);
    const issueCodes = ["invalid-heap-index", "invalid-row"];

    expect(artifact.references.map(({ name }) => name)).toEqual([
      "System.Runtime",
      "System.Runtime",
    ]);
    expect(artifact.attributes).toEqual([]);
    expect(artifact.coverage.issues.map(({ code }) => code)).toEqual(
      issueCodes,
    );
    expect(members.coverage.issues.map(({ code }) => code)).toEqual(issueCodes);
    expect(boundaries.coverage).toMatchObject({
      state: "partial",
      issues: [
        expect.objectContaining({ code: "invalid-heap-index" }),
        expect.objectContaining({ code: "invalid-row" }),
      ],
    });
  });
});
