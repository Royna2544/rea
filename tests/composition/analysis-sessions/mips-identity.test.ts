import { describe, expect, it } from "vitest";
import type { BinaryTarget } from "../../../src/domain/binaryTargetTypes.js";
import { createAnalysisProfile } from "../../../src/domain/analysisProfile.js";
import { createEvidence, parseEvidence } from "../../../src/domain/evidence.js";
import { createEvidenceBundle } from "../../../src/domain/evidenceBundle.js";
import {
  createAnalysisSnapshotEntry,
  parseAnalysisSnapshot,
  serializeAnalysisSnapshot,
  snapshotBinding,
  snapshotTarget,
  snapshotMatchesProfile,
} from "../../../src/domain/analysisSnapshot.js";
import { sessionOutputSchemas } from "../../../src/contracts/toolOutputSchemaGroups.js";

const target: BinaryTarget = {
  path: "/source-owned.elf",
  sha256: "a".repeat(64),
  kind: "executable",
  format: "elf",
  architecture: "mips",
  availableArchitectures: ["mips"],
  mips: { elfClass: 32, byteOrder: "little", type: 2, flags: 0x70001001 },
};
const provider = { id: "ghidra", name: "Ghidra", version: "12.1.4" };
const profile = createAnalysisProfile(provider, {
  mips_elf: { elf_class: 32, byte_order: "little", type: 2, flags: 0x70001001 },
});
// Windows CE MIPS: the COFF machine, not ELF metadata, declares the family.
const peTarget: BinaryTarget = {
  path: "/source-owned.exe",
  sha256: "b".repeat(64),
  kind: "executable",
  format: "pe",
  architecture: "mips",
  availableArchitectures: ["mips"],
  peMachine: 0x0166,
  executableRole: "application",
  managed: false,
};
const peProfileParameters = {
  pe_machine: 0x0166,
  mips_support_lane: "pe32-coff-r4000-le-windows-cspec-v1",
  mips_abi_basis: "coff-machine-language-assumption-v1",
  instruction_context_evidence: "per-address-isa-mode-v1",
};
const peProfile = createAnalysisProfile(provider, peProfileParameters);

describe("MIPS identity through lifecycle, Evidence and snapshot consumers", () => {
  it("round-trips query bindings without relaxing integrity", () => {
    const result = [{ address: "0x20150", value: "rea_mips_entry" }];
    const parameters = {};
    const evidence = createEvidence(target, provider, {
      operation: "list_procedures",
      parameters,
      result,
      analysisProfile: profile,
    });
    const binding = snapshotBinding(profile);
    const entry = createAnalysisSnapshotEntry({
      target: snapshotTarget(target),
      binding,
      operation: "list_procedures",
      parameters,
      execution: {
        result,
        rawResult: null,
        provider,
        analysisProfile: profile,
        limitations: [],
        locations: [],
        subject: target,
      },
    });
    const snapshot = {
      target: snapshotTarget(target),
      binding,
      entries: [entry],
      workflow_entries: [],
      evidence_bundle: createEvidenceBundle([evidence]),
    };
    const restored = parseAnalysisSnapshot(
      JSON.parse(serializeAnalysisSnapshot(snapshot)),
    );
    expect(restored.target.architecture).toBe("mips");
    expect(restored.evidence_bundle.records[0]?.subject?.architecture).toBe(
      "mips",
    );
    expect(restored.entries[0]?.execution.subject?.architecture).toBe("mips");
    expect(
      sessionOutputSchemas.open_binary.parse({ result: target }).result
        .architecture,
    ).toBe("mips");
    expect(() =>
      parseEvidence({
        ...evidence,
        subject: { ...evidence.subject, architecture: "x86" },
      }),
    ).toThrow("semantic identifier");
    const changed = createAnalysisProfile(provider, {
      mips_elf: {
        elf_class: 32,
        byte_order: "big",
        type: 2,
        flags: 0x70001001,
      },
    });
    expect(snapshotMatchesProfile(binding, changed)).toBe(false);
  });

  it("keeps a MIPS PE's family in Evidence and snapshots and its COFF machine in the profile", () => {
    const result = [{ address: "0x11000", value: "rea_wince_entry" }];
    const parameters = {};
    const evidence = createEvidence(peTarget, provider, {
      operation: "list_procedures",
      parameters,
      result,
      analysisProfile: peProfile,
    });
    // Neither the raw COFF machine nor an ELF `mips` member reaches the subject.
    expect(evidence.subject).toEqual({
      name: "source-owned.exe",
      digest: { sha256: peTarget.sha256 },
      format: "pe",
      architecture: "mips",
      local_path: peTarget.path,
    });
    const binding = snapshotBinding(peProfile);
    const entry = createAnalysisSnapshotEntry({
      target: snapshotTarget(peTarget),
      binding,
      operation: "list_procedures",
      parameters,
      execution: {
        result,
        rawResult: null,
        provider,
        analysisProfile: peProfile,
        limitations: [],
        locations: [],
        subject: peTarget,
      },
    });
    const restored = parseAnalysisSnapshot(
      JSON.parse(
        serializeAnalysisSnapshot({
          target: snapshotTarget(peTarget),
          binding,
          entries: [entry],
          workflow_entries: [],
          evidence_bundle: createEvidenceBundle([evidence]),
        }),
      ),
    );
    expect(restored.target).toEqual({
      sha256: peTarget.sha256,
      kind: "executable",
      architecture: "mips",
      format: "pe",
    });
    expect(restored.evidence_bundle.records[0]?.subject).toMatchObject({
      format: "pe",
      architecture: "mips",
    });
    expect(restored.entries[0]?.execution.subject).toEqual({
      path: peTarget.path,
      sha256: peTarget.sha256,
      format: "pe",
      architecture: "mips",
    });
    expect(
      sessionOutputSchemas.open_binary.parse({ result: peTarget }).result,
    ).toMatchObject({ format: "pe", architecture: "mips" });
    expect(() =>
      parseEvidence({
        ...evidence,
        subject: { ...evidence.subject, architecture: "x86" },
      }),
    ).toThrow("semantic identifier");
    // The snapshot target keeps only the family, so a different COFF machine
    // must be told apart by the committed profile.
    const otherMachine = createAnalysisProfile(provider, {
      ...peProfileParameters,
      pe_machine: 0x0169,
    });
    expect(snapshotMatchesProfile(binding, peProfile)).toBe(true);
    expect(snapshotMatchesProfile(binding, otherMachine)).toBe(false);
  });
});
