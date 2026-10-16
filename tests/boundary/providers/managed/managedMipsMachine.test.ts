import { writeFile } from "node:fs/promises";
import { join } from "node:path";
import { expect, it } from "vitest";
import { createTestTempDirectory } from "../../../fixtures/temporaryDirectory.js";
import { parseBinaryTarget } from "../../../../src/application/BinaryTargetResolver.js";
import { projectAnalysisError } from "../../../../src/domain/analysisErrorProjection.js";
import {
  buildManagedPeFixture,
  buildNativePeFixture,
} from "../../../../src/dotnet/ManagedPe.fixture.js";
import { ManagedStaticProvider } from "../../../../src/dotnet/ManagedStaticProvider.js";

/** Patch the COFF machine of a generated image and resolve it as a caller-selected file. */
const resolveWithMachine = async (
  bytes: Buffer,
  machine: number,
  name: string,
) => {
  bytes.writeUInt16LE(machine, bytes.readUInt32LE(0x3c) + 4);
  const directory = await createTestTempDirectory("rea-managed-mips-");
  const path = join(directory, name);
  await writeFile(path, bytes);
  return { path, parsed: await parseBinaryTarget(path) };
};

// Managed output contracts enumerate x86, x86-64, ARM and ARM64 only, so a
// resolved MIPS PE is refused by every managed operation instead of mislabelled.
it.each([
  ["managed", () => buildManagedPeFixture({ cliFlags: 0 }), true],
  ["native", () => buildNativePeFixture(), false],
] as const)(
  "resolves a %s MIPS PE target but refuses managed inspection through the public path",
  async (_label, build, managed) => {
    const { parsed } = await resolveWithMachine(build(), 0x0166, "fixture.exe");
    if (!parsed.ok) throw parsed.error;
    expect(parsed.value).toMatchObject({
      kind: "executable",
      format: "pe",
      architecture: "mips",
      peMachine: 0x0166,
      managed,
    });
    const client = new ManagedStaticProvider().createClient(parsed.value);
    try {
      for (const operation of [
        "inspect_managed_artifact",
        "inspect_managed_members",
        "inspect_managed_native_boundaries",
      ] as const) {
        const observed = await client.execute(operation, {});
        if (observed.ok) throw new Error(`${operation} admitted a MIPS PE`);
        expect(projectAnalysisError(observed.error)).toMatchObject({
          code: "capability_unavailable",
          retryable: false,
          details: {
            provider_id: "rea-dotnet-static",
            operation,
            reason:
              "Managed static triage does not admit MIPS PE targets; its output contracts cover x86, x86-64, ARM and ARM64 images.",
          },
        });
      }
    } finally {
      await client.close();
    }
  },
);

// ReadyToRun has no MIPS target: XOR-ing an OS override into the MIPS machine
// must not turn a managed image into any other architecture.
it.each([
  ["Apple", 0x4722],
  ["FreeBSD", 0xaca2],
  ["OpenBSD", 0xaca3],
  ["Linux", 0x7a1f],
  ["NetBSD", 0x18f5],
  ["SunOS", 0x18f4],
] as const)(
  "refuses the %s OS-override image of the MIPS machine before any managed provider sees it",
  async (_label, machine) => {
    const { parsed } = await resolveWithMachine(
      buildManagedPeFixture({ readyToRun: true }),
      machine,
      "fixture.dll",
    );
    if (parsed.ok) throw new Error("OS-override MIPS image was admitted");

    expect(projectAnalysisError(parsed.error)).toMatchObject({
      code: "target_unavailable",
      details: {
        reason: `unsupported PE architecture (COFF machine 0x${machine.toString(16)})`,
        constraint: "file_format_rejected",
      },
    });
  },
);
