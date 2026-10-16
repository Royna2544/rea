import { createHash } from "node:crypto";
import { writeFile } from "node:fs/promises";
import { join } from "node:path";

import { expect, it } from "vitest";

import { createTestTempDirectory } from "../../tests/fixtures/temporaryDirectory.js";
import { declinedFamilyFixtures } from "../domain/declinedFamily.fixture.js";
import {
  hopperLoaderArgsForTarget,
  resolveHopperAnalysisProfile,
} from "./HopperAnalysisProfile.js";

it("routes physical universal Mach-O containers through Hopper's FAT loader", () => {
  const result = hopperLoaderArgsForTarget(
    {
      path: "/tmp/universal",
      sha256: "a".repeat(64),
      kind: "executable",
      format: "mach-o-universal",
      architecture: "arm64",
      availableArchitectures: ["x86_64", "arm64"],
      universalSlice: { offset: 0, size: 32 },
    },
    "fat64",
  );

  expect(result).toEqual({
    ok: true,
    value: ["-l", "FAT", "--aarch64", "-l", "Mach-O"],
  });
});

it("prepares a verified thin arm64e slice for a FAT32 system container", async () => {
  const directory = await createTestTempDirectory("rea-hopper-fat32-profile-");
  const writeUInt32 = (buffer: Buffer, offset: number, value: number): void => {
    buffer.writeUInt32BE(value, offset);
  };
  const slices = [
    { cpuType: 0x01000007, cpuSubtype: 3 },
    { cpuType: 0x0100000c, cpuSubtype: 0x80000002 },
    { cpuType: 0x0100000c, cpuSubtype: 0x8000000c },
  ];
  const container = Buffer.alloc(3 * 4096 + 64);
  writeUInt32(container, 0, 0xcafebabe);
  writeUInt32(container, 4, slices.length);
  slices.forEach((slice, index) => {
    const offset = 4096 * (index + 1);
    const entry = 8 + index * 20;
    writeUInt32(container, entry, slice.cpuType);
    writeUInt32(container, entry + 4, slice.cpuSubtype);
    writeUInt32(container, entry + 8, offset);
    writeUInt32(container, entry + 12, 64);
    writeUInt32(container, entry + 16, 12);
    writeUInt32(container, offset, 0xfeedfacf);
    writeUInt32(container, offset + 4, slice.cpuType);
    writeUInt32(container, offset + 8, slice.cpuSubtype);
  });
  const arm64eOffset = 8192;
  const path = join(directory, "system.fat");
  await writeFile(path, container);
  const result = await resolveHopperAnalysisProfile(
    {
      path,
      sha256: createHash("sha256").update(container).digest("hex"),
      kind: "executable",
      format: "mach-o-universal",
      architecture: "arm64",
      availableArchitectures: ["x86_64", "arm64"],
      universalSlice: { offset: arm64eOffset, size: 64 },
    },
    {
      launcherPath: path,
      loaderArgsOverride: [],
      provider: { id: "hopper", name: "Hopper Disassembler", version: null },
    },
  );
  if (!result.ok) throw new Error(result.error.message);
  const parameters = result.value.profile?.parameters;
  expect(parameters).toMatchObject({
    macho_container: "fat32",
    prepared_image: {
      method: "fat32_thin_slice",
      source_offset: arm64eOffset,
      byte_length: 64,
      cpu_type: 0x0100000c,
      cpu_subtype: 0x80000002,
    },
    loader: {
      source: "derived",
      arguments: ["-l", "Mach-O", "--aarch64"],
    },
  });
});

it.each([
  ["MIPS", declinedFamilyFixtures.elfMips],
  ["RISC-V", declinedFamilyFixtures.elfRiscv],
  ["PowerPC", declinedFamilyFixtures.elfPowerPc],
] as const)(
  "refuses ELF %s targets with the Ghidra profile to select instead",
  (family, target) => {
    const result = hopperLoaderArgsForTarget(target());
    if (result.ok) throw new Error(`Hopper derived a ${family} loader`);

    expect(result.error).toMatchObject({
      _tag: "AnalysisCapabilityUnavailableError",
      message: expect.stringContaining(
        `REA's Hopper adapter does not admit ${family} targets. Select a verified Ghidra ${family} profile instead.`,
      ),
    });
  },
);

it("refuses a MIPS PE by its COFF machine", () => {
  const result = hopperLoaderArgsForTarget(declinedFamilyFixtures.peMips());
  if (result.ok) throw new Error("Hopper derived a MIPS PE loader");

  expect(result.error).toMatchObject({
    _tag: "AnalysisCapabilityUnavailableError",
    message: expect.stringContaining(
      "REA's Hopper adapter does not admit MIPS PE (COFF machine 0x0166) targets. Select a verified Ghidra MIPS profile instead.",
    ),
  });
});

it("keeps the WinPE loader for an x86 PE", () => {
  expect(hopperLoaderArgsForTarget(declinedFamilyFixtures.peX86())).toEqual({
    ok: true,
    value: ["-l", "WinPE", "--intel-32"],
  });
});
