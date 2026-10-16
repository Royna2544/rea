import { mkdir, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { createTestTempDirectory } from "../../tests/fixtures/temporaryDirectory.js";
import { parseConfig } from "../config/parseConfig.js";
import type { BinaryTarget } from "../domain/binaryTargetTypes.js";
import { ok } from "../domain/result.js";
import { silentLogger } from "../logger.js";
import {
  ghidraPinnedLanguage,
  ghidraProfileLanguageOverride,
  sameGhidraLanguageOverride,
} from "./GhidraAnalysisProfile.js";
import type { GhidraClientOptions } from "./GhidraClientTypes.js";
import type { GhidraInstallationHost } from "./GhidraInstallation.js";
import { ghidraProfileInstallationHost as host } from "./GhidraInstallation.fixture.js";
import {
  GhidraHeadlessLauncher,
  ghidraHeadlessArguments,
} from "./GhidraLauncher.js";
import {
  ghidraMipsLanguageOverride,
  ghidraMipsProfileParameters,
  ghidraMipsUnsupportedReason,
} from "./GhidraMipsProfile.js";
import {
  ghidraMipsPeLanguage,
  ghidraMipsPeLimitations,
  ghidraMipsPeProfileParameters,
  ghidraMipsPeUnsupportedReason,
} from "./GhidraMipsPeProfile.js";
import { ghidraProcessorUnsupportedReason } from "./GhidraPspProfile.js";
import { GhidraProvider } from "./GhidraProvider.js";
import { GHIDRA_SESSION_CAPABILITIES } from "./GhidraSessionValues.js";

type PeTarget = Extract<BinaryTarget, { format: "pe" }>;

// Windows CE MIPS: COFF machine 0x0166 is little-endian R4000. The lane commits
// the decimal machine, so the tests spell both forms instead of importing the
// production constant they check.
const R4000 = 0x0166;

const mipsPe = (
  change: Partial<
    Pick<PeTarget, "peMachine" | "executableRole" | "managed">
  > = {},
): PeTarget => ({
  path: "/fixture.exe",
  sha256: "a".repeat(64),
  kind: "executable",
  format: "pe",
  architecture: "mips",
  availableArchitectures: ["mips"],
  peMachine: R4000,
  executableRole: "application",
  managed: false,
  ...change,
});
const unobservedMachine = (): PeTarget => {
  const { peMachine: _machine, ...unobserved } = mipsPe();
  void _machine;
  return unobserved;
};
const x86Pe: BinaryTarget = {
  path: "/fixture.exe",
  sha256: "a".repeat(64),
  kind: "executable",
  format: "pe",
  architecture: "x86",
  availableArchitectures: ["x86"],
  peMachine: 0x014c,
  executableRole: "application",
  managed: false,
};
const x86Elf: BinaryTarget = {
  path: "/fixture.elf",
  sha256: "b".repeat(64),
  kind: "executable",
  format: "elf",
  architecture: "x86_64",
  availableArchitectures: ["x86_64"],
};
// A recordless legacy header is the ELF MIPS shape that Ghidra also pins to
// MIPS:LE:32:default, so it is the closest neighbour of the PE pin.
const legacyMipsElf: BinaryTarget = {
  path: "/fixture-mips.elf",
  sha256: "c".repeat(64),
  kind: "executable",
  format: "elf",
  architecture: "mips",
  availableArchitectures: ["mips"],
  mips: {
    elfClass: 32,
    byteOrder: "little",
    type: 2,
    flags: 0x50000001,
    abiFlags: null,
    gnuAttributes: null,
  },
};

const PIN = { languageId: "MIPS:LE:32:default", compilerSpecId: "windows" };

// One refusal per admission rule, ordered as the lane applies them: machine,
// then image role, then managed status.
const refusals = [
  ["an unobserved COFF machine", unobservedMachine(), "was not observed"],
  [
    "another MIPS COFF machine",
    mipsPe({ peMachine: 0x0162 }),
    "machine 0x0162",
  ],
  [
    "a non-executable image",
    mipsPe({ executableRole: "non-executable" }),
    "applications and DLLs, not non-executable",
  ],
  [
    "a managed image",
    mipsPe({ managed: true }),
    "native PE applications and DLLs; managed",
  ],
] satisfies readonly (readonly [string, PeTarget, string])[];

describe("Ghidra MIPS PE lane boundary", () => {
  it.each(["application", "shared-library"] as const)(
    "admits a native R4000 %s and pins the Windows language",
    (executableRole) => {
      const value = mipsPe({ executableRole });
      expect(ghidraMipsPeUnsupportedReason(value)).toBeNull();
      expect(ghidraMipsPeLanguage(value)).toEqual(PIN);
      expect(ghidraPinnedLanguage(value)).toEqual(PIN);
      expect(ghidraMipsPeProfileParameters(value)).toEqual({
        pe_machine: 358,
        mips_support_lane: "pe32-coff-r4000-le-windows-cspec-v1",
        mips_abi_basis: "coff-machine-language-assumption-v1",
        instruction_context_evidence: "per-address-isa-mode-v1",
      });
    },
  );

  it.each(refusals)("refuses %s", (_label, value, reason) => {
    expect(ghidraMipsPeUnsupportedReason(value)).toContain(reason);
    // Neither the pin nor the committed facts exist for an unadmitted image.
    expect(ghidraMipsPeLanguage(value)).toBeUndefined();
    expect(ghidraPinnedLanguage(value)).toBeUndefined();
    expect(ghidraMipsPeProfileParameters(value)).toEqual({});
  });

  it.each(["0160", "0162", "0168", "0169", "0266", "0366", "0466"])(
    "refuses the unverified MIPS COFF machine 0x%s",
    (hex) => {
      const value = mipsPe({ peMachine: Number.parseInt(hex, 16) });
      const reason = ghidraMipsPeUnsupportedReason(value);
      expect(reason).toContain("0x0166 (R4000) only");
      expect(reason).toContain(`machine 0x${hex} selects`);
      expect(ghidraMipsPeLanguage(value)).toBeUndefined();
      expect(ghidraMipsPeProfileParameters(value)).toEqual({});
    },
  );

  it("leaves every other target to its own lane", () => {
    for (const value of [x86Pe, x86Elf, legacyMipsElf]) {
      expect(ghidraMipsPeUnsupportedReason(value)).toBeNull();
      expect(ghidraMipsPeLanguage(value)).toBeUndefined();
      expect(ghidraMipsPeProfileParameters(value)).toEqual({});
      expect(ghidraMipsPeLimitations(value)).toEqual([]);
    }
    // The ELF pin is unchanged and never inherits the PE compiler specification.
    expect(ghidraPinnedLanguage(legacyMipsElf)).toEqual({
      languageId: "MIPS:LE:32:default",
      compilerSpecId: "default",
    });
  });

  it("gives a PE no ELF MIPS pin, facts or reasons", () => {
    const value = mipsPe();
    expect(ghidraMipsLanguageOverride(value)).toBeUndefined();
    expect(ghidraMipsProfileParameters(value)).toEqual({});
    expect(ghidraMipsProfileParameters(value, PIN)).toEqual({});
    // The ELF reasoner would refuse a PE for lacking ELF metadata; the Ghidra
    // dispatcher must consult the PE lane first, for admitted and refused images.
    expect(ghidraMipsUnsupportedReason(value)).toContain("requires ELF header");
    expect(ghidraProcessorUnsupportedReason(value)).toBeNull();
    expect(
      ghidraProcessorUnsupportedReason(mipsPe({ peMachine: 0x0162 })),
    ).toBe(ghidraMipsPeUnsupportedReason(mipsPe({ peMachine: 0x0162 })));
  });

  it("states the pinned language and the claims it cannot make", () => {
    const notes = ghidraMipsPeLimitations(mipsPe());
    expect(notes).toHaveLength(3);
    expect(notes[0]).toContain("`MIPS:LE:32:default`");
    expect(notes[0]).toContain("`windows` compiler specification");
    expect(notes[0]).toContain("0x0166");
    expect(notes[0]).toContain(
      "MIPS III 64-bit instructions are not faithfully modeled",
    );
    expect(notes[0]).toContain(
      "`daddu` decodes with 32-bit register semantics",
    );
    expect(notes[0]).toContain("`dsll` is not decoded");
    expect(notes[1]).toContain("share `mips32le.cspec`");
    expect(notes[1]).toContain("an assumption of this lane");
    expect(notes[2]).toContain("subsystem and operating system");
    expect(notes[2]).toContain("Windows CE");
    expect(notes[2]).toContain("not inspected");
  });
});

const macHost: GhidraInstallationHost = {
  ...host,
  platform: "darwin",
  probeJava: (command, environment) => {
    const observed = host.probeJava(command, environment);
    return observed === undefined
      ? undefined
      : { ...observed, osName: "Mac OS X" };
  },
};
const windowsHost: GhidraInstallationHost = { ...host, platform: "win32" };

const configOf = (environment: Record<string, string> = {}) => {
  const parsed = parseConfig({ GHIDRA_INSTALL_DIR: "/ghidra", ...environment });
  if (!parsed.ok) throw parsed.error;
  return parsed.value;
};
const ghidraOn = (installationHost: GhidraInstallationHost = host) =>
  new GhidraProvider(configOf(), silentLogger, {}, installationHost);

describe("Ghidra MIPS PE host admission", () => {
  it.each([
    ["linux", host],
    ["darwin", macHost],
  ] as const)(
    "admits a native R4000 EXE and DLL on a %s host",
    async (platform, installationHost) => {
      const ghidra = ghidraOn(installationHost);
      expect(ghidra.inspectAvailability()).toMatchObject({
        status: "available",
      });
      for (const executableRole of ["application", "shared-library"] as const) {
        const value = mipsPe({ executableRole });
        expect(ghidra.inspectTargetSupport(value)).toMatchObject({
          status: "supported",
          code: null,
          reason: null,
          diagnostics: {
            host_platform: platform,
            target_format: "pe",
            architecture: "mips",
            executable_role: executableRole,
            managed: false,
          },
        });
        expect((await ghidra.resolveAnalysisProfile(value)).ok).toBe(true);
      }
    },
  );

  it.each(refusals)(
    "refuses %s on a Linux host before any profile is resolved",
    async (_label, value, reason) => {
      const ghidra = ghidraOn();
      expect(ghidra.inspectTargetSupport(value)).toMatchObject({
        status: "unsupported",
        code: "architecture_unsupported",
        reason: expect.stringContaining(reason),
      });
      expect(await ghidra.resolveAnalysisProfile(value)).toMatchObject({
        ok: false,
        error: {
          _tag: "AnalysisUnsupportedTargetError",
          reason: expect.stringContaining(reason),
        },
      });
    },
  );

  it("refuses an unadmitted R4000 image on macOS with the same reason", () => {
    expect(
      ghidraOn(macHost).inspectTargetSupport(mipsPe({ managed: true })),
    ).toMatchObject({
      status: "unsupported",
      code: "architecture_unsupported",
      reason: expect.stringContaining(
        "native PE applications and DLLs; managed",
      ),
    });
  });

  it("keeps Windows P0 closed to every MIPS PE, admitted or not", () => {
    const ghidra = ghidraOn(windowsHost);
    // The architecture rule comes first, so role and managed status never
    // change the code and a Linux-admissible image is still refused here.
    for (const value of [
      mipsPe(),
      mipsPe({ executableRole: "shared-library" }),
      ...refusals.map(([, refused]) => refused),
    ])
      expect(ghidra.inspectTargetSupport(value)).toMatchObject({
        status: "unsupported",
        code: "architecture_unsupported",
        reason:
          "Windows Ghidra P0 accepts x86, x86-64, ARM and ARM64 PE targets only.",
        diagnostics: { host_platform: "win32", architecture: "mips" },
      });
  });
});

// A language definition modeled on the lane's own notes (a `windows` and a
// `default` compiler specification, both mips32le.cspec). It is not copied from
// a Ghidra installation; it makes the pin and a neighbouring valid language
// resolvable so a refusal can only come from the REA lane.
const MIPS_LDEFS = `<?xml version="1.0" encoding="UTF-8"?>
<language_definitions>
  <language processor="MIPS" endian="little" size="32" variant="default"
            id="MIPS:LE:32:default">
    <compiler name="default" spec="mips32le.cspec" id="default"/>
    <compiler name="Visual Studio" spec="mips32le.cspec" id="windows"/>
  </language>
  <language processor="MIPS" endian="big" size="32" variant="default"
            id="MIPS:BE:32:default">
    <compiler name="default" spec="mips32be.cspec" id="default"/>
  </language>
</language_definitions>
`;

const installationWithMipsLanguages = async (): Promise<string> => {
  const installDir = await createTestTempDirectory("rea-ghidra-mips-pe-");
  const languages = join(installDir, "Ghidra/Processors/MIPS/data/languages");
  await mkdir(languages, { recursive: true });
  await writeFile(join(languages, "mips.ldefs"), MIPS_LDEFS);
  return installDir;
};

const resolved = async (
  value: BinaryTarget,
  environment: Record<string, string> = {},
) => {
  const result = await new GhidraProvider(
    configOf(environment),
    silentLogger,
    {},
    host,
  ).resolveAnalysisProfile(value);
  if (!result.ok || result.value.profile === null)
    throw result.ok ? new Error("expected a resolved profile") : result.error;
  return result.value.profile;
};

describe("Ghidra MIPS PE analysis profile", () => {
  it("commits the pinned Windows language and the lane facts", async () => {
    const profile = await resolved(mipsPe());
    expect(profile.parameters).toMatchObject({
      target_kind: "executable",
      target_format: "pe",
      architecture: "mips",
      available_architectures: ["mips"],
      executable_role: "application",
      managed: false,
      loader: "auto-from-header",
      language_id: "MIPS:LE:32:default",
      compiler_spec_id: "windows",
      language_selection: "provider-pinned-v1",
      pe_machine: 358,
      mips_support_lane: "pe32-coff-r4000-le-windows-cspec-v1",
      mips_abi_basis: "coff-machine-language-assumption-v1",
      instruction_context_evidence: "per-address-isa-mode-v1",
    });
    // A PE carries its raw machine, never ELF family metadata.
    expect(profile.parameters).not.toHaveProperty("mips_elf");
    expect(profile.parameters).not.toHaveProperty("mips_soft_float_storage");
    // The committed slot is what the session readback compares to the pin.
    expect(
      sameGhidraLanguageOverride(
        ghidraProfileLanguageOverride(profile.parameters),
        ghidraPinnedLanguage(mipsPe()),
      ),
    ).toBe(true);
  });

  it("resolves the same image identically and tells images apart", async () => {
    const first = await resolved(mipsPe());
    const second = await resolved(mipsPe());
    expect(second.parameters).toEqual(first.parameters);
    expect(second.digest).toBe(first.digest);
    const library = await resolved(
      mipsPe({ executableRole: "shared-library" }),
    );
    expect(library.parameters).toMatchObject({
      executable_role: "shared-library",
      pe_machine: 358,
    });
    expect(library.digest).not.toBe(first.digest);
    // An x86 PE of the same path and digest gets neither the pin nor the facts.
    const x86 = await resolved(x86Pe);
    expect(x86.digest).not.toBe(first.digest);
    for (const key of [
      "pe_machine",
      "mips_support_lane",
      "mips_abi_basis",
      "instruction_context_evidence",
      "language_selection",
    ])
      expect(x86.parameters).not.toHaveProperty(key);
  });

  it("gives an ELF MIPS profile none of the PE facts", async () => {
    const profile = await resolved(legacyMipsElf);
    expect(profile.parameters).toMatchObject({
      language_id: "MIPS:LE:32:default",
      compiler_spec_id: "default",
      mips_support_lane: "elf32-exec-arch32-legacy-pinned-v1",
    });
    for (const key of ["pe_machine", "executable_role", "managed"])
      expect(profile.parameters).not.toHaveProperty(key);
  });
});

describe("Ghidra MIPS PE language selection", () => {
  it("keeps a configured language that equals the pin as configured", async () => {
    const installDir = await installationWithMipsLanguages();
    const provider = new GhidraProvider(
      configOf({
        GHIDRA_INSTALL_DIR: installDir,
        REA_GHIDRA_LANGUAGE_ID: "MIPS:LE:32:default",
        REA_GHIDRA_COMPILER_SPEC_ID: "windows",
      }),
      silentLogger,
      {},
      host,
    );
    const result = await provider.resolveAnalysisProfile(mipsPe());
    if (!result.ok || result.value.profile === null)
      throw result.ok ? new Error("expected a profile") : result.error;
    expect(result.value.profile.parameters).toMatchObject({
      language_id: "MIPS:LE:32:default",
      compiler_spec_id: "windows",
      language_selection: "configured-v1",
      pe_machine: 358,
    });
    expect(
      ghidraProfileLanguageOverride(result.value.profile.parameters),
    ).toEqual(PIN);
  });

  it.each([
    [
      "a different compiler specification",
      { id: "MIPS:LE:32:default", spec: "default" },
    ],
    ["a big-endian language", { id: "MIPS:BE:32:default", spec: "default" }],
  ])("refuses %s as outside the verified profile", async (_label, selected) => {
    const installDir = await installationWithMipsLanguages();
    const provider = new GhidraProvider(
      configOf({
        GHIDRA_INSTALL_DIR: installDir,
        REA_GHIDRA_LANGUAGE_ID: selected.id,
        REA_GHIDRA_COMPILER_SPEC_ID: selected.spec,
      }),
      silentLogger,
      {},
      host,
    );
    // Both languages exist in the catalog, so only the PE lane can refuse them.
    expect(await provider.resolveAnalysisProfile(mipsPe())).toMatchObject({
      ok: false,
      error: {
        _tag: "AnalysisUnsupportedTargetError",
        reason: expect.stringContaining(
          "outside the verified little-endian MIPS32 Windows PE profile. The requested override has not been changed.",
        ),
      },
    });
  });

  // The pinned `windows` specification is not the language's default one, so a
  // language-only selection would import another specification while the
  // profile described the pin.
  it("refuses a language-only selection and names the pinned specification", async () => {
    const installDir = await installationWithMipsLanguages();
    const provider = new GhidraProvider(
      configOf({
        GHIDRA_INSTALL_DIR: installDir,
        REA_GHIDRA_LANGUAGE_ID: "MIPS:LE:32:default",
      }),
      silentLogger,
      {},
      host,
    );
    expect(await provider.resolveAnalysisProfile(mipsPe())).toMatchObject({
      ok: false,
      error: {
        _tag: "AnalysisUnsupportedTargetError",
        reason: expect.stringContaining(
          "Name the pinned compiler specification as well (REA_GHIDRA_COMPILER_SPEC_ID=windows). The requested override has not been changed.",
        ),
      },
    });
  });

  it("keeps a language-only selection valid for lanes that pin their default specification", async () => {
    const installDir = await installationWithMipsLanguages();
    const provider = new GhidraProvider(
      configOf({
        GHIDRA_INSTALL_DIR: installDir,
        REA_GHIDRA_LANGUAGE_ID: "MIPS:LE:32:default",
      }),
      silentLogger,
      {},
      host,
    );
    // The legacy ELF MIPS lane lets the caller choose, and pins `default`.
    const result = await provider.resolveAnalysisProfile(legacyMipsElf);
    expect(result.ok).toBe(true);
  });
});

const sessionInfo = {
  name: "REA Ghidra bridge" as const,
  run_id: "11111111-1111-4111-8111-111111111111",
  profile_digest: "a".repeat(64),
  provider: { id: "ghidra" as const, version: "12.1.4" },
  read_only: false as const,
  analysis_complete: true,
  analysis_timed_out: false,
  capabilities: [...GHIDRA_SESSION_CAPABILITIES],
  target: {
    name: "fixture.exe",
    language_id: "MIPS:LE:32:default",
    compiler_spec_id: "windows",
    image_base: "0x400000",
    default_address_space: "ram",
    sha256: "a".repeat(64),
  },
};

// The profile is resolved for `profileFor` and then bound to `value`, as a
// session does when its committed profile and target must still agree.
const session = async (
  value: BinaryTarget,
  profileFor: BinaryTarget = value,
) => {
  const counts = { starts: 0, calls: 0, closes: 0 };
  const created: GhidraClientOptions[] = [];
  const ghidra = new GhidraProvider(
    configOf(),
    silentLogger,
    {},
    host,
    (options) => {
      created.push(options);
      return {
        start: () => {
          counts.starts++;
          return Promise.resolve(ok(sessionInfo));
        },
        callTool: () => {
          counts.calls++;
          return Promise.resolve(ok(null));
        },
        close: () => {
          counts.closes++;
          return Promise.resolve(ok(null));
        },
      };
    },
  );
  const result = await ghidra.resolveAnalysisProfile(profileFor);
  if (!result.ok || result.value.profile === null)
    throw result.ok ? new Error("expected a profile") : result.error;
  return {
    counts,
    created,
    client: ghidra.createClient(value, result.value.profile),
  };
};

describe("Ghidra MIPS PE session", () => {
  it("hands the pinned language to the launcher and the handshake check", async () => {
    const { created, client } = await session(mipsPe());
    const [options] = created;
    if (options === undefined) throw new Error("expected a client");
    expect(options.expectedLanguageId).toBe("MIPS:LE:32:default");
    expect(options.expectedCompilerSpecId).toBe("windows");
    const launcher = options.launcher;
    if (!(launcher instanceof GhidraHeadlessLauncher))
      throw new Error("expected the headless launcher");
    const pinned = launcher.options.languageOverride;
    if (pinned === undefined) throw new Error("expected a pinned language");
    expect(pinned).toEqual(PIN);
    // None of the other import shapes applies to a native MIPS PE.
    for (const unrelated of [
      "mipsSoftFloat",
      "pspExtension",
      "dosMz",
      "dosCom",
      "rawBinary",
    ] as const)
      expect(launcher.options[unrelated]).toBeUndefined();
    const arguments_ = ghidraHeadlessArguments({
      platform: "linux",
      projectRoot: "/tmp/project",
      targetPath: "/tmp/target.exe",
      bridgeScriptPath: launcher.options.bridgeScriptPath,
      descriptorPath: "/tmp/session.json",
      ghidraLogPath: "/tmp/ghidra.log",
      scriptLogPath: "/tmp/script.log",
      languageOverride: pinned,
    });
    expect(arguments_[arguments_.indexOf("-processor") + 1]).toBe(
      "MIPS:LE:32:default",
    );
    expect(arguments_[arguments_.indexOf("-cspec") + 1]).toBe("windows");
    expect(arguments_).not.toContain("-loader");
    expect(arguments_.join(" ")).not.toMatch(
      /ReaGhidraMipsSoftFloat|PspElfLoader/u,
    );
    await client.close();
  });

  it("reports the lane limitations on the session", async () => {
    const { counts, client } = await session(mipsPe());
    const health = await client.execute("health", {});
    if (!health.ok) throw health.error;
    expect(counts.starts).toBe(1);
    expect(health.value.limitations).toEqual(
      expect.arrayContaining([
        expect.stringContaining("MIPS PE: REA pins Ghidra's"),
        expect.stringContaining("share `mips32le.cspec`"),
        expect.stringContaining("not inspected"),
      ]),
    );
  });

  it.each([
    ["an x86 PE that carries no pin", x86Pe, mipsPe()],
    ["an R4000 PE bound to an unpinned profile", mipsPe(), x86Pe],
  ] satisfies readonly (readonly [string, BinaryTarget, BinaryTarget])[])(
    "refuses to start for %s",
    async (_label, value, profileFor) => {
      const { counts, created, client } = await session(value, profileFor);
      expect((await client.execute("health", {})).ok).toBe(false);
      expect(counts.starts).toBe(0);
      expect(created).toEqual([]);
    },
  );
});
