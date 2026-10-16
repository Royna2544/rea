#!/usr/bin/env node
import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { createHash } from "node:crypto";
import {
  mkdir,
  mkdtemp,
  readFile,
  readdir,
  rm,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";
import { Client } from "@modelcontextprotocol/client";
import { StdioClientTransport } from "@modelcontextprotocol/client/stdio";
import { parseEvidence } from "../dist/domain/evidence.js";
import {
  functionBodySchema,
  functionDossierSchema,
} from "../dist/domain/hopperValues.js";
import { inspectGhidraInstallation } from "../dist/ghidra/GhidraInstallation.js";
import { buildMipsPeFixture } from "../tests/conformance/ghidra/mips-pe-fixture.mjs";
import { requireMcpOperationResult } from "./lib/mcp-verifier-results.mjs";
import {
  assertVerifierCleanupComplete,
  completeVerifierRun,
  createVerifierRun,
} from "./lib/verifier-run.mjs";

// Optional cross-target lane. Hand-encoded fixture bytes, no compiler, no binary
// seed and no tool acquisition. REA never executes the target.
if (process.argv.length !== 2)
  throw new Error("Usage: node scripts/verify-real-ghidra-mips-pe.mjs");
if (!["linux", "darwin", "win32"].includes(process.platform))
  throw new Error(
    "verify:ghidra:mips-pe supports Linux, macOS and Windows x64 hosts only.",
  );
if (process.platform === "win32" && process.arch !== "x64")
  throw new Error("verify:ghidra:mips-pe requires a Windows x64 host.");
if (process.env.GHIDRA_INSTALL_DIR === undefined)
  throw new Error(
    "verify:ghidra:mips-pe prerequisite missing: GHIDRA_INSTALL_DIR (bring your own Ghidra).",
  );
const installation = inspectGhidraInstallation({
  environment: process.env,
  installDir: process.env.GHIDRA_INSTALL_DIR,
  ...(process.env.JAVA_HOME === undefined
    ? {}
    : { javaHome: process.env.JAVA_HOME }),
});
if (installation.status !== "available")
  throw new Error(
    `verify:ghidra:mips-pe prerequisite unavailable: ${JSON.stringify(installation)}`,
  );

const run = createVerifierRun();
const workspace = await mkdtemp(join(tmpdir(), "rea-mips-pe-proof-"));
const runtime = join(workspace, "runtime");
await mkdir(runtime);
const entrypoint = fileURLToPath(new URL("./rea.mjs", import.meta.url));
// Windows children need the system variables Node and the JVM resolve at start
// (SystemRoot, TEMP, PATHEXT); everything else is left out.
const WINDOWS_CHILD_VARIABLES = [
  "SystemRoot",
  "SystemDrive",
  "windir",
  "ComSpec",
  "PATHEXT",
  "USERPROFILE",
  "APPDATA",
  "LOCALAPPDATA",
  "ProgramData",
  "ProgramFiles",
  "USERNAME",
  "USERDOMAIN",
  "COMPUTERNAME",
  "PROCESSOR_ARCHITECTURE",
  "NUMBER_OF_PROCESSORS",
  "OS",
];
const baseEnv = {
  PATH: process.env.PATH ?? "/usr/bin:/bin",
  TMPDIR: runtime,
  ...(process.platform === "win32"
    ? {
        TEMP: runtime,
        TMP: runtime,
        ...Object.fromEntries(
          WINDOWS_CHILD_VARIABLES.flatMap((name) =>
            process.env[name] === undefined ? [] : [[name, process.env[name]]],
          ),
        ),
      }
    : {}),
  REA_LOG_LEVEL: "silent",
  REA_ANALYSIS_PROVIDER: "ghidra",
  REA_PROCESS_RUN_ID: run.run_id,
  HOPPER_LAUNCHER_PATH: "/rea-unconfigured-deep-provider/hopper",
  GHIDRA_INSTALL_DIR: process.env.GHIDRA_INSTALL_DIR,
  ...(process.env.JAVA_HOME === undefined
    ? {}
    : { JAVA_HOME: process.env.JAVA_HOME }),
};

const digest = (bytes) => createHash("sha256").update(bytes).digest("hex");
const targets = {};
for (const [name, options] of Object.entries({
  exe: {},
  dll: { image: "dll" },
  daddu: { daddu: true },
  dsll: { dsll: true },
  r3000: { machine: 0x0162 },
})) {
  const fixture = buildMipsPeFixture(options);
  const path = join(
    workspace,
    `${name}.${options.image === "dll" ? "dll" : "exe"}`,
  );
  await writeFile(path, fixture.bytes, { mode: 0o600 });
  targets[name] = { fixture, path, sha256: digest(fixture.bytes) };
}
const { fixture } = targets.exe;
const expectedEntryBytes = fixture.entry_instruction_bytes.join("");
const expectedEntryInstructions = [
  `${fixture.entry}: addiu sp, sp, -0x10`,
  "0x11004: sw ra, 0xc(sp)",
  "0x11008: li a0, 0x3",
  `${fixture.jal}: jal 0x00011024`,
  "0x11010: _li a1, 0x4",
  "0x11014: lw ra, 0xc(sp)",
  "0x11018: addiu sp, sp, 0x10",
  "0x1101c: jr ra",
  "0x11020: _nop",
];

let current;
let opened = false;
let stderr = "";
let report;

/** Run one MCP session against the real Ghidra adapter with extra environment. */
const withClient = async (extraEnv, name, work) => {
  const transport = new StdioClientTransport({
    command: process.execPath,
    args: [entrypoint, "mcp"],
    env: { ...baseEnv, ...extraEnv },
    stderr: "pipe",
  });
  const client = new Client({ name, version: "1" });
  const previous = current;
  current = client;
  try {
    await client.connect(transport);
    transport.stderr?.on("data", (chunk) => {
      stderr = (stderr + chunk.toString()).slice(-65536);
    });
    return await work(client);
  } finally {
    try {
      if (opened) {
        opened = false;
        await client.callTool({ name: "close_binary", arguments: {} });
      }
    } finally {
      try {
        await client.close();
      } finally {
        await transport.close();
        current = previous;
      }
    }
  }
};

try {
  report = await withClient({}, "rea-real-mips-pe-proof", async (client) => {
    const exe = targets.exe;
    const opening = await call("open_binary", {
      path: exe.path,
      provider_id: "ghidra",
    });
    opened = true;
    assert.equal(opening.kind, "executable");
    assert.equal(opening.format, "pe");
    assert.equal(opening.architecture, "mips");
    assert.equal(opening.sha256, exe.sha256);

    const session = await call("binary_session");
    const profile = session.analysis_provider_binding?.analysis_profile;
    assert.ok(profile, "Public session omitted the committed profile");
    assertProfile(profile, "application");

    // PE has no independent attestation, but the observations still carry the
    // facts Ghidra loaded; the hashes below come from the encoded fixture bytes.
    const image = await call("inspect_native_load_image");
    assert.equal(image.status, "unsupported");
    assert.equal(
      image.observations.executable_format,
      "Portable Executable (PE)",
    );
    assert.equal(image.observations.language_id, "MIPS:LE:32:default");
    assert.equal(image.observations.compiler_spec_id, "windows");
    assert.equal(image.observations.image_base, fixture.image_base);
    assert.deepEqual(image.observations.entry_points, [fixture.entry]);
    assert.deepEqual(
      image.observations.mappings.map(
        ({ block, start, end, file_offset, sha256 }) => ({
          block,
          start,
          end,
          file_offset,
          sha256,
        }),
      ),
      [
        {
          block: "Headers",
          start: fixture.image_base,
          end: "0x101ff",
          file_offset: 0,
          sha256: digest(exe.fixture.bytes.subarray(0, 0x200)),
        },
        {
          block: ".text",
          start: fixture.text_start,
          end: "0x111ff",
          file_offset: fixture.text_file_offset,
          sha256: digest(exe.fixture.bytes.subarray(0x200, 0x400)),
        },
      ],
    );
    assert.deepEqual(image.observations.relocations, []);

    const procedures = await call("list_procedures");
    assert.deepEqual(
      procedures.map(({ address }) => address),
      [fixture.entry, fixture.helper],
      "Entry flow and the direct call did not recover exactly the two source functions",
    );

    const entryInfo = await call("procedure_info", {
      procedure: fixture.entry,
    });
    assertBody(entryInfo.body, fixture.entry, fixture.entry_end);
    const helperInfo = await call("procedure_info", {
      procedure: fixture.helper,
    });
    assertBody(helperInfo.body, fixture.helper, fixture.helper_end);

    const window = await call("read_function_instructions", {
      procedure: fixture.entry,
    });
    assert.deepEqual(window.instructions, expectedEntryInstructions);

    const bytes = await call("read_bytes", {
      address: fixture.entry,
      length: 36,
    });
    assert.equal(bytes.complete, true);
    assert.equal(bytes.bytes_hex, expectedEntryBytes);
    const fileOffset = await call("address_to_file_offset", {
      address: fixture.entry,
    });
    assert.equal(fileOffset.file_offset, fixture.text_file_offset);
    assert.equal(
      exe.fixture.bytes
        .subarray(fileOffset.file_offset, fileOffset.file_offset + 36)
        .toString("hex"),
      expectedEntryBytes,
    );

    const jal = await call("inspect_native_instruction", {
      address: fixture.jal,
    });
    assert.equal(jal.status, "decoded");
    assert.equal(jal.architecture, "MIPS:LE:32:default");
    assert.equal(jal.mnemonic, "jal");
    assert.equal(jal.bytes, fixture.entry_instruction_bytes[3]);
    assert.equal(jal.flow.kind, "call");
    assert.deepEqual(jal.flow.direct_destinations, [fixture.helper]);
    assert.ok(
      jal.decoder_context.some(
        ({ register, source }) =>
          register === "ISA_MODE" && source === "ghidra-program-context",
      ),
      "Decoder context omitted the ISA_MODE register the profile commits",
    );
    const targetsResolved = await call("resolve_native_call_targets", {
      address: fixture.jal,
    });
    assert.equal(targetsResolved.status, "direct");
    assert.ok(
      targetsResolved.targets.some(({ address }) => address === fixture.helper),
    );
    const delaySlot = await call("inspect_native_instruction", {
      address: "0x11010",
    });
    assert.equal(delaySlot.status, "decoded");
    assert.equal(delaySlot.bytes, fixture.entry_instruction_bytes[4]);

    const dossierEvidence = await evidenceCall(
      "analyze_function",
      { procedure: fixture.entry },
      exe,
    );
    const dossier = functionDossierSchema.parse(
      dossierEvidence.normalized_result,
    );
    assert.match(dossier.pseudocode, /FUN_00011024\(3,\s*4\)/u);
    assertBody(dossier.procedure.body, fixture.entry, fixture.entry_end);
    assert.ok(
      dossierEvidence.limitations.some((text) =>
        text.includes("MIPS PE: REA pins Ghidra's"),
      ),
      "Evidence omitted the MIPS PE lane limitations",
    );

    const cli = await cliEvidence("function", exe, fixture.entry);
    assert.deepEqual(
      stableDossierObservations(
        functionDossierSchema.parse(cli.normalized_result),
      ),
      stableDossierObservations(dossier),
      "CLI/MCP stable MIPS PE dossier observations differ",
    );
    assert.equal(
      digest(await readFile(exe.path)),
      exe.sha256,
      "Analysis changed original bytes",
    );

    await call("close_binary");
    opened = false;
    assert.equal((await call("binary_session")).open, false);

    // Shared-library role: the same image shape with IMAGE_FILE_DLL set.
    const dll = targets.dll;
    const dllOpening = await call("open_binary", {
      path: dll.path,
      provider_id: "ghidra",
    });
    opened = true;
    assert.equal(dllOpening.architecture, "mips");
    assert.equal(dllOpening.format, "pe");
    const dllProfile = (await call("binary_session")).analysis_provider_binding
      ?.analysis_profile;
    assertProfile(dllProfile, "shared-library");
    assert.deepEqual(
      (await call("list_procedures")).map(({ address }) => address),
      [fixture.entry, fixture.helper],
    );
    await call("close_binary");
    opened = false;

    // Documented limitation, verified rather than assumed: MIPS III opcodes are
    // not faithfully modeled by the pinned 32-bit language. `daddu` decodes with
    // 32-bit register semantics; `dsll` is not decoded and halts the decompiler.
    const daddu = targets.daddu;
    await call("open_binary", { path: daddu.path, provider_id: "ghidra" });
    opened = true;
    const wide = await call("read_function_instructions", {
      procedure: fixture.helper,
    });
    assert.ok(
      wide.instructions.some((text) => /\bdaddu\b/u.test(text)),
      "Expected the MIPS III daddu to be listed",
    );
    const wideDossier = functionDossierSchema.parse(
      (
        await evidenceCall(
          "analyze_function",
          { procedure: fixture.helper },
          daddu,
        )
      ).normalized_result,
    );
    assert.match(wideDossier.pseudocode, /param_1\s*\+\s*param_2/u);
    assert.doesNotMatch(wideDossier.pseudocode, /halt_/u);
    await call("close_binary");
    opened = false;

    const dsll = targets.dsll;
    await call("open_binary", { path: dsll.path, provider_id: "ghidra" });
    opened = true;
    const narrow = await call("read_function_instructions", {
      procedure: fixture.helper,
    });
    // Delay-slot instructions are listed with a `_` prefix, so match the address.
    assert.ok(
      !narrow.instructions.some((text) =>
        text.startsWith(`${fixture.helper_delay_slot}:`),
      ),
      "The dsll delay slot was decoded; the documented MIPS III limitation changed",
    );
    const narrowDossier = functionDossierSchema.parse(
      (
        await evidenceCall(
          "analyze_function",
          { procedure: fixture.helper },
          dsll,
        )
      ).normalized_result,
    );
    assert.match(narrowDossier.pseudocode, /halt_(?:unimplemented|baddata)/u);
    await call("close_binary");
    opened = false;

    return {
      ok: true,
      mocked: false,
      lane: "ghidra-mips-pe",
      host: process.platform,
      provider: { id: "ghidra", version: installation.providerVersion },
      target: {
        format: "pe",
        architecture: "mips",
        coff_machine: fixture.machine,
        sha256: exe.sha256,
        bytes: exe.fixture.bytes.length,
      },
      profile: {
        digest: profile.digest,
        loader: profile.parameters.loader,
        language_id: profile.parameters.language_id,
        compiler_spec_id: profile.parameters.compiler_spec_id,
        language_selection: profile.parameters.language_selection,
        mips_support_lane: profile.parameters.mips_support_lane,
      },
      transport: { cli: true, stdio_mcp: true },
      load_image: {
        attestation: image.status,
        executable_format: image.observations.executable_format,
        mappings: image.observations.mappings.length,
        independent_range_hashes: true,
      },
      functions: {
        entry: {
          body: entryInfo.body,
          instructions: window.instructions.length,
        },
        helper: { body: helperInfo.body },
      },
      instruction_oracles: {
        entry_bytes: bytes.bytes_hex,
        jal_bytes: jal.bytes,
        jal_target: fixture.helper,
        delay_slot_decoded: true,
      },
      shared_library_role_verified: true,
      mips_iii_limitation_verified: {
        daddu_decodes: true,
        dsll_halts_decompiler: true,
      },
      original_unchanged: true,
    };
  });

  // Fail-closed neighbors, each through the production MCP and CLI boundary.
  const refused = await withClient({}, "rea-real-mips-pe-r3000", (client) =>
    refusedOpen(client, targets.r3000.path),
  );
  assert.match(
    refused.message,
    /unsupported PE architecture \(COFF machine 0x0162\)/u,
  );
  const cliRefusal = await promisify(execFile)(
    process.execPath,
    [
      entrypoint,
      "inspect",
      targets.r3000.path,
      "--provider",
      "ghidra",
      "--json",
    ],
    { env: baseEnv, timeout: 240000, maxBuffer: 4 * 1024 * 1024 },
  ).then(
    () =>
      assert.fail("The unverified R3000 machine was admitted through the CLI"),
    (failure) => String(failure.stdout ?? ""),
  );
  assert.match(
    cliRefusal,
    /unsupported PE architecture \(COFF machine 0x0162\)/u,
  );

  const conflicting = await withClient(
    { REA_GHIDRA_LANGUAGE_ID: "x86:LE:32:default" },
    "rea-real-mips-pe-conflict",
    (client) => refusedOpen(client, targets.exe.path),
  );
  assert.match(
    conflicting.message,
    /outside the verified little-endian MIPS32 Windows PE profile\. The requested override has not been changed\./u,
  );
  const languageOnly = await withClient(
    { REA_GHIDRA_LANGUAGE_ID: "MIPS:LE:32:default" },
    "rea-real-mips-pe-language-only",
    (client) => refusedOpen(client, targets.exe.path),
  );
  assert.match(
    languageOnly.message,
    /Name the pinned compiler specification as well \(REA_GHIDRA_COMPILER_SPEC_ID=windows\)\. The requested override has not been changed\./u,
  );
  const configured = await withClient(
    {
      REA_GHIDRA_LANGUAGE_ID: "MIPS:LE:32:default",
      REA_GHIDRA_COMPILER_SPEC_ID: "windows",
    },
    "rea-real-mips-pe-equal-override",
    async () => {
      await call("open_binary", {
        path: targets.exe.path,
        provider_id: "ghidra",
      });
      opened = true;
      const profile = (await call("binary_session")).analysis_provider_binding
        ?.analysis_profile;
      assert.equal(profile.parameters.language_selection, "configured-v1");
      assert.equal(profile.parameters.language_id, "MIPS:LE:32:default");
      assert.equal(profile.parameters.compiler_spec_id, "windows");
      await call("close_binary");
      opened = false;
      return profile.parameters.language_selection;
    },
  );
  report.fail_closed = {
    unverified_machine_refused: "0x0162",
    conflicting_override_refused: true,
    language_only_override_refused: true,
    equal_override_selection: configured,
  };
} catch (error) {
  if (stderr.trim())
    process.stderr.write(`MIPS PE verifier MCP diagnostics:\n${stderr}\n`);
  throw error;
} finally {
  try {
    for (const target of Object.values(targets))
      assert.equal(
        digest(await readFile(target.path)),
        target.sha256,
        `${target.path} changed during verification`,
      );
    const leftovers = (await readdir(runtime)).filter((name) =>
      name.startsWith("rea-ghidra-"),
    );
    assert.deepEqual(leftovers, [], "Owned Ghidra runtime survived close");
  } finally {
    await rm(workspace, { recursive: true, force: true });
  }
}
assert.ok(report, "No MIPS PE proof report was produced");
const verifierRun = await completeVerifierRun(run);
// The verifier holds no Job Object lease on Windows, so its lineage observation
// is unavailable there; the provider's native owners verify their own cleanup.
const lineageVerified = verifierRun.process_lineage.status === "verified";
if (process.platform !== "win32")
  assertVerifierCleanupComplete(verifierRun.process_lineage);
process.stdout.write(
  `${JSON.stringify({
    verifier_run: verifierRun,
    ...report,
    cleanup: lineageVerified ? "complete" : "provider-owned",
  })}\n`,
);

function assertProfile(profile, role) {
  assert.ok(profile, "Profile missing");
  assert.equal(profile.provider.id, "ghidra");
  const parameters = profile.parameters;
  assert.equal(parameters.target_kind, "executable");
  assert.equal(parameters.target_format, "pe");
  assert.equal(parameters.architecture, "mips");
  assert.deepEqual(parameters.available_architectures, ["mips"]);
  assert.equal(parameters.executable_role, role);
  assert.equal(parameters.managed, false);
  assert.equal(parameters.import_mode, "ephemeral-source-immutable");
  assert.equal(parameters.loader, "auto-from-header");
  assert.equal(parameters.language_id, "MIPS:LE:32:default");
  assert.equal(parameters.compiler_spec_id, "windows");
  assert.equal(parameters.language_selection, "provider-pinned-v1");
  assert.equal(parameters.pe_machine, fixture.machine);
  assert.equal(
    parameters.mips_support_lane,
    "pe32-coff-r4000-le-windows-cspec-v1",
  );
  assert.equal(
    parameters.mips_abi_basis,
    "coff-machine-language-assumption-v1",
  );
  assert.equal(
    parameters.instruction_context_evidence,
    "per-address-isa-mode-v1",
  );
}

function assertBody(input, start, end) {
  const body = functionBodySchema.parse(input);
  assert.equal(body.available, true);
  assert.equal(body.provenance, "ghidra-function-body-address-set");
  assert.deepEqual(body.ranges, [{ start, end }]);
  assert.equal(body.contains_entry, true);
  assert.equal(body.non_contiguous, false);
  assert.equal(BigInt(body.total_bytes), BigInt(end) - BigInt(start) + 1n);
}

async function call(name, arguments_ = {}) {
  const result = await current.callTool(
    { name, arguments: arguments_ },
    { timeout: 240000 },
  );
  assert.notEqual(result.isError, true, JSON.stringify(result));
  assert.ok(result.structuredContent, `${name} omitted structured result`);
  return requireMcpOperationResult(result, name);
}

async function evidenceCall(name, arguments_, target) {
  const result = await current.callTool(
    { name, arguments: arguments_ },
    { timeout: 240000 },
  );
  assert.notEqual(result.isError, true, JSON.stringify(result));
  const evidence = parseEvidence(result.structuredContent);
  assert.equal(evidence.subject.digest.sha256, target.sha256);
  assert.equal(evidence.provider.id, "ghidra");
  assert.equal(evidence.subject.architecture, "mips");
  return evidence;
}

async function refusedOpen(client, path) {
  const result = await client.callTool(
    { name: "open_binary", arguments: { path, provider_id: "ghidra" } },
    { timeout: 240000 },
  );
  assert.equal(
    result.isError,
    true,
    "The target was admitted but must be refused",
  );
  const text = result.content?.find((part) => part.type === "text")?.text ?? "";
  return { message: JSON.parse(text).error.message };
}

async function cliEvidence(command, target, procedure) {
  const { stdout } = await promisify(execFile)(
    process.execPath,
    [
      entrypoint,
      command,
      target.path,
      procedure,
      "--provider",
      "ghidra",
      "--json",
    ],
    { env: baseEnv, timeout: 240000, maxBuffer: 16 * 1024 * 1024 },
  );
  const evidence = parseEvidence(JSON.parse(stdout));
  assert.equal(evidence.subject.digest.sha256, target.sha256);
  assert.equal(evidence.provider.id, "ghidra");
  assert.equal(digest(await readFile(target.path)), target.sha256);
  return evidence;
}

// Raw high-pcode address-space selector tokens are process-specific; every
// other body, instruction, decompilation and reference observation is compared.
function stableDossierObservations(dossier) {
  const { native_value_flow: flow, ...observations } = dossier;
  assert.ok(flow, "Dossier omitted native value-flow availability");
  return observations;
}
