# MIPS PE analysis through Ghidra

This lane extends native PE analysis for COFF machine `0x0166`
(`IMAGE_FILE_MACHINE_R4000`, little-endian MIPS), the machine declared by Windows
CE MIPS images. It does not execute MIPS code, emulate Windows CE, or rehost a
device. It follows the lane shape of [MIPS ELF support](ghidra-mips.md) and
[RISC-V support](ghidra-riscv.md).

## Admission boundary

A PE whose COFF machine is `0x0166` is retained as the provider-neutral `mips`
family. Unlike MIPS ELF, the target carries no ELF metadata: the raw COFF machine
stays on the target and decides the lane. Family recognition does not mean every
provider or MIPS machine is supported. The other MIPS COFF machines (R3000
`0x0160`/`0x0162`, R10000 `0x0168`, WCE v2 `0x0169`, MIPS16 `0x0266`, MIPS FPU
`0x0366`, MIPS16 FPU `0x0466`) stay refused as an unsupported PE architecture,
because each selects a different ISA, word size or instruction encoding and none
is verified. A PE32+ optional header with machine `0x0166` is malformed and is
refused as well.

Provider selection returns the specific unsupported constraint:

| Declaration                                    | Outcome                                                                    |
| ---------------------------------------------- | -------------------------------------------------------------------------- |
| Native PE application or DLL, machine `0x0166` | admitted on Linux and macOS, `MIPS:LE:32:default` + `windows`              |
| Managed (CLI directory) PE, machine `0x0166`   | refused; managed inspection refuses MIPS machines as well                  |
| Non-executable or unclassified PE image        | refused                                                                    |
| Machine not observed                           | refused; the family alone does not select the ISA, word size or byte order |
| Any other MIPS COFF machine                    | refused at target resolution as an unsupported PE architecture             |
| Windows host (Windows Ghidra P0)               | refused; P0 admits x86, x86-64, ARMNT and ARM64 PE targets only            |
| IDA and Hopper                                 | decline with a PE-specific reason; neither has a verified MIPS PE lane     |

Admission reads the COFF machine, characteristics and CLI directory only. The
subsystem and operating system are not inspected: Windows CE (subsystem 9) is the
motivating use, not a verified property of an admitted image. Only standalone PE
files are admitted; Windows CE ROM images are not PE files and are not handled by
this lane.

## Why the language is pinned

Ghidra 12.1.4's `MIPS.opinion` already maps PE machine 358 (`0x0166`) to
`MIPS:LE:32:default` with the `windows` compiler specification. REA pins that
pair instead of accepting the loader's choice, so the committed profile, the
session readback and any different mapping in another Ghidra release compare
against one owner. The profile records `language_selection: provider-pinned-v1`.
A caller-selected `REA_GHIDRA_LANGUAGE_ID` or `REA_GHIDRA_COMPILER_SPEC_ID` that
disagrees with the pin is refused without changing the requested override. The
pinned `windows` specification is not the language's default one, so a
language-only selection is refused too: name both. An override that matches the
pin is accepted and recorded as `configured-v1`.

Ghidra's `windows` and `default` compiler specifications for this language both
use `mips32le.cspec`, so Windows calling-convention fidelity is an assumption of
this lane, not a verified fact.

## Evidence

The lane identity is `pe32-coff-r4000-le-windows-cspec-v1`. The committed profile
retains `pe_machine` (358, the decimal value of `0x0166`) because Evidence
subjects and snapshots carry only the `mips` family and could not otherwise tell
one MIPS machine from another. `mips_abi_basis` is
`coff-machine-language-assumption-v1`: the COFF machine is a header declaration,
not proof of the MIPS32 ISA level the pinned language models.
`instruction_context_evidence` is `per-address-isa-mode-v1`, as for the ELF MIPS
lanes; for this language the `ISA_MODE` register is reported with no value set.

As for other PE targets, load-image inspection returns an `unsupported`
attestation status, but its observations still report what Ghidra loaded: the executable
format, language, compiler specification, image base, entry points and the
section mappings with their source file offsets and hashes.

## Limits

- **MIPS III instructions are not faithfully modeled.** R4000 is a MIPS III
  core, but the pinned language is 32-bit. On Ghidra 12.1.4 a `daddu` decodes
  with 32-bit register semantics, so its result is a 32-bit add. An encoding
  such as `dsll` is not decoded at all, and the decompiler halts there with an
  unimplemented-instruction or bad-instruction warning. Code that uses 64-bit
  instructions needs a different analysis.
- **Relocations are not applied.** Ghidra's PE loader records base relocations
  as skipped and analyzes the image at its preferred base. MIPS-specific
  relocation types are not interpreted.
- Imports, exports, Windows CE module conventions and any ROM or compression
  container are not inspected by REA.
- The lane is verified for one machine value. R3000, R10000, MIPS16, FPU and WCE
  v2 images need their own verification before admission.

## Verification

Run `npm run verify:ghidra:mips-pe` on a Linux or macOS host with an existing
Ghidra 12.1.4 installation and JDK 21+. The verifier acquires no tools, needs no
compiler, and never executes target code:

```sh
GHIDRA_INSTALL_DIR=/path/to/ghidra_12.1.4_PUBLIC \
JAVA_HOME=/path/to/jdk-21 \
npm run verify:ghidra:mips-pe
```

The fixture is a 1 KiB PE32 image whose twelve MIPS II instruction words and
header fields are encoded in
`tests/conformance/ghidra/mips-pe-fixture.mjs`. Through the public stdio MCP and CLI workflows it verifies:

- the committed profile, including the pinned language and lane identity, for an
  application and for the same image marked as a DLL;
- the loaded format, language and compiler specification, and the Headers and
  `.text` mappings against hashes computed from the encoded fixture bytes;
- exactly two recovered functions, their complete body ranges, the nine entry
  instructions including both delay slots, their bytes and file offset, the
  direct `jal` call target, and the decompiled call;
- CLI and MCP agreement on the function dossier;
- the MIPS III limitation above: a `daddu` image decompiles to a 32-bit add and
  a `dsll` image has no instruction at the delay slot and halts the decompiler,
  so a Ghidra release that changes either behavior fails the verifier instead
  of the documentation drifting;
- refusal of an unverified machine (`0x0162`), refusal of a conflicting or
  language-only override with the requested value unchanged, acceptance of a
  matching one,
  unchanged source bytes, and owned-process cleanup.

The fixture is encoded by hand rather than produced by a Windows CE toolchain,
so it establishes REA's handling of the header and instruction shapes it
contains, not compatibility with real Windows CE binaries. The verifier is a
manual lane and has no automatic CI workflow. Module and boundary tests cover
admission, malformed headers and the refusals above with simulated providers,
which do not establish real-provider behavior.
