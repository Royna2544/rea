/**
 * Build a public, source-owned Windows CE style MIPS PE32 without a compiler or
 * binary seed. REA never executes it; Ghidra only parses and analyzes it.
 *
 * COFF machine 0x0166 (IMAGE_FILE_MACHINE_R4000) with subsystem 9
 * (IMAGE_SUBSYSTEM_WINDOWS_CE_GUI). The code is little-endian MIPS II:
 *
 *   entry:  addiu sp,sp,-16      ; frame
 *           sw    ra,12(sp)
 *           addiu a0,zero,3
 *           jal   helper
 *           addiu a1,zero,4      ; delay slot
 *           lw    ra,12(sp)
 *           addiu sp,sp,16
 *           jr    ra
 *           nop                  ; delay slot
 *   helper: addu  v0,a0,a1       ; `daddu` (MIPS III) in the 64-bit variant
 *           jr    ra
 *           sll   v0,v0,1        ; delay slot; `dsll` in the 64-bit variant
 */
const IMAGE_BASE = 0x0001_0000;
const TEXT_RVA = 0x1000;
const FILE_ALIGNMENT = 0x200;
const SECTION_ALIGNMENT = 0x1000;
const MACHINE_R4000 = 0x0166;
const SUBSYSTEM_WINDOWS_CE_GUI = 9;
const HELPER_OFFSET = 0x24;

const word = (value) => {
  const bytes = Buffer.alloc(4);
  bytes.writeUInt32LE(value >>> 0);
  return bytes;
};

/** `jal` keeps the upper four bits of the delay-slot address and encodes the rest. */
const jal = (target) => 0x0c00_0000 | ((target >>> 2) & 0x03ff_ffff);

/** Encoded instruction words in program order, with the helper at HELPER_OFFSET. */
const codeWords = (mips3) => [
  0x27bd_fff0, // addiu sp,sp,-16
  0xafbf_000c, // sw ra,12(sp)
  0x2404_0003, // addiu a0,zero,3
  jal(IMAGE_BASE + TEXT_RVA + HELPER_OFFSET), // jal helper
  0x2405_0004, // addiu a1,zero,4 (delay slot)
  0x8fbf_000c, // lw ra,12(sp)
  0x27bd_0010, // addiu sp,sp,16
  0x03e0_0008, // jr ra
  0x0000_0000, // nop (delay slot)
  mips3 ? 0x0085_102d : 0x0085_1021, // daddu / addu v0,a0,a1
  0x03e0_0008, // jr ra
  mips3 ? 0x0002_1078 : 0x0002_1040, // dsll / sll v0,v0,1 (delay slot)
];

/**
 * @param {{ image?: "exe" | "dll", mips3?: boolean, machine?: number }} [options]
 *   `mips3` swaps two helper instructions for 64-bit MIPS III encodings;
 *   `machine` overrides the COFF machine for negative controls.
 */
export function buildMipsPeFixture(options = {}) {
  const dll = options.image === "dll";
  const code = Buffer.concat(codeWords(options.mips3 === true).map(word));
  const bytes = Buffer.alloc(FILE_ALIGNMENT + FILE_ALIGNMENT);
  bytes.write("MZ", 0, "latin1");
  bytes.writeUInt32LE(0x40, 0x3c); // e_lfanew; no DOS stub program
  bytes.write("PE\0\0", 0x40, "latin1");
  const coff = 0x44;
  bytes.writeUInt16LE(options.machine ?? MACHINE_R4000, coff);
  bytes.writeUInt16LE(1, coff + 2); // one section
  bytes.writeUInt16LE(0xe0, coff + 16); // PE32 optional header with 16 directories
  // EXECUTABLE_IMAGE | RELOCS_STRIPPED | LINE_NUMS_STRIPPED | LOCAL_SYMS_STRIPPED
  // | 32BIT_MACHINE, plus DLL for the shared-library variant.
  bytes.writeUInt16LE(0x010f | (dll ? 0x2000 : 0), coff + 18);
  const optional = coff + 20;
  bytes.writeUInt16LE(0x10b, optional); // PE32
  bytes.writeUInt32LE(code.length, optional + 4);
  bytes.writeUInt32LE(TEXT_RVA, optional + 16); // entry point at the first word
  bytes.writeUInt32LE(TEXT_RVA, optional + 20);
  bytes.writeUInt32LE(0x2000, optional + 24);
  bytes.writeUInt32LE(IMAGE_BASE, optional + 28);
  bytes.writeUInt32LE(SECTION_ALIGNMENT, optional + 32);
  bytes.writeUInt32LE(FILE_ALIGNMENT, optional + 36);
  bytes.writeUInt16LE(4, optional + 40); // OS version
  bytes.writeUInt16LE(4, optional + 48); // subsystem version
  bytes.writeUInt32LE(0x2000, optional + 56); // SizeOfImage
  bytes.writeUInt32LE(FILE_ALIGNMENT, optional + 60); // SizeOfHeaders
  bytes.writeUInt16LE(SUBSYSTEM_WINDOWS_CE_GUI, optional + 68);
  bytes.writeUInt32LE(0x10_0000, optional + 72);
  bytes.writeUInt32LE(0x1000, optional + 76);
  bytes.writeUInt32LE(0x10_0000, optional + 80);
  bytes.writeUInt32LE(0x1000, optional + 84);
  bytes.writeUInt32LE(16, optional + 92); // empty data directories
  const section = optional + 0xe0;
  bytes.write(".text", section, "latin1");
  bytes.writeUInt32LE(code.length, section + 8); // VirtualSize
  bytes.writeUInt32LE(TEXT_RVA, section + 12);
  bytes.writeUInt32LE(FILE_ALIGNMENT, section + 16); // SizeOfRawData
  bytes.writeUInt32LE(FILE_ALIGNMENT, section + 20); // PointerToRawData
  bytes.writeUInt32LE(0x6000_0020, section + 36); // CODE | EXECUTE | READ
  code.copy(bytes, FILE_ALIGNMENT);
  const at = (offset) => `0x${(IMAGE_BASE + TEXT_RVA + offset).toString(16)}`;
  return {
    bytes,
    machine: options.machine ?? MACHINE_R4000,
    image_base: `0x${IMAGE_BASE.toString(16)}`,
    text_start: at(0),
    text_file_offset: FILE_ALIGNMENT,
    code_bytes: code.length,
    entry: at(0),
    jal: at(0x0c),
    helper: at(HELPER_OFFSET),
    helper_end: at(code.length - 1),
    entry_end: at(HELPER_OFFSET - 1),
    /** Little-endian bytes of each entry instruction, in order, as lowercase hex. */
    entry_instruction_bytes: Array.from({ length: 9 }, (_, index) =>
      code.subarray(index * 4, index * 4 + 4).toString("hex"),
    ),
  };
}
