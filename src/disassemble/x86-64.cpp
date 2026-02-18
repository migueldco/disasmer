#include <cassert>
#include <cstdint>
#include <disassemble.hpp>
#include <format>
#include <optional>
#include <sstream>
#include <string>
#include <string_view>

namespace disassemble {

namespace X86_64 {

enum class Register : uint8_t {
	RAX = 0,
	RCX,
	RDX,
	RBX,
	RSP,
	RBP,
	RSI,
	RDI,
	R8,
	R9,
	R10,
	R11,
	R12,
	R13,
	R14,
	R15,
	RIP,
	// XMM registers (SSE)
	XMM0,
	XMM1,
	XMM2,
	XMM3,
	XMM4,
	XMM5,
	XMM6,
	XMM7,
	XMM8,
	XMM9,
	XMM10,
	XMM11,
	XMM12,
	XMM13,
	XMM14,
	XMM15,
	None,
};

constexpr Register makeRegister(uint8_t bits3, bool rexExt) {
	return static_cast<Register>(bits3 | (rexExt ? 8 : 0));
}

constexpr Register makeXmmRegister(uint8_t bits3, bool rexExt) {
	return static_cast<Register>(static_cast<uint8_t>(Register::XMM0) + bits3 +
								 (rexExt ? 8 : 0));
}

constexpr std::string_view registerName(Register reg, uint8_t size) {
	// clang-format off
    constexpr std::string_view names8[]  = { "al",  "cl",  "dl",  "bl",  "spl", "bpl", "sil", "dil",
                                             "r8b", "r9b", "r10b","r11b","r12b","r13b","r14b","r15b" };
    constexpr std::string_view names16[] = { "ax",  "cx",  "dx",  "bx",  "sp",  "bp",  "si",  "di",
                                             "r8w", "r9w", "r10w","r11w","r12w","r13w","r14w","r15w" };
    constexpr std::string_view names32[] = { "eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi",
                                             "r8d", "r9d", "r10d","r11d","r12d","r13d","r14d","r15d" };
    constexpr std::string_view names64[] = { "rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi",
                                             "r8",  "r9",  "r10", "r11", "r12", "r13", "r14", "r15", "rip" };
	// clang-format on
	// clang-format off
	constexpr std::string_view namesXmm[] = { "xmm0", "xmm1", "xmm2", "xmm3", "xmm4", "xmm5", "xmm6", "xmm7",
	                                          "xmm8", "xmm9", "xmm10","xmm11","xmm12","xmm13","xmm14","xmm15" };
	// clang-format on
	auto idx = static_cast<uint8_t>(reg);
	if (idx >= static_cast<uint8_t>(Register::XMM0) &&
		idx <= static_cast<uint8_t>(Register::XMM15)) {
		return namesXmm[idx - static_cast<uint8_t>(Register::XMM0)];
	}
	switch (size) {
	case 1:
		return names8[idx];
	case 2:
		return names16[idx];
	case 4:
		return names32[idx];
	case 8:
		return names64[idx];
	default:
		return "???";
	}
}

struct LegacyPrefixes {
	bool operandSizeOverride = false; // 0x66
	bool addressSizeOverride = false; // 0x67
	bool lock = false;				  // 0xF0
	bool repne = false;				  // 0xF2
	bool rep = false;				  // 0xF3
	enum class Segment { None, CS, SS, DS, ES, FS, GS } segment = Segment::None;
};

struct Rex {
	bool present = false;
	bool w = false;
	bool r = false;
	bool x = false;
	bool b = false;

	static std::optional<Rex> tryDecode(uint8_t byte) {
		if ((byte & 0xF0) != 0x40)
			return std::nullopt;
		return Rex{
			.present = true,
			.w = (byte & 0x08) != 0,
			.r = (byte & 0x04) != 0,
			.x = (byte & 0x02) != 0,
			.b = (byte & 0x01) != 0,
		};
	}
};

struct ModRM {
	uint8_t mod;
	uint8_t reg;
	uint8_t rm;

	static ModRM decode(uint8_t byte) {
		return {
			.mod = static_cast<uint8_t>((byte >> 6) & 0x3),
			.reg = static_cast<uint8_t>((byte >> 3) & 0x7),
			.rm = static_cast<uint8_t>(byte & 0x7),
		};
	}

	bool needsSIB() const { return mod != 3 && rm == 4; }
	uint8_t displacementSize() const {
		if (mod == 1)
			return 1;
		if (mod == 2)
			return 4;
		if (mod == 0 && rm == 5)
			return 4;
		return 0;
	}
	bool isDirectRegister() const { return mod == 3; }
};

struct SIB {
	uint8_t scale;
	uint8_t index;
	uint8_t base;

	static SIB decode(uint8_t byte) {
		return {
			.scale = static_cast<uint8_t>((byte >> 6) & 0x3),
			.index = static_cast<uint8_t>((byte >> 3) & 0x7),
			.base = static_cast<uint8_t>(byte & 0x7),
		};
	}

	uint8_t scaleFactor() const { return static_cast<uint8_t>(1 << scale); }
	bool hasBase(uint8_t mod) const { return !(base == 5 && mod == 0); }
	bool hasIndex(bool rexX) const { return index != 4 || rexX; }
};

struct MemoryOperand {
	Register base = Register::None;
	Register index = Register::None;
	uint8_t scale = 1;
	int64_t displacement = 0;
	bool ripRelative = false;
};

struct Operand {
	enum class Kind : uint8_t { None, Register, Memory, Immediate };

	Kind kind = Kind::None;
	uint8_t size = 0;

	Register reg = Register::None;
	MemoryOperand mem = {};
	int64_t imm = 0;

	static Operand makeRegister(Register r, uint8_t sz) {
		return {.kind = Kind::Register, .size = sz, .reg = r};
	}
	static Operand makeMemory(MemoryOperand m, uint8_t sz) {
		return {.kind = Kind::Memory, .size = sz, .mem = m};
	}
	static Operand makeImmediate(int64_t value, uint8_t sz) {
		return {.kind = Kind::Immediate, .size = sz, .imm = value};
	}
};

struct DecodedInstruction {
	std::string_view mnemonic;
	Operand operands[2];
	uint8_t operandCount = 0;
	size_t length = 0;
};

enum class OperandEnc : uint8_t {
	ZO, // zero operands
	MR, // ModR/M r/m = dest, reg = src
	RM, // ModR/M reg = dest, r/m = src
	MI, // ModR/M r/m = dest, immediate = src
	M,	// ModR/M r/m = single operand
	O,	// register in low 3 bits of opcode
	OI, // register in opcode + immediate
	I,	// immediate only
	D,	// relative displacement
};

enum class OpSize : uint8_t {
	Fixed8,
	Fixed16,
	Fixed32,
	Fixed64,
	Fixed128, // XMM 128-bit operand
	Default,  // 32 default, REX.W -> 64, 0x66 -> 16
	Imm8,	  // sign-extended 8-bit immediate
};

struct InstructionEntry {
	uint8_t opcode;
	bool twoByteOpcode;
	int8_t regField;		 // -1 = any, 0-7 = must match ModR/M /reg
	uint8_t mandatoryPrefix; // 0 = none, 0x66, 0xF2, or 0xF3
	std::string_view mnemonic;
	OperandEnc encoding;
	OpSize operandSize;
	OpSize immediateSize; // only used when encoding has an immediate component
};

// clang-format off
constexpr InstructionEntry instructionTable[] = {
	// --- ADD ---
	{0x00, false, -1, 0, "add",   OperandEnc::MR, OpSize::Fixed8,  OpSize::Fixed8},
	{0x01, false, -1, 0, "add",   OperandEnc::MR, OpSize::Default, OpSize::Default},
	{0x02, false, -1, 0, "add",   OperandEnc::RM, OpSize::Fixed8,  OpSize::Fixed8},
	{0x03, false, -1, 0, "add",   OperandEnc::RM, OpSize::Default, OpSize::Default},
	{0x81, false,  0, 0, "add",   OperandEnc::MI, OpSize::Default, OpSize::Fixed32},
	{0x83, false,  0, 0, "add",   OperandEnc::MI, OpSize::Default, OpSize::Imm8},

	// --- OR ---
	{0x08, false, -1, 0, "or",    OperandEnc::MR, OpSize::Fixed8,  OpSize::Fixed8},
	{0x09, false, -1, 0, "or",    OperandEnc::MR, OpSize::Default, OpSize::Default},
	{0x0A, false, -1, 0, "or",    OperandEnc::RM, OpSize::Fixed8,  OpSize::Fixed8},
	{0x0B, false, -1, 0, "or",    OperandEnc::RM, OpSize::Default, OpSize::Default},
	{0x81, false,  1, 0, "or",    OperandEnc::MI, OpSize::Default, OpSize::Fixed32},
	{0x83, false,  1, 0, "or",    OperandEnc::MI, OpSize::Default, OpSize::Imm8},

	// --- AND ---
	{0x20, false, -1, 0, "and",   OperandEnc::MR, OpSize::Fixed8,  OpSize::Fixed8},
	{0x21, false, -1, 0, "and",   OperandEnc::MR, OpSize::Default, OpSize::Default},
	{0x22, false, -1, 0, "and",   OperandEnc::RM, OpSize::Fixed8,  OpSize::Fixed8},
	{0x23, false, -1, 0, "and",   OperandEnc::RM, OpSize::Default, OpSize::Default},
	{0x81, false,  4, 0, "and",   OperandEnc::MI, OpSize::Default, OpSize::Fixed32},
	{0x83, false,  4, 0, "and",   OperandEnc::MI, OpSize::Default, OpSize::Imm8},

	// --- SUB ---
	{0x28, false, -1, 0, "sub",   OperandEnc::MR, OpSize::Fixed8,  OpSize::Fixed8},
	{0x29, false, -1, 0, "sub",   OperandEnc::MR, OpSize::Default, OpSize::Default},
	{0x2A, false, -1, 0, "sub",   OperandEnc::RM, OpSize::Fixed8,  OpSize::Fixed8},
	{0x2B, false, -1, 0, "sub",   OperandEnc::RM, OpSize::Default, OpSize::Default},
	{0x81, false,  5, 0, "sub",   OperandEnc::MI, OpSize::Default, OpSize::Fixed32},
	{0x83, false,  5, 0, "sub",   OperandEnc::MI, OpSize::Default, OpSize::Imm8},

	// --- XOR ---
	{0x30, false, -1, 0, "xor",   OperandEnc::MR, OpSize::Fixed8,  OpSize::Fixed8},
	{0x31, false, -1, 0, "xor",   OperandEnc::MR, OpSize::Default, OpSize::Default},
	{0x32, false, -1, 0, "xor",   OperandEnc::RM, OpSize::Fixed8,  OpSize::Fixed8},
	{0x33, false, -1, 0, "xor",   OperandEnc::RM, OpSize::Default, OpSize::Default},
	{0x81, false,  6, 0, "xor",   OperandEnc::MI, OpSize::Default, OpSize::Fixed32},
	{0x83, false,  6, 0, "xor",   OperandEnc::MI, OpSize::Default, OpSize::Imm8},

	// --- CMP ---
	{0x38, false, -1, 0, "cmp",   OperandEnc::MR, OpSize::Fixed8,  OpSize::Fixed8},
	{0x39, false, -1, 0, "cmp",   OperandEnc::MR, OpSize::Default, OpSize::Default},
	{0x3A, false, -1, 0, "cmp",   OperandEnc::RM, OpSize::Fixed8,  OpSize::Fixed8},
	{0x3B, false, -1, 0, "cmp",   OperandEnc::RM, OpSize::Default, OpSize::Default},
	{0x81, false,  7, 0, "cmp",   OperandEnc::MI, OpSize::Default, OpSize::Fixed32},
	{0x83, false,  7, 0, "cmp",   OperandEnc::MI, OpSize::Default, OpSize::Imm8},

	// --- PUSH/POP ---
	{0x50, false, -1, 0, "push",  OperandEnc::O,  OpSize::Fixed64, OpSize::Fixed64},
	{0x58, false, -1, 0, "pop",   OperandEnc::O,  OpSize::Fixed64, OpSize::Fixed64},

	// --- MOV ---
	{0x88, false, -1, 0, "mov",   OperandEnc::MR, OpSize::Fixed8,  OpSize::Fixed8},
	{0x89, false, -1, 0, "mov",   OperandEnc::MR, OpSize::Default, OpSize::Default},
	{0x8A, false, -1, 0, "mov",   OperandEnc::RM, OpSize::Fixed8,  OpSize::Fixed8},
	{0x8B, false, -1, 0, "mov",   OperandEnc::RM, OpSize::Default, OpSize::Default},
	{0xC6, false,  0, 0, "mov",   OperandEnc::MI, OpSize::Fixed8,  OpSize::Fixed8},
	{0xC7, false,  0, 0, "mov",   OperandEnc::MI, OpSize::Default, OpSize::Fixed32},
	{0xB8, false, -1, 0, "mov",   OperandEnc::OI, OpSize::Default, OpSize::Default},

	// --- LEA ---
	{0x8D, false, -1, 0, "lea",   OperandEnc::RM, OpSize::Default, OpSize::Default},

	// --- TEST ---
	{0x84, false, -1, 0, "test",  OperandEnc::MR, OpSize::Fixed8,  OpSize::Fixed8},
	{0x85, false, -1, 0, "test",  OperandEnc::MR, OpSize::Default, OpSize::Default},
	{0xF6, false,  0, 0, "test",  OperandEnc::MI, OpSize::Fixed8,  OpSize::Fixed8},
	{0xF7, false,  0, 0, "test",  OperandEnc::MI, OpSize::Default, OpSize::Fixed32},

	// --- NOT/NEG ---
	{0xF7, false,  2, 0, "not",   OperandEnc::M,  OpSize::Default, OpSize::Default},
	{0xF7, false,  3, 0, "neg",   OperandEnc::M,  OpSize::Default, OpSize::Default},

	// --- IMUL (single operand) ---
	{0xF7, false,  5, 0, "imul",  OperandEnc::M,  OpSize::Default, OpSize::Default},

	// --- DIV/IDIV ---
	{0xF7, false,  6, 0, "div",   OperandEnc::M,  OpSize::Default, OpSize::Default},
	{0xF7, false,  7, 0, "idiv",  OperandEnc::M,  OpSize::Default, OpSize::Default},

	// --- INC/DEC (via 0xFF) ---
	{0xFF, false,  0, 0, "inc",   OperandEnc::M,  OpSize::Default, OpSize::Default},
	{0xFF, false,  1, 0, "dec",   OperandEnc::M,  OpSize::Default, OpSize::Default},

	// --- CALL indirect / JMP indirect ---
	{0xFF, false,  2, 0, "call",  OperandEnc::M,  OpSize::Fixed64, OpSize::Fixed64},
	{0xFF, false,  4, 0, "jmp",   OperandEnc::M,  OpSize::Fixed64, OpSize::Fixed64},
	{0xFF, false,  6, 0, "push",  OperandEnc::M,  OpSize::Fixed64, OpSize::Fixed64},

	// --- NOP ---
	{0x90, false, -1, 0, "nop",   OperandEnc::ZO, OpSize::Default, OpSize::Default},

	// --- RET ---
	{0xC3, false, -1, 0, "ret",   OperandEnc::ZO, OpSize::Default, OpSize::Default},

	// --- INT3 ---
	{0xCC, false, -1, 0, "int3",  OperandEnc::ZO, OpSize::Default, OpSize::Default},

	// --- LEAVE ---
	{0xC9, false, -1, 0, "leave", OperandEnc::ZO, OpSize::Default, OpSize::Default},

	// --- CQO/CDQ ---
	{0x99, false, -1, 0, "cdq",   OperandEnc::ZO, OpSize::Default, OpSize::Default},

	// --- CALL rel32 ---
	{0xE8, false, -1, 0, "call",  OperandEnc::D,  OpSize::Default, OpSize::Fixed32},

	// --- JMP rel32 / rel8 ---
	{0xE9, false, -1, 0, "jmp",   OperandEnc::D,  OpSize::Default, OpSize::Fixed32},
	{0xEB, false, -1, 0, "jmp",   OperandEnc::D,  OpSize::Default, OpSize::Fixed8},

	// --- Short conditional jumps (rel8) ---
	{0x70, false, -1, 0, "jo",    OperandEnc::D,  OpSize::Default, OpSize::Fixed8},
	{0x71, false, -1, 0, "jno",   OperandEnc::D,  OpSize::Default, OpSize::Fixed8},
	{0x72, false, -1, 0, "jb",    OperandEnc::D,  OpSize::Default, OpSize::Fixed8},
	{0x73, false, -1, 0, "jae",   OperandEnc::D,  OpSize::Default, OpSize::Fixed8},
	{0x74, false, -1, 0, "je",    OperandEnc::D,  OpSize::Default, OpSize::Fixed8},
	{0x75, false, -1, 0, "jne",   OperandEnc::D,  OpSize::Default, OpSize::Fixed8},
	{0x76, false, -1, 0, "jbe",   OperandEnc::D,  OpSize::Default, OpSize::Fixed8},
	{0x77, false, -1, 0, "ja",    OperandEnc::D,  OpSize::Default, OpSize::Fixed8},
	{0x78, false, -1, 0, "js",    OperandEnc::D,  OpSize::Default, OpSize::Fixed8},
	{0x79, false, -1, 0, "jns",   OperandEnc::D,  OpSize::Default, OpSize::Fixed8},
	{0x7C, false, -1, 0, "jl",    OperandEnc::D,  OpSize::Default, OpSize::Fixed8},
	{0x7D, false, -1, 0, "jge",   OperandEnc::D,  OpSize::Default, OpSize::Fixed8},
	{0x7E, false, -1, 0, "jle",   OperandEnc::D,  OpSize::Default, OpSize::Fixed8},
	{0x7F, false, -1, 0, "jg",    OperandEnc::D,  OpSize::Default, OpSize::Fixed8},

	// --- Near conditional jumps (0F xx rel32) ---
	{0x80, true,  -1, 0, "jo",    OperandEnc::D,  OpSize::Default, OpSize::Fixed32},
	{0x81, true,  -1, 0, "jno",   OperandEnc::D,  OpSize::Default, OpSize::Fixed32},
	{0x82, true,  -1, 0, "jb",    OperandEnc::D,  OpSize::Default, OpSize::Fixed32},
	{0x83, true,  -1, 0, "jae",   OperandEnc::D,  OpSize::Default, OpSize::Fixed32},
	{0x84, true,  -1, 0, "je",    OperandEnc::D,  OpSize::Default, OpSize::Fixed32},
	{0x85, true,  -1, 0, "jne",   OperandEnc::D,  OpSize::Default, OpSize::Fixed32},
	{0x86, true,  -1, 0, "jbe",   OperandEnc::D,  OpSize::Default, OpSize::Fixed32},
	{0x87, true,  -1, 0, "ja",    OperandEnc::D,  OpSize::Default, OpSize::Fixed32},
	{0x88, true,  -1, 0, "js",    OperandEnc::D,  OpSize::Default, OpSize::Fixed32},
	{0x89, true,  -1, 0, "jns",   OperandEnc::D,  OpSize::Default, OpSize::Fixed32},
	{0x8C, true,  -1, 0, "jl",    OperandEnc::D,  OpSize::Default, OpSize::Fixed32},
	{0x8D, true,  -1, 0, "jge",   OperandEnc::D,  OpSize::Default, OpSize::Fixed32},
	{0x8E, true,  -1, 0, "jle",   OperandEnc::D,  OpSize::Default, OpSize::Fixed32},
	{0x8F, true,  -1, 0, "jg",    OperandEnc::D,  OpSize::Default, OpSize::Fixed32},

	// --- SETcc (0F 9x) ---
	{0x92, true,  -1, 0, "setb",  OperandEnc::M,  OpSize::Fixed8,  OpSize::Fixed8},
	{0x94, true,  -1, 0, "sete",  OperandEnc::M,  OpSize::Fixed8,  OpSize::Fixed8},
	{0x95, true,  -1, 0, "setne", OperandEnc::M,  OpSize::Fixed8,  OpSize::Fixed8},
	{0x9C, true,  -1, 0, "setl",  OperandEnc::M,  OpSize::Fixed8,  OpSize::Fixed8},
	{0x9D, true,  -1, 0, "setge", OperandEnc::M,  OpSize::Fixed8,  OpSize::Fixed8},
	{0x9E, true,  -1, 0, "setle", OperandEnc::M,  OpSize::Fixed8,  OpSize::Fixed8},
	{0x9F, true,  -1, 0, "setg",  OperandEnc::M,  OpSize::Fixed8,  OpSize::Fixed8},

	// --- CMOVcc (0F 4x) ---
	{0x44, true,  -1, 0, "cmove",  OperandEnc::RM, OpSize::Default, OpSize::Default},
	{0x45, true,  -1, 0, "cmovne", OperandEnc::RM, OpSize::Default, OpSize::Default},
	{0x4C, true,  -1, 0, "cmovl",  OperandEnc::RM, OpSize::Default, OpSize::Default},
	{0x4D, true,  -1, 0, "cmovge", OperandEnc::RM, OpSize::Default, OpSize::Default},
	{0x4E, true,  -1, 0, "cmovle", OperandEnc::RM, OpSize::Default, OpSize::Default},
	{0x4F, true,  -1, 0, "cmovg",  OperandEnc::RM, OpSize::Default, OpSize::Default},

	// --- MOVZX / MOVSX ---
	{0xB6, true,  -1, 0, "movzx", OperandEnc::RM, OpSize::Fixed8,  OpSize::Fixed8},
	{0xB7, true,  -1, 0, "movzx", OperandEnc::RM, OpSize::Fixed16, OpSize::Fixed16},
	{0xBE, true,  -1, 0, "movsx", OperandEnc::RM, OpSize::Fixed8,  OpSize::Fixed8},
	{0xBF, true,  -1, 0, "movsx", OperandEnc::RM, OpSize::Fixed16, OpSize::Fixed16},

	// --- MOVSXD ---
	{0x63, false, -1, 0, "movsxd", OperandEnc::RM, OpSize::Fixed32, OpSize::Fixed32},

	// --- IMUL r, r/m ---
	{0xAF, true,  -1, 0, "imul",  OperandEnc::RM, OpSize::Default, OpSize::Default},

	// --- SYSCALL ---
	{0x05, true,  -1, 0, "syscall", OperandEnc::ZO, OpSize::Default, OpSize::Default},

	// --- SHL/SHR/SAR (via 0xC1) ---
	{0xC1, false,  4, 0, "shl",   OperandEnc::MI, OpSize::Default, OpSize::Imm8},
	{0xC1, false,  5, 0, "shr",   OperandEnc::MI, OpSize::Default, OpSize::Imm8},
	{0xC1, false,  7, 0, "sar",   OperandEnc::MI, OpSize::Default, OpSize::Imm8},

	// --- SHL/SHR/SAR by 1 (via 0xD1) ---
	{0xD1, false,  4, 0, "shl",   OperandEnc::M,  OpSize::Default, OpSize::Default},
	{0xD1, false,  5, 0, "shr",   OperandEnc::M,  OpSize::Default, OpSize::Default},
	{0xD1, false,  7, 0, "sar",   OperandEnc::M,  OpSize::Default, OpSize::Default},

	// --- XCHG ---
	{0x87, false, -1, 0, "xchg",  OperandEnc::MR, OpSize::Default, OpSize::Default},

	// --- SSE: MOVAPS ---
	{0x28, true,  -1, 0, "movaps", OperandEnc::RM, OpSize::Fixed128, OpSize::Fixed128},
	{0x29, true,  -1, 0, "movaps", OperandEnc::MR, OpSize::Fixed128, OpSize::Fixed128},

	// --- SSE: PXOR xmm1, xmm2/m128 (66 0F EF /r) ---
	{0xEF, true,  -1, 0x66, "pxor", OperandEnc::RM, OpSize::Fixed128, OpSize::Fixed128},
};
// clang-format on

constexpr size_t instructionTableSize =
	sizeof(instructionTable) / sizeof(instructionTable[0]);

// For O and OI encodings, the opcode encodes a register in the low 3 bits.
// We mask to the base opcode (high 5 bits) when looking up.
static bool encodingUsesOpcodeReg(OperandEnc enc) {
	return enc == OperandEnc::O || enc == OperandEnc::OI;
}

static const InstructionEntry *findInstruction(uint8_t opcode,
											   bool twoByteOpcode,
											   int8_t regField,
											   uint8_t mandatoryPrefix) {
	const InstructionEntry *fallback = nullptr;
	for (size_t i = 0; i < instructionTableSize; i++) {
		const auto &e = instructionTable[i];
		if (e.twoByteOpcode != twoByteOpcode)
			continue;
		if (e.mandatoryPrefix != mandatoryPrefix)
			continue;

		bool opcodeMatch;
		if (encodingUsesOpcodeReg(e.encoding))
			opcodeMatch = (opcode & 0xF8) == (e.opcode & 0xF8);
		else
			opcodeMatch = opcode == e.opcode;

		if (!opcodeMatch)
			continue;

		if (e.regField >= 0) {
			if (regField >= 0 && e.regField == regField)
				return &e;
			if (regField < 0)
				fallback = &e;
		} else {
			if (fallback == nullptr)
				fallback = &e;
			else
				return &e;
		}
	}
	return fallback;
}

class InstructionDecoder {
  public:
	InstructionDecoder(std::span<const uint8_t> data) : data_(data) {}

	bool done() const { return offset_ >= data_.size(); }
	size_t offset() const { return offset_; }

	std::optional<DecodedInstruction> decode() {
		if (done())
			return std::nullopt;

		size_t start = offset_;
		LegacyPrefixes prefixes = consumeLegacyPrefixes();
		Rex rex = consumeRex();

		// Read opcode
		bool twoByteOpcode = false;
		uint8_t opcode = getByte();
		if (opcode == 0x0F) {
			twoByteOpcode = true;
			opcode = getByte();
		}

		// Determine mandatory prefix: try with the prefix first, fall back
		// to 0 (no mandatory prefix). This distinguishes e.g. 66 0F EF (PXOR)
		// from plain 0F EF.
		uint8_t mandatoryPrefix = 0;
		if (prefixes.operandSizeOverride)
			mandatoryPrefix = 0x66;
		else if (prefixes.repne)
			mandatoryPrefix = 0xF2;
		else if (prefixes.rep)
			mandatoryPrefix = 0xF3;

		// For encodings that need ModR/M, peek at reg field for table lookup
		std::optional<ModRM> modrm;
		int8_t regField = -1;

		// Determine if we need ModR/M by checking if any table entry for this
		// opcode uses it. Try mandatory prefix match first, then no-prefix.
		auto needsModRMForPrefix = [&](uint8_t mp) {
			for (size_t i = 0; i < instructionTableSize; i++) {
				const auto &e = instructionTable[i];
				if (e.twoByteOpcode != twoByteOpcode || e.mandatoryPrefix != mp)
					continue;
				bool opcodeMatch;
				if (encodingUsesOpcodeReg(e.encoding))
					opcodeMatch = (opcode & 0xF8) == (e.opcode & 0xF8);
				else
					opcodeMatch = opcode == e.opcode;
				if (!opcodeMatch)
					continue;
				auto enc = e.encoding;
				if (enc == OperandEnc::MR || enc == OperandEnc::RM ||
					enc == OperandEnc::MI || enc == OperandEnc::M)
					return true;
			}
			return false;
		};

		bool needsModRM = needsModRMForPrefix(mandatoryPrefix);
		if (!needsModRM && mandatoryPrefix != 0)
			needsModRM = needsModRMForPrefix(0);

		if (needsModRM) {
			modrm = ModRM::decode(getByte());
			regField = static_cast<int8_t>(modrm->reg);
		}

		// Look up with mandatory prefix first; if not found, try without
		const InstructionEntry *entry =
			findInstruction(opcode, twoByteOpcode, regField, mandatoryPrefix);
		if (!entry && mandatoryPrefix != 0) {
			entry = findInstruction(opcode, twoByteOpcode, regField, 0);
		}

		// If we matched a mandatory-prefix entry, suppress the prefix's
		// operand-size effect so it doesn't interfere with size resolution
		if (entry && entry->mandatoryPrefix != 0) {
			if (entry->mandatoryPrefix == 0x66)
				prefixes.operandSizeOverride = false;
			else if (entry->mandatoryPrefix == 0xF2)
				prefixes.repne = false;
			else if (entry->mandatoryPrefix == 0xF3)
				prefixes.rep = false;
		}
		if (!entry) {
			// Unknown instruction — skip this byte
			DecodedInstruction unknown;
			unknown.mnemonic = "???";
			unknown.length = offset_ - start;
			return unknown;
		}

		// Resolve operand size
		uint8_t opndSize = resolveSize(entry->operandSize, rex, prefixes);
		uint8_t immSize = resolveSize(entry->immediateSize, rex, prefixes);

		// For MOVZX/MOVSX/MOVSXD the destination register size differs from
		// the r/m source size. The reg operand uses the "default" size.
		bool isExtendingMov = entry->mnemonic == "movzx" ||
							  entry->mnemonic == "movsx" ||
							  entry->mnemonic == "movsxd";
		uint8_t regSize = isExtendingMov
							  ? resolveSize(OpSize::Default, rex, prefixes)
							  : opndSize;

		// Decode SIB + displacement if ModR/M present and not direct register
		std::optional<SIB> sib;
		int64_t displacement = 0;
		uint8_t dispSize = 0;

		if (modrm && !modrm->isDirectRegister()) {
			if (modrm->needsSIB()) {
				sib = SIB::decode(getByte());
				// SIB displacement: base=5 with mod=0 means disp32
				if (!sib->hasBase(modrm->mod)) {
					dispSize = 4;
				} else {
					dispSize = modrm->displacementSize();
				}
			} else {
				dispSize = modrm->displacementSize();
			}
			if (dispSize > 0)
				displacement = readSigned(dispSize);
		}

		// Build operands based on encoding
		DecodedInstruction inst;
		inst.mnemonic = entry->mnemonic;

		// Special handling for CDQ → CQO when REX.W is set
		if (entry->mnemonic == "cdq" && rex.w)
			inst.mnemonic = "cqo";

		switch (entry->encoding) {
		case OperandEnc::ZO:
			inst.operandCount = 0;
			break;

		case OperandEnc::MR: {
			inst.operands[0] =
				decodeRMOperand(*modrm, sib, rex, opndSize, displacement);
			Register regOp = (opndSize == 16)
								 ? makeXmmRegister(modrm->reg, rex.r)
								 : makeRegister(modrm->reg, rex.r);
			inst.operands[1] = Operand::makeRegister(regOp, opndSize);
			inst.operandCount = 2;
			break;
		}

		case OperandEnc::RM: {
			Register regOp = (regSize == 16)
								 ? makeXmmRegister(modrm->reg, rex.r)
								 : makeRegister(modrm->reg, rex.r);
			inst.operands[0] = Operand::makeRegister(regOp, regSize);
			inst.operands[1] =
				decodeRMOperand(*modrm, sib, rex, opndSize, displacement);
			inst.operandCount = 2;
			break;
		}

		case OperandEnc::MI: {
			inst.operands[0] =
				decodeRMOperand(*modrm, sib, rex, opndSize, displacement);
			int64_t imm = readSigned(immSize);
			inst.operands[1] = Operand::makeImmediate(imm, immSize);
			inst.operandCount = 2;
			break;
		}

		case OperandEnc::M:
			inst.operands[0] =
				decodeRMOperand(*modrm, sib, rex, opndSize, displacement);
			inst.operandCount = 1;
			break;

		case OperandEnc::O: {
			uint8_t regBits = opcode & 0x07;
			Register r = makeRegister(regBits, rex.b);
			inst.operands[0] = Operand::makeRegister(r, opndSize);
			inst.operandCount = 1;
			break;
		}

		case OperandEnc::OI: {
			uint8_t regBits = opcode & 0x07;
			Register r = makeRegister(regBits, rex.b);
			// For OI encoding, the immediate size matches operand size
			// (e.g., MOV r64, imm64 when REX.W)
			uint8_t oiImmSize = opndSize;
			int64_t imm = readSigned(oiImmSize);
			inst.operands[0] = Operand::makeRegister(r, opndSize);
			inst.operands[1] = Operand::makeImmediate(imm, oiImmSize);
			inst.operandCount = 2;
			break;
		}

		case OperandEnc::I: {
			int64_t imm = readSigned(immSize);
			inst.operands[0] = Operand::makeImmediate(imm, immSize);
			inst.operandCount = 1;
			break;
		}

		case OperandEnc::D: {
			int64_t rel = readSigned(immSize);
			inst.operands[0] = Operand::makeImmediate(rel, immSize);
			inst.operandCount = 1;
			break;
		}
		}

		inst.length = offset_ - start;
		return inst;
	}

  private:
	std::span<const uint8_t> data_;
	size_t offset_ = 0;

	uint8_t getByte() { return data_[offset_++]; }

	uint8_t peekByte() const { return data_[offset_]; }

	int64_t readSigned(uint8_t size) {
		switch (size) {
		case 1: {
			auto v = static_cast<int8_t>(getByte());
			return v;
		}
		case 2: {
			uint16_t lo = getByte();
			uint16_t hi = getByte();
			auto v = static_cast<int16_t>(lo | (hi << 8));
			return v;
		}
		case 4: {
			uint32_t v = 0;
			for (int i = 0; i < 4; i++)
				v |= static_cast<uint32_t>(getByte()) << (i * 8);
			return static_cast<int32_t>(v);
		}
		case 8: {
			uint64_t v = 0;
			for (int i = 0; i < 8; i++)
				v |= static_cast<uint64_t>(getByte()) << (i * 8);
			return static_cast<int64_t>(v);
		}
		default:
			return 0;
		}
	}

	static uint8_t resolveSize(OpSize spec, const Rex &rex,
							   const LegacyPrefixes &prefixes) {
		switch (spec) {
		case OpSize::Fixed8:
			return 1;
		case OpSize::Fixed16:
			return 2;
		case OpSize::Fixed32:
			return 4;
		case OpSize::Fixed64:
			return 8;
		case OpSize::Fixed128:
			return 16;
		case OpSize::Imm8:
			return 1;
		case OpSize::Default:
			if (rex.w)
				return 8;
			if (prefixes.operandSizeOverride)
				return 2;
			return 4;
		}
		return 4;
	}

	LegacyPrefixes consumeLegacyPrefixes() {
		LegacyPrefixes p;
		while (!done()) {
			uint8_t b = peekByte();
			switch (b) {
			case 0x66:
				p.operandSizeOverride = true;
				break;
			case 0x67:
				p.addressSizeOverride = true;
				break;
			case 0xF0:
				p.lock = true;
				break;
			case 0xF2:
				p.repne = true;
				break;
			case 0xF3:
				p.rep = true;
				break;
			case 0x26:
				p.segment = LegacyPrefixes::Segment::ES;
				break;
			case 0x2E:
				p.segment = LegacyPrefixes::Segment::CS;
				break;
			case 0x36:
				p.segment = LegacyPrefixes::Segment::SS;
				break;
			case 0x3E:
				p.segment = LegacyPrefixes::Segment::DS;
				break;
			case 0x64:
				p.segment = LegacyPrefixes::Segment::FS;
				break;
			case 0x65:
				p.segment = LegacyPrefixes::Segment::GS;
				break;
			default:
				return p;
			}
			offset_++;
		}
		return p;
	}

	Rex consumeRex() {
		if (done())
			return {};
		auto r = Rex::tryDecode(peekByte());
		if (r) {
			offset_++;
			return *r;
		}
		return {};
	}

	Operand decodeRMOperand(const ModRM &modrm, std::optional<SIB> sib,
							const Rex &rex, uint8_t opndSize,
							int64_t displacement) {
		if (modrm.isDirectRegister()) {
			Register r = (opndSize == 16) ? makeXmmRegister(modrm.rm, rex.b)
										  : makeRegister(modrm.rm, rex.b);
			return Operand::makeRegister(r, opndSize);
		}

		MemoryOperand mem;

		if (sib) {
			if (sib->hasBase(modrm.mod))
				mem.base = makeRegister(sib->base, rex.b);
			if (sib->hasIndex(rex.x)) {
				mem.index = makeRegister(sib->index, rex.x);
				mem.scale = sib->scaleFactor();
			}
			mem.displacement = displacement;
		} else if (modrm.mod == 0 && modrm.rm == 5) {
			// RIP-relative
			mem.ripRelative = true;
			mem.displacement = displacement;
		} else {
			mem.base = makeRegister(modrm.rm, rex.b);
			mem.displacement = displacement;
		}

		return Operand::makeMemory(mem, opndSize);
	}
};

static std::string formatMemoryRef(const MemoryOperand &mem, uint8_t size) {
	std::string result;

	switch (size) {
	case 1:
		result += "BYTE PTR ";
		break;
	case 2:
		result += "WORD PTR ";
		break;
	case 4:
		result += "DWORD PTR ";
		break;
	case 8:
		result += "QWORD PTR ";
		break;
	case 16:
		result += "XMMWORD PTR ";
		break;
	}

	result += '[';
	bool needPlus = false;

	if (mem.ripRelative) {
		result += "rip";
		needPlus = true;
	} else if (mem.base != Register::None) {
		result += registerName(mem.base, 8);
		needPlus = true;
	}

	if (mem.index != Register::None) {
		if (needPlus)
			result += " + ";
		result += registerName(mem.index, 8);
		if (mem.scale > 1)
			result += std::format("*{}", mem.scale);
		needPlus = true;
	}

	if (mem.displacement != 0 || !needPlus) {
		if (needPlus) {
			if (mem.displacement >= 0)
				result += std::format(" + {:#x}", mem.displacement);
			else
				result += std::format(" - {:#x}", -mem.displacement);
		} else {
			result += std::format("{:#x}", mem.displacement);
		}
	}

	result += ']';
	return result;
}

static std::string formatOperand(const Operand &op) {
	switch (op.kind) {
	case Operand::Kind::Register:
		return std::string(registerName(op.reg, op.size));
	case Operand::Kind::Memory:
		return formatMemoryRef(op.mem, op.size);
	case Operand::Kind::Immediate:
		if (op.imm < 0)
			return std::format("-{:#x}", -op.imm);
		return std::format("{:#x}", op.imm);
	case Operand::Kind::None:
		return "";
	}
	return "";
}

static std::string formatInstruction(const DecodedInstruction &inst) {
	std::string result = "\t";
	result += inst.mnemonic;
	if (inst.operandCount > 0) {
		result += "\t";
		result += formatOperand(inst.operands[0]);
		if (inst.operandCount > 1) {
			result += ", ";
			result += formatOperand(inst.operands[1]);
		}
	}
	return result;
}

static std::string stringifyMemoryRef(const MemoryOperand &mem, uint8_t size) {
	std::string result;
	result += '@';
	if (mem.ripRelative) {
		result += "G_";
	}
	if (mem.displacement >= 0) {
		result += std::format("{:#x}#{}", mem.displacement, size);
	} else {
		result += std::format("-{:#x}#{}", -mem.displacement, size);
	}
	return result;
}

static std::string stringifyOperand(const Operand &op) {
	switch (op.kind) {
	case Operand::Kind::Register:
		return std::format("${}", registerName(op.reg, op.size));
	case Operand::Kind::Memory:
		return stringifyMemoryRef(op.mem, op.size);
	case Operand::Kind::Immediate:
		if (op.imm < 0)
			return std::format("-{:#x}", -op.imm);
		else
			return std::format("{:x}", op.imm);
	case Operand::Kind::None:
		return "";
	}
	return "";
}

static std::string stringifyInstruction(const DecodedInstruction &inst) {
	std::string result;
	result += inst.mnemonic;
	if (inst.operandCount > 0) {
		result += '(';
		result += stringifyOperand(inst.operands[0]);
		if (inst.operandCount > 1) {
			result += ',';
			result += stringifyOperand(inst.operands[1]);
		}
		result += ')';
	}
	return result;
}

}; // namespace X86_64

// Disassemble in human-readable assembly
std::string disassembleX86_64(const std::span<const uint8_t> code) {
	std::string result;
	X86_64::InstructionDecoder decoder(code);

	while (!decoder.done()) {
		auto inst = decoder.decode();
		if (!inst)
			break;
		result += X86_64::formatInstruction(*inst);
		result += '\n';
	}
	return result;
}

// Disassemble into an easily-parsable format
std::string decodeX86_64(const std::span<const uint8_t> code) {
	std::string result;
	X86_64::InstructionDecoder decoder(code);

	while (!decoder.done()) {
		auto inst = decoder.decode();
		if (!inst)
			break;
		result += X86_64::stringifyInstruction(*inst);
		result += '\n';
	}
	return result;
}

}; // namespace disassemble
