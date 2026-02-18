#ifndef ELF_TYPES_HPP
#define ELF_TYPES_HPP

#include <cstddef>
#include <cstdint>

namespace binary {

// ELF identity
constexpr size_t  EI_NIDENT    = 16;
constexpr size_t  EI_CLASS     = 4;
constexpr size_t  EI_DATA      = 5;

constexpr uint8_t ELFMAG0      = 0x7f;
constexpr uint8_t ELFMAG1      = 'E';
constexpr uint8_t ELFMAG2      = 'L';
constexpr uint8_t ELFMAG3      = 'F';

constexpr uint8_t ELFCLASS32   = 1;
constexpr uint8_t ELFCLASS64   = 2;
constexpr uint8_t ELFDATA2LSB  = 1;
constexpr uint8_t ELFDATA2MSB  = 2;

// Section header types
constexpr uint32_t SHT_PROGBITS = 1;
constexpr uint32_t SHT_SYMTAB   = 2;
constexpr uint32_t SHT_STRTAB   = 3;
constexpr uint32_t SHT_DYNSYM   = 11;

// Special section indices
constexpr uint16_t SHN_UNDEF    = 0;

// Symbol types
constexpr uint8_t STT_FUNC      = 2;

// Machine types
constexpr uint16_t EM_386       = 3;
constexpr uint16_t EM_ARM       = 40;
constexpr uint16_t EM_X86_64    = 62;
constexpr uint16_t EM_AARCH64   = 183;

// Replaces ELF32_ST_TYPE / ELF64_ST_TYPE macros
constexpr uint8_t elf_st_type(uint8_t st_info) { return st_info & 0xf; }

// Address types
using Elf32_Addr = uint32_t;
using Elf64_Addr = uint64_t;

// ELF header (32-bit)
struct Elf32_Ehdr {
    uint8_t    e_ident[EI_NIDENT];
    uint16_t   e_type;
    uint16_t   e_machine;
    uint32_t   e_version;
    Elf32_Addr e_entry;
    uint32_t   e_phoff;
    uint32_t   e_shoff;
    uint32_t   e_flags;
    uint16_t   e_ehsize;
    uint16_t   e_phentsize;
    uint16_t   e_phnum;
    uint16_t   e_shentsize;
    uint16_t   e_shnum;
    uint16_t   e_shstrndx;
};

// ELF header (64-bit)
struct Elf64_Ehdr {
    uint8_t    e_ident[EI_NIDENT];
    uint16_t   e_type;
    uint16_t   e_machine;
    uint32_t   e_version;
    Elf64_Addr e_entry;
    uint64_t   e_phoff;
    uint64_t   e_shoff;
    uint32_t   e_flags;
    uint16_t   e_ehsize;
    uint16_t   e_phentsize;
    uint16_t   e_phnum;
    uint16_t   e_shentsize;
    uint16_t   e_shnum;
    uint16_t   e_shstrndx;
};

// Section header (32-bit)
struct Elf32_Shdr {
    uint32_t   sh_name;
    uint32_t   sh_type;
    uint32_t   sh_flags;
    Elf32_Addr sh_addr;
    uint32_t   sh_offset;
    uint32_t   sh_size;
    uint32_t   sh_link;
    uint32_t   sh_info;
    uint32_t   sh_addralign;
    uint32_t   sh_entsize;
};

// Section header (64-bit)
struct Elf64_Shdr {
    uint32_t   sh_name;
    uint32_t   sh_type;
    uint64_t   sh_flags;
    Elf64_Addr sh_addr;
    uint64_t   sh_offset;
    uint64_t   sh_size;
    uint32_t   sh_link;
    uint32_t   sh_info;
    uint64_t   sh_addralign;
    uint64_t   sh_entsize;
};

// Symbol table entry (32-bit)
// Wire order: name, value, size, info, other, shndx
struct Elf32_Sym {
    uint32_t   st_name;
    Elf32_Addr st_value;
    uint32_t   st_size;
    uint8_t    st_info;
    uint8_t    st_other;
    uint16_t   st_shndx;
};

// Symbol table entry (64-bit)
// Wire order: name, info, other, shndx, value, size
struct Elf64_Sym {
    uint32_t   st_name;
    uint8_t    st_info;
    uint8_t    st_other;
    uint16_t   st_shndx;
    Elf64_Addr st_value;
    uint64_t   st_size;
};

} // namespace binary

#endif // ELF_TYPES_HPP
