#include <binary.hpp>
#include <elf_binary.hpp>

#include <cassert>
#include <fstream>
#include <stdexcept>

namespace binary {

Binary::Binary(std::vector<uint8_t> &&data, ReaderFn reader)
    : data_(std::move(data)), reader_(std::move(reader)) {}

const std::vector<uint8_t> &Binary::getData() const noexcept { return data_; }
std::vector<uint8_t>       &Binary::getData()       noexcept { return data_; }

static uint64_t readLsb(size_t pos, size_t intSize, const std::vector<uint8_t> &data) {
    uint64_t ret = 0;
    for (size_t i = 0; i < intSize; i++) {
        ret |= static_cast<uint64_t>(data[pos + i]) << (8 * i);
    }
    return ret;
}

static uint64_t readMsb(size_t pos, size_t intSize, const std::vector<uint8_t> &data) {
    uint64_t ret = 0;
    for (size_t i = 0; i < intSize; i++) {
        ret = (ret << 8) | data[pos + i];
    }
    return ret;
}

static Binary::ReaderFn getElfReaderFunction(const std::vector<uint8_t> &data) {
    if (data[EI_DATA] == ELFDATA2LSB) return readLsb;
    if (data[EI_DATA] == ELFDATA2MSB) return readMsb;
    throw std::runtime_error("Invalid ELF data encoding");
}

template <typename Traits>
ElfBinary<Traits>::ElfBinary(std::vector<uint8_t> &&data, ReaderFn reader)
    : Binary(std::move(data), std::move(reader))
{
    parseHeader();
    parseSectionHeaders();
    parseSymbolTables();
    populateFunctions();
}

template <typename Traits>
void ElfBinary<Traits>::parseHeader() {
    std::copy(getData().begin(), getData().begin() + EI_NIDENT, header_.e_ident);
    size_t pos = EI_NIDENT;
    pos = readInt(header_.e_type,      pos);
    pos = readInt(header_.e_machine,   pos);
    pos = readInt(header_.e_version,   pos);
    pos = readInt(header_.e_entry,     pos);
    pos = readInt(header_.e_phoff,     pos);
    pos = readInt(header_.e_shoff,     pos);
    pos = readInt(header_.e_flags,     pos);
    pos = readInt(header_.e_ehsize,    pos);
    pos = readInt(header_.e_phentsize, pos);
    pos = readInt(header_.e_phnum,     pos);
    pos = readInt(header_.e_shentsize, pos);
    pos = readInt(header_.e_shnum,     pos);
    pos = readInt(header_.e_shstrndx,  pos);
}

template <typename Traits>
void ElfBinary<Traits>::parseSectionHeaders() {
    sectionHeaders_.resize(header_.e_shnum);
    size_t pos = header_.e_shoff;
    for (size_t i = 0; i < header_.e_shnum; i++) {
        pos = readInt(sectionHeaders_[i].sh_name,      pos);
        pos = readInt(sectionHeaders_[i].sh_type,      pos);
        pos = readInt(sectionHeaders_[i].sh_flags,     pos);
        pos = readInt(sectionHeaders_[i].sh_addr,      pos);
        pos = readInt(sectionHeaders_[i].sh_offset,    pos);
        pos = readInt(sectionHeaders_[i].sh_size,      pos);
        pos = readInt(sectionHeaders_[i].sh_link,      pos);
        pos = readInt(sectionHeaders_[i].sh_info,      pos);
        pos = readInt(sectionHeaders_[i].sh_addralign, pos);
        pos = readInt(sectionHeaders_[i].sh_entsize,   pos);
    }
}

// readSym is explicitly specialised below to handle the different field
// ordering in Elf32_Sym vs Elf64_Sym.

template <typename Traits>
void ElfBinary<Traits>::parseSymbolTables() {
    for (size_t i = 0; i < header_.e_shnum; i++) {
        const auto &sh = sectionHeaders_[i];
        if (sh.sh_type == SHT_SYMTAB) {
            size_t pos = sh.sh_offset;
            while (pos < sh.sh_offset + sh.sh_size) {
                symtab_.push_back(readSym(pos));
            }
        } else if (sh.sh_type == SHT_DYNSYM) {
            size_t pos = sh.sh_offset;
            while (pos < sh.sh_offset + sh.sh_size) {
                dynsymtab_.push_back(readSym(pos));
            }
        }
    }
    for (size_t i = 0; i < sectionHeaders_.size(); i++) {
        if (getSectionName(i) == ".strtab") {
            strtabIdx_   = i;
            strtabFound_ = true;
            break;
        }
    }
}

template <typename Traits>
void ElfBinary<Traits>::populateFunctions() {
    if (!strtabFound_) return;
    for (const auto &sym : symtab_) {
        if (!Traits::isFunction(sym.st_info)) continue;
        if (sym.st_name  == 0)               continue;
        if (sym.st_shndx == SHN_UNDEF)       continue;

        size_t fileOffset = virtualAddrToFileOffset(sym.st_value, sym.st_shndx);
        if (fileOffset == SIZE_MAX)           continue;

        functions_.push_back(Function{
            .name   = getStringFromTable(strtabIdx_, sym.st_name),
            .offset = fileOffset,
            .size   = static_cast<size_t>(sym.st_size),
        });
    }
}

template <typename Traits>
size_t ElfBinary<Traits>::virtualAddrToFileOffset(
    typename Traits::Addr vaddr, uint16_t shndx) const noexcept
{
    if (shndx < sectionHeaders_.size()) {
        const auto &sh = sectionHeaders_[shndx];
        if (vaddr >= sh.sh_addr && vaddr < sh.sh_addr + sh.sh_size) {
            return sh.sh_offset + (vaddr - sh.sh_addr);
        }
    }
    // Fallback: scan all PROGBITS sections
    for (const auto &sh : sectionHeaders_) {
        if (sh.sh_type != SHT_PROGBITS) continue;
        if (vaddr >= sh.sh_addr && vaddr < sh.sh_addr + sh.sh_size) {
            return sh.sh_offset + (vaddr - sh.sh_addr);
        }
    }
    return SIZE_MAX;
}

template <typename Traits>
std::string_view ElfBinary<Traits>::getStringFromTable(
    size_t tableIdx, size_t offset) const noexcept
{
    const auto &sh = sectionHeaders_[tableIdx];
    assert(sh.sh_type == SHT_STRTAB);
    return reinterpret_cast<const char *>(getData().data() + sh.sh_offset + offset);
}

template <typename Traits>
const std::vector<Function> &ElfBinary<Traits>::getFunctions() const noexcept {
    return functions_;
}

template <typename Traits>
std::span<const uint8_t> ElfBinary<Traits>::getFunctionCode(size_t idx) const noexcept {
    const Function &fn = functions_[idx];
    return std::span<const uint8_t>(getData().data() + fn.offset, fn.size);
}

template <typename Traits>
Architecture ElfBinary<Traits>::getArchitecture() const noexcept {
    switch (header_.e_machine) {
    case EM_X86_64:  return Architecture::X86_64;
    case EM_386:     return Architecture::X86;
    case EM_AARCH64: return Architecture::ARM64;
    case EM_ARM:     return Architecture::ARM;
    default:         return Architecture::Unknown;
    }
}

template <typename Traits>
const typename ElfBinary<Traits>::Ehdr &ElfBinary<Traits>::getHeader() const noexcept {
    return header_;
}

template <typename Traits>
const typename ElfBinary<Traits>::Shdr &ElfBinary<Traits>::getSectionHeader(size_t idx) const noexcept {
    return sectionHeaders_[idx];
}

template <typename Traits>
std::string_view ElfBinary<Traits>::getSectionName(size_t idx) const noexcept {
    return getStringFromTable(header_.e_shstrndx, sectionHeaders_[idx].sh_name);
}

// ===================================================================
// readSym explicit specialisations
// Elf32_Sym wire order: name, value, size, info, other, shndx
// Elf64_Sym wire order: name, info, other, shndx, value, size
// ===================================================================

template <>
Elf32Traits::Sym ElfBinary<Elf32Traits>::readSym(size_t &pos) {
    Elf32_Sym sym{};
    pos = readInt(sym.st_name,  pos);
    pos = readInt(sym.st_value, pos);
    pos = readInt(sym.st_size,  pos);
    pos = readInt(sym.st_info,  pos);
    pos = readInt(sym.st_other, pos);
    pos = readInt(sym.st_shndx, pos);
    return sym;
}

template <>
Elf64Traits::Sym ElfBinary<Elf64Traits>::readSym(size_t &pos) {
    Elf64_Sym sym{};
    pos = readInt(sym.st_name,  pos);
    pos = readInt(sym.st_info,  pos);
    pos = readInt(sym.st_other, pos);
    pos = readInt(sym.st_shndx, pos);
    pos = readInt(sym.st_value, pos);
    pos = readInt(sym.st_size,  pos);
    return sym;
}

template class ElfBinary<Elf32Traits>;
template class ElfBinary<Elf64Traits>;

[[nodiscard]] std::unique_ptr<Binary> fromFile(std::string_view filepath) {
    std::ifstream input(filepath.data(), std::ios::binary);
    if (!input) {
        throw std::runtime_error("Unable to open file: " + std::string(filepath));
    }
    std::vector<uint8_t> data(
        std::istreambuf_iterator<char>(input),
        std::istreambuf_iterator<char>{}
    );

    if (data.size() < EI_NIDENT) {
        throw std::runtime_error("File too small to be a recognised binary");
    }

    if (data[0] == ELFMAG0 && data[1] == ELFMAG1 &&
        data[2] == ELFMAG2 && data[3] == ELFMAG3)
    {
        auto reader = getElfReaderFunction(data);
        switch (data[EI_CLASS]) {
        case ELFCLASS32:
            return std::make_unique<Elf32>(std::move(data), reader);
        case ELFCLASS64:
            return std::make_unique<Elf64>(std::move(data), reader);
        default:
            throw std::runtime_error("Invalid ELF class byte");
        }
    }

    throw std::runtime_error("Unrecognised binary format");
}

} // namespace binary
