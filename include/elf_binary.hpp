#ifndef ELF_BINARY_HPP
#define ELF_BINARY_HPP

#include <binary.hpp>
#include <elf_types.hpp>

#include <cassert>
#include <string_view>

namespace binary {

struct Elf32Traits {
    using Ehdr = Elf32_Ehdr;
    using Shdr = Elf32_Shdr;
    using Sym  = Elf32_Sym;
    using Addr = Elf32_Addr;

    static bool isFunction(uint8_t st_info) {
        return elf_st_type(st_info) == STT_FUNC;
    }
};

struct Elf64Traits {
    using Ehdr = Elf64_Ehdr;
    using Shdr = Elf64_Shdr;
    using Sym  = Elf64_Sym;
    using Addr = Elf64_Addr;

    static bool isFunction(uint8_t st_info) {
        return elf_st_type(st_info) == STT_FUNC;
    }
};

template <typename Traits>
class ElfBinary : public Binary {
  public:
    using Ehdr = typename Traits::Ehdr;
    using Shdr = typename Traits::Shdr;
    using Sym  = typename Traits::Sym;

    explicit ElfBinary(std::vector<uint8_t> &&data, ReaderFn reader);

    [[nodiscard]] const std::vector<Function> &getFunctions() const noexcept override;
    [[nodiscard]] std::span<const uint8_t> getFunctionCode(size_t idx) const noexcept override;
    [[nodiscard]] Architecture getArchitecture() const noexcept override;

    // ELF-specific accessors (not on the base class)
    [[nodiscard]] const Ehdr &getHeader() const noexcept;
    [[nodiscard]] const Shdr &getSectionHeader(size_t idx) const noexcept;
    [[nodiscard]] std::string_view getSectionName(size_t idx) const noexcept;

  private:
    void parseHeader();
    void parseSectionHeaders();
    void parseSymbolTables();
    void populateFunctions();

    // readSym is explicitly specialised in binary.cpp to handle the
    // different field ordering between Elf32_Sym and Elf64_Sym.
    Sym readSym(size_t &pos);

    [[nodiscard]] std::string_view getStringFromTable(size_t tableIdx, size_t offset) const noexcept;
    [[nodiscard]] size_t virtualAddrToFileOffset(typename Traits::Addr vaddr, uint16_t shndx) const noexcept;

    Ehdr header_{};
    std::vector<Shdr> sectionHeaders_;
    std::vector<Sym> symtab_;
    std::vector<Sym> dynsymtab_;
    std::vector<Function> functions_;
    size_t strtabIdx_ = 0;
    bool strtabFound_ = false;
};

using Elf32 = ElfBinary<Elf32Traits>;
using Elf64 = ElfBinary<Elf64Traits>;

} // namespace binary

#endif // ELF_BINARY_HPP
