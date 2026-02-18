#ifndef _BINARY_HPP_
#define _BINARY_HPP_

#include <cstdint>
#include <elf.h>
#include <functional>
#include <memory>
#include <string_view>
#include <vector>
#include <span>

namespace binary {

struct Function {
	std::string_view name;
	size_t offset;
	size_t size;
};

class Binary {
  public:
    enum class Type {
        Elf32,
        Elf64,
    };

    size_t readIntRef(int8_t &ref, size_t position) const noexcept;
    size_t readIntRef(int16_t &ref, size_t position) const noexcept;
    size_t readIntRef(int32_t &ref, size_t position) const noexcept;
    size_t readIntRef(int64_t &ref, size_t position) const noexcept;
    size_t readIntRef(uint8_t &ref, size_t position) const noexcept;
    size_t readIntRef(uint16_t &ref, size_t position) const noexcept;
    size_t readIntRef(uint32_t &ref, size_t position) const noexcept;
    size_t readIntRef(uint64_t &ref, size_t position) const noexcept;

    virtual ~Binary() = default;

	const std::vector<uint8_t> &getData() const noexcept;

  protected:
    using ReaderFn =
        std::function<uint64_t(size_t, size_t, const std::vector<uint8_t> &)>;

    [[nodiscard]] Binary(Type type, std::vector<uint8_t> &&data,
                         ReaderFn reader);

    std::vector<uint8_t> &getData() noexcept;

  private:
    Type type_;
    std::vector<uint8_t> data_;
    ReaderFn reader_;
};

class Elf32 : public Binary {
  public:
    explicit Elf32(std::vector<uint8_t> &&data);

    [[nodiscard]] Elf32_Ehdr getHeader() const noexcept;
    [[nodiscard]] Elf32_Shdr getSectionHeader(size_t idx) const noexcept;
	[[nodiscard]] std::string_view getSectionName(size_t idx) const noexcept;
	[[nodiscard]] Elf32_Sym getSymbol(size_t idx) const noexcept;
	[[nodiscard]] const std::vector<Function> &getFunctions() const noexcept;

  private:

	[[nodiscard]] std::string_view getStringFromTable(size_t tableIdx, size_t offset) const noexcept;

    Elf32_Ehdr header_;
    std::vector<Elf32_Shdr> sectionHeaders_;
	std::vector<Elf32_Sym> symtab_;
	std::vector<Elf32_Sym> dynsymtab_;
	std::vector<Function> functions_;

	size_t strtabIdx_;
};

class Elf64 : public Binary {
  public:
    explicit Elf64(std::vector<uint8_t> &&data);

    [[nodiscard]] Elf64_Ehdr getHeader() const noexcept;
    [[nodiscard]] Elf64_Shdr getSectionHeader(size_t idx) const noexcept;
	[[nodiscard]] std::string_view getSectionName(size_t idx) const noexcept;
	[[nodiscard]] Elf64_Sym getSymbol(size_t idx) const noexcept;
	[[nodiscard]] const std::vector<Function> &getFunctions() const noexcept;
	[[nodiscard]] const std::span<const uint8_t> getFunctionCode(size_t idx) const noexcept;

  private:

	[[nodiscard]] std::string_view getStringFromTable(size_t tableIdx, size_t offset) const noexcept;

    Elf64_Ehdr header_;
    std::vector<Elf64_Shdr> sectionHeaders_;
	std::vector<Elf64_Sym> symtab_;
	std::vector<Elf64_Sym> dynsymtab_;
	std::vector<Function> functions_;

	size_t strtabIdx_;
};

[[nodiscard]] std::unique_ptr<Binary> fromFile(std::string_view filepath);

} // namespace binary

#endif
