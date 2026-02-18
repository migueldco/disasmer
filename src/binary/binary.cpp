#include <binary.hpp>

#include <cassert>
#include <elf.h>
#include <fstream>
#include <iostream>
#include <print>

namespace binary {

bool checkMagicBytes(std::vector<uint8_t> &data, Binary::Type type) {
    switch (type) {
    case Binary::Type::Elf32:
    case Binary::Type::Elf64:
        std::vector<uint8_t> magic = {ELFMAG0, ELFMAG1, ELFMAG2, ELFMAG3};
        if (data.size() < 4) {
            return false;
        }
        for (size_t i = 0; i < 4; i++) {
            if (data[i] != magic[i]) {
                return false;
            }
        }
        return true;
    }
    return false;
}

Binary::Type identifyFileType(std::vector<uint8_t> &data) {
    if (checkMagicBytes(data, Binary::Type::Elf32)) {
        if (data[EI_CLASS] == ELFCLASS32) {
            return Binary::Type::Elf32;
        } else if (data[EI_CLASS] == ELFCLASS64) {
            return Binary::Type::Elf64;
        } else {
            throw std::runtime_error("Invalid ELF class");
        }
    }
    throw std::runtime_error("Unrecognized file type");
}

[[nodiscard]] std::unique_ptr<Binary> fromFile(std::string_view filepath) {
    std::ifstream input(filepath.data(), std::ios::binary);
    if (!input) {
        throw std::runtime_error("Unable to read file");
    }
    std::vector<uint8_t> data(std::istreambuf_iterator<char>(input), {});
    Binary::Type type = identifyFileType(data);
    switch (type) {
    case Binary::Type::Elf32:
        return std::make_unique<Elf32>(std::move(data));
    case Binary::Type::Elf64:
        return std::make_unique<Elf64>(std::move(data));
    }

    const bool unreachable = false;
    assert(unreachable);
}

size_t Binary::readIntRef(uint8_t &ref, size_t position) const noexcept {
    ref = reader_(position, sizeof(uint8_t), data_);
    return position + sizeof(uint8_t);
}
size_t Binary::readIntRef(uint16_t &ref, size_t position) const noexcept {
    ref = reader_(position, sizeof(uint16_t), data_);
    return position + sizeof(uint16_t);
}
size_t Binary::readIntRef(uint32_t &ref, size_t position) const noexcept {
    ref = reader_(position, sizeof(uint32_t), data_);
    return position + sizeof(uint32_t);
}
size_t Binary::readIntRef(uint64_t &ref, size_t position) const noexcept {
    ref = reader_(position, sizeof(uint64_t), data_);
    return position + sizeof(uint64_t);
}
size_t Binary::readIntRef(int8_t &ref, size_t position) const noexcept {
    ref = reader_(position, sizeof(int8_t), data_);
    return position + sizeof(int8_t);
}
size_t Binary::readIntRef(int16_t &ref, size_t position) const noexcept {
    ref = reader_(position, sizeof(int16_t), data_);
    return position + sizeof(int16_t);
}
size_t Binary::readIntRef(int32_t &ref, size_t position) const noexcept {
    ref = reader_(position, sizeof(int32_t), data_);
    return position + sizeof(int32_t);
}
size_t Binary::readIntRef(int64_t &ref, size_t position) const noexcept {
    ref = reader_(position, sizeof(int64_t), data_);
    return position + sizeof(int64_t);
}

uint64_t readLsb(size_t position, size_t intSize,
                 const std::vector<uint8_t> &data) {
    uint64_t ret = 0;
    for (size_t i = 0; i < intSize; i++) {
        ret |= data[position + i] << (8 * i);
    }
    return ret;
}

uint64_t readMsb(size_t position, size_t intSize,
                 const std::vector<uint8_t> &data) {
    uint64_t ret = 0;
    for (size_t i = 0; i < intSize; i++) {
        ret <<= 8;
        ret |= data[position + i];
    }
    return ret;
}

std::function<uint64_t(size_t, size_t, const std::vector<uint8_t> &)>
getElfReaderFunction(const std::vector<uint8_t> &data) {
    if (data[EI_DATA] == ELFDATA2LSB) {
        return readLsb;
    }
    if (data[EI_DATA] == ELFDATA2MSB) {
        return readMsb;
    }
    throw std::runtime_error("Invalid data encoding");
}

Elf32::Elf32(std::vector<std::uint8_t> &&data)
    : Binary(Type::Elf32, std::forward<std::vector<uint8_t>>(data),
             getElfReaderFunction(data)) {

    std::copy(header_.e_ident, header_.e_ident + EI_NIDENT, getData().begin());
    size_t position = EI_NIDENT;
    position = readIntRef(header_.e_type, position);
    position = readIntRef(header_.e_machine, position);
    position = readIntRef(header_.e_version, position);
    position = readIntRef(header_.e_entry, position);
    position = readIntRef(header_.e_phoff, position);
    position = readIntRef(header_.e_shoff, position);
    position = readIntRef(header_.e_flags, position);
    position = readIntRef(header_.e_ehsize, position);
    position = readIntRef(header_.e_phentsize, position);
    position = readIntRef(header_.e_phnum, position);
    position = readIntRef(header_.e_shentsize, position);
    position = readIntRef(header_.e_shnum, position);
    position = readIntRef(header_.e_shstrndx, position);

    sectionHeaders_.resize(header_.e_shnum);
    position = header_.e_shoff;
    for (size_t i = 0; i < header_.e_shnum; i++) {
        position = readIntRef(sectionHeaders_[i].sh_name, position);
        position = readIntRef(sectionHeaders_[i].sh_type, position);
        position = readIntRef(sectionHeaders_[i].sh_flags, position);
        position = readIntRef(sectionHeaders_[i].sh_addr, position);
        position = readIntRef(sectionHeaders_[i].sh_offset, position);
        position = readIntRef(sectionHeaders_[i].sh_size, position);
        position = readIntRef(sectionHeaders_[i].sh_link, position);
        position = readIntRef(sectionHeaders_[i].sh_info, position);
        position = readIntRef(sectionHeaders_[i].sh_addralign, position);
        position = readIntRef(sectionHeaders_[i].sh_entsize, position);
    }

    for (size_t i = 0; i < header_.e_shnum; i++) {
        if (sectionHeaders_[i].sh_type == SHT_DYNSYM) {
            position = sectionHeaders_[i].sh_offset;
            while (position <
                   sectionHeaders_[i].sh_offset + sectionHeaders_[i].sh_size) {
                Elf32_Sym symbol;
                position = readIntRef(symbol.st_name, position);
                position = readIntRef(symbol.st_value, position);
                position = readIntRef(symbol.st_size, position);
                position = readIntRef(symbol.st_info, position);
                position = readIntRef(symbol.st_other, position);
                position = readIntRef(symbol.st_shndx, position);
                symtab_.push_back(symbol);
            }
        }
    }
}

Elf64::Elf64(std::vector<std::uint8_t> &&data)
    : Binary(Type::Elf64, std::forward<std::vector<uint8_t>>(data),
             getElfReaderFunction(data)) {

    std::copy(header_.e_ident, header_.e_ident + EI_NIDENT, getData().begin());
    size_t position = EI_NIDENT;
    position = readIntRef(header_.e_type, position);
    position = readIntRef(header_.e_machine, position);
    position = readIntRef(header_.e_version, position);
    position = readIntRef(header_.e_entry, position);
    position = readIntRef(header_.e_phoff, position);
    position = readIntRef(header_.e_shoff, position);
    position = readIntRef(header_.e_flags, position);
    position = readIntRef(header_.e_ehsize, position);
    position = readIntRef(header_.e_phentsize, position);
    position = readIntRef(header_.e_phnum, position);
    position = readIntRef(header_.e_shentsize, position);
    position = readIntRef(header_.e_shnum, position);
    position = readIntRef(header_.e_shstrndx, position);

    sectionHeaders_.resize(header_.e_shnum);
    position = header_.e_shoff;
    for (size_t i = 0; i < header_.e_shnum; i++) {
        position = readIntRef(sectionHeaders_[i].sh_name, position);
        position = readIntRef(sectionHeaders_[i].sh_type, position);
        position = readIntRef(sectionHeaders_[i].sh_flags, position);
        position = readIntRef(sectionHeaders_[i].sh_addr, position);
        position = readIntRef(sectionHeaders_[i].sh_offset, position);
        position = readIntRef(sectionHeaders_[i].sh_size, position);
        position = readIntRef(sectionHeaders_[i].sh_link, position);
        position = readIntRef(sectionHeaders_[i].sh_info, position);
        position = readIntRef(sectionHeaders_[i].sh_addralign, position);
        position = readIntRef(sectionHeaders_[i].sh_entsize, position);
    }

    for (size_t i = 0; i < header_.e_shnum; i++) {
        if (sectionHeaders_[i].sh_type == SHT_DYNSYM) {
            position = sectionHeaders_[i].sh_offset;
            while (position <
                   sectionHeaders_[i].sh_offset + sectionHeaders_[i].sh_size) {
                Elf64_Sym symbol;
                position = readIntRef(symbol.st_name, position);
                position = readIntRef(symbol.st_info, position);
                position = readIntRef(symbol.st_other, position);
                position = readIntRef(symbol.st_shndx, position);
                position = readIntRef(symbol.st_value, position);
                position = readIntRef(symbol.st_size, position);
                dynsymtab_.push_back(symbol);
            }
        } else if (sectionHeaders_[i].sh_type == SHT_SYMTAB) {
            position = sectionHeaders_[i].sh_offset;
            while (position <
                   sectionHeaders_[i].sh_offset + sectionHeaders_[i].sh_size) {
                Elf64_Sym symbol;
                position = readIntRef(symbol.st_name, position);
                position = readIntRef(symbol.st_info, position);
                position = readIntRef(symbol.st_other, position);
                position = readIntRef(symbol.st_shndx, position);
                position = readIntRef(symbol.st_value, position);
                position = readIntRef(symbol.st_size, position);
                symtab_.push_back(symbol);
            }
        }
    }
    for (size_t i = 0; i < sectionHeaders_.size(); i++) {
        if (getSectionName(i) == ".strtab") {
            strtabIdx_ = i;
        }
    }
    for (size_t i = 0; i < symtab_.size(); i++) {
        if (ELF64_ST_TYPE(symtab_[i].st_info) == STT_FUNC) {
			Function fn;
			if (symtab_[i].st_name == 0) {
				continue;
			}
			if (symtab_[i].st_shndx == SHN_UNDEF) {
				continue;
			}
			fn.name = getStringFromTable(strtabIdx_, symtab_[i].st_name);
			fn.size = symtab_[i].st_size;
			fn.offset = symtab_[i].st_value;
			functions_.push_back(fn);
        }
    }
}

std::vector<uint8_t> &Binary::getData() noexcept { return data_; }

Binary::Binary(Type type, std::vector<uint8_t> &&data, ReaderFn reader)
    : type_(type), data_(data), reader_(reader) {}

[[nodiscard]] Elf32_Ehdr Elf32::getHeader() const noexcept { return header_; }

[[nodiscard]] Elf64_Ehdr Elf64::getHeader() const noexcept { return header_; }

[[nodiscard]] Elf32_Shdr Elf32::getSectionHeader(size_t idx) const noexcept {
    return sectionHeaders_[idx];
}

[[nodiscard]] Elf64_Shdr Elf64::getSectionHeader(size_t idx) const noexcept {
    return sectionHeaders_[idx];
}

[[nodiscard]] std::string_view
Elf32::getStringFromTable(size_t tableIdx, size_t offset) const noexcept {
    auto sectionHeader = sectionHeaders_[tableIdx];
    assert(sectionHeader.sh_type == SHT_STRTAB);
    return reinterpret_cast<const char *>(getData().data() +
                                          sectionHeader.sh_offset + offset);
}

[[nodiscard]] std::string_view
Elf64::getStringFromTable(size_t tableIdx, size_t offset) const noexcept {
    auto sectionHeader = sectionHeaders_[tableIdx];
    assert(sectionHeader.sh_type == SHT_STRTAB);
    return reinterpret_cast<const char *>(getData().data() +
                                          sectionHeader.sh_offset + offset);
}

[[nodiscard]] std::string_view
Elf32::getSectionName(size_t idx) const noexcept {
    return getStringFromTable(header_.e_shstrndx, sectionHeaders_[idx].sh_name);
}

[[nodiscard]] std::string_view
Elf64::getSectionName(size_t idx) const noexcept {
    return getStringFromTable(header_.e_shstrndx, sectionHeaders_[idx].sh_name);
}

[[nodiscard]] const std::vector<uint8_t> &Binary::getData() const noexcept {
    return data_;
}

[[nodiscard]] Elf32_Sym Elf32::getSymbol(size_t idx) const noexcept {
    return symtab_[idx];
}

[[nodiscard]] Elf64_Sym Elf64::getSymbol(size_t idx) const noexcept {
    return symtab_[idx];
}

[[nodiscard]] const std::vector<Function> &
Elf64::getFunctions() const noexcept {
    return functions_;
}

[[nodiscard]] const std::vector<Function> &
Elf32::getFunctions() const noexcept {
    return functions_;
}

[[nodiscard]] const std::span<const uint8_t> Elf64::getFunctionCode(size_t idx) const noexcept {
	auto fn = functions_[idx];
	return std::span(getData().begin() + fn.offset, getData().begin() + fn.offset + fn.size);
}

}; // namespace binary
