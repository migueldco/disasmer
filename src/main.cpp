#include <binary.hpp>
#include <disassemble.hpp>
#include <demangle.hpp>

#include <elf.h>
#include <iostream>
#include <print>

size_t readSize(std::string_view data, size_t &position) {
    size_t ret = 0;
    while ('0' <= data[position] && data[position] <= '9') {
        ret *= 10;
        ret += data[position] - '0';
        position++;
    }
    return ret;
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        std::println("Usage: {} <filename>", argv[0]);
        return 0;
    }
    auto bin = binary::fromFile(argv[1]);
    if (auto elf32 = dynamic_cast<binary::Elf32 *>(bin.get())) {
        [[maybe_unused]] auto header = elf32->getHeader();
    } else if (auto elf64 = dynamic_cast<binary::Elf64 *>(bin.get())) {
        auto functions = elf64->getFunctions();
        std::optional<size_t> mainIdx;
        for (size_t i = 0; i < functions.size(); i++) {
            auto function = functions[i];
            if (function.name == "main") {
                mainIdx = i;
            }
        }
        if (mainIdx.has_value()) {
            [[maybe_unused]] auto idx = mainIdx.value();
            auto code = elf64->getFunctionCode(idx);
            std::println(
                "main:\n{}",
                disassemble::decodeX86_64(code));
        } else {
            std::println("main function not found");
        }
    } else {
        std::cerr << "Unsupported file type" << std::endl;
    }
    return 0;
}
