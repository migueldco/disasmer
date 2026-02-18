#include <binary.hpp>
#include <disassemble.hpp>
#include <demangle.hpp>

#include <iostream>
#include <print>

int main(int argc, char *argv[]) {
    if (argc < 2) {
        std::println("Usage: {} <filename>", argv[0]);
        return 0;
    }

    auto bin = binary::fromFile(argv[1]);

    const auto &functions = bin->getFunctions();
    // for (const auto &fn : functions) {
    //     std::cout << analysis::demangleCpp(fn.name) << '\n';
    // }

    std::optional<size_t> mainIdx;
    for (size_t i = 0; i < functions.size(); i++) {
        if (functions[i].name == "main") {
            mainIdx = i;
        }
    }

    if (mainIdx.has_value()) {
        auto code = bin->getFunctionCode(mainIdx.value());
        std::println("main:\n{}", disassemble::disassembleX86_64(code));
    } else {
        std::println("main function not found");
    }

    return 0;
}
