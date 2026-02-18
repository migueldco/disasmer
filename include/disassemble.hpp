#ifndef _DISASSEMBLE_HPP_
#define _DISASSEMBLE_HPP_

#include <cstdint>
#include <span>
#include <string>

namespace disassemble {

std::string disassembleX86_64(const std::span<const uint8_t> code);

std::string decodeX86_64(const std::span<const uint8_t> code);

};

#endif
