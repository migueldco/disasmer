#ifndef _DEMANGLE_HPP_
#define _DEMANGLE_HPP_

#include <string>
#include <string_view>

namespace analysis {

std::string demangleCpp(std::string_view name);

};

#endif
