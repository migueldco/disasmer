#include <demangle.hpp>
#include <cxxabi.h>

namespace analysis {

std::string demangleCpp(std::string_view name) {
	int status = 0;
	char *demangledNamePtr =
		abi::__cxa_demangle(name.data(), nullptr, nullptr, &status);
	if (demangledNamePtr == nullptr) {
		return std::string(name);
	}
	std::string_view demangledName{demangledNamePtr};
	return std::string{(status == 0) ? demangledName : name};
}

}; // namespace analysis
