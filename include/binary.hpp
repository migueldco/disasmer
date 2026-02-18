#ifndef BINARY_HPP
#define BINARY_HPP

#include <concepts>
#include <cstdint>
#include <functional>
#include <memory>
#include <span>
#include <string_view>
#include <vector>

namespace binary {

enum class Architecture {
	X86_64,
	X86,
	ARM64,
	ARM,
	Unknown,
};

struct Function {
	std::string_view name;
	size_t offset;
	size_t size;
};

class Binary {
  public:
	using ReaderFn = std::function<uint64_t(size_t pos, size_t intSize,
											const std::vector<uint8_t> &data)>;

	virtual ~Binary() = default;

	Binary(const Binary &) = delete;
	Binary &operator=(const Binary &) = delete;

	[[nodiscard]] virtual const std::vector<Function> &
	getFunctions() const noexcept = 0;
	[[nodiscard]] virtual std::span<const uint8_t>
	getFunctionCode(size_t idx) const noexcept = 0;
	[[nodiscard]] virtual Architecture getArchitecture() const noexcept = 0;

	[[nodiscard]] const std::vector<uint8_t> &getData() const noexcept;

  protected:
	explicit Binary(std::vector<uint8_t> &&data, ReaderFn reader);

	template <std::integral T>
	size_t readInt(T &ref, size_t pos) const noexcept {
		ref = static_cast<T>(reader_(pos, sizeof(T), data_));
		return pos + sizeof(T);
	}

	[[nodiscard]] std::vector<uint8_t> &getData() noexcept;

  private:
	std::vector<uint8_t> data_;
	ReaderFn reader_;
};

[[nodiscard]] std::unique_ptr<Binary> fromFile(std::string_view filepath);

}; // namespace binary

#endif
