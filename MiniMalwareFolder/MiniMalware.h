#pragma once
#include <filesystem>
namespace MW {
class Malware {
public:
    explicit Malware();
    void attack();
private:
    std::filesystem::path workingDirectory;
};
class MalwareError: public std::runtime_error {
public:
    MalwareError(const std::string& s);
    const char* what() const noexcept override;
private:
    std::string message;
};
}
