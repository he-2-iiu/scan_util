#include <iostream>
#include <string>
#include <fstream>
#include <filesystem>
#include <chrono>

enum class Result
{
  error,
  js_suspicious,
  unix_suspicious,
  macos_suspicious,
  none
};

static Result inspect_file(const std::filesystem::directory_entry& entry);

int main(int argc, char* argv[])
{
  if (argc != 2) {
    std::cerr << "Usage: " << argv[0] << " [directory path]\n";
    exit(EXIT_FAILURE);
  }

  std::filesystem::path dir_path{ argv[1] };
  if (!std::filesystem::exists(dir_path)) {
    std::cerr << dir_path << " does not exist.\n";
    exit(EXIT_FAILURE);
  }
  if (!std::filesystem::is_directory(dir_path)) {
    std::cerr << dir_path << " is not a directory\n";
    exit(EXIT_FAILURE);
  }

  size_t n_searched{};
  size_t n_errors{};
  size_t n_js_detects{};
  size_t n_unix_detects{};
  size_t n_macos_detects{};

  auto start{ std::chrono::high_resolution_clock::now() };

  for (const auto& entry : std::filesystem::directory_iterator{ dir_path,
                                                                std::filesystem::directory_options::skip_permission_denied }) {
    ++n_searched;
    Result res{ inspect_file(entry) };
    switch (res) {
      case Result::error:
        ++n_errors;
        break;
      case Result::js_suspicious:
        ++n_js_detects;
        break;
      case Result::unix_suspicious:
        ++n_unix_detects;
        break;
      case Result::macos_suspicious:
        ++n_macos_detects;
        break;
      case Result::none:
        break;
      default:
        ;
    }
  }

  auto duration{ std::chrono::high_resolution_clock::now() - start };
  auto duration_s = std::chrono::duration_cast<std::chrono::seconds>(duration).count();
  auto duration_ms = std::chrono::duration_cast<std::chrono::milliseconds>(duration).count() % 1000;
  auto duration_us = std::chrono::duration_cast<std::chrono::microseconds>(duration).count() % 1000;

  std::cout << "====== Scan result ===========\n" <<
            "Processed files: " << n_searched << '\n' <<
            "JS detects: " << n_js_detects << '\n' <<
            "Unix detects: " << n_unix_detects << '\n' <<
            "macOS detects: " << n_macos_detects << '\n' <<
            "Errors: " << n_errors << '\n' <<
            "Execution time: " << std::fixed << std::setprecision(2) << duration_s << "s:" <<
            std::fixed << std::setprecision(2) << duration_ms << "ms:" <<
            std::fixed << std::setprecision(2) << duration_us << "us" << '\n' <<
            "==============================\n";
  return EXIT_SUCCESS;
}

static Result inspect_file(const std::filesystem::directory_entry& entry)
{
  std::ifstream file{ entry.path() };
  if (!file.is_open()) {
    return Result::error;
  }

  const char* js_suspicious{ "<script>evil_script()</script>" };
  const char* unix_suspicious{ "rm -rf ~/Documents" };
  const char* macos_suspicious{ "system(\"launchctl load /Library/LaunchAgents/com.malware.agent\")" };

  std::string line;
  const auto& extension = entry.path().extension().string();
  if (extension == ".js") {
    while (getline(file, line)) {
      if (line.find(js_suspicious) != std::string::npos) {
        return Result::js_suspicious;
      }
    }
  }

  while (getline(file, line)) {
    if (line.find(unix_suspicious) != std::string::npos) {
      return Result::unix_suspicious;
    }
    if (line.find(macos_suspicious) != std::string::npos) {
      return Result::macos_suspicious;
    }
  }
  return Result::none;
}
