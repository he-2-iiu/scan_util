#include <iostream>
#include <string>
#include <vector>
#include <fstream>
#include <filesystem>
#include <chrono>
#include <thread>
#include <atomic>
#include <condition_variable>
#include <mutex>

constexpr unsigned thread_max = 4;
static std::atomic<unsigned> available_threads = thread_max;
static std::condition_variable cv;

static std::atomic<size_t> n_errors{};
static std::atomic<size_t> n_js_detects{};
static std::atomic<size_t> n_unix_detects{};
static std::atomic<size_t> n_macos_detects{};

static void inspect_file_task(const std::filesystem::directory_entry& entry);

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
  {
    std::ifstream dir{dir_path};
    if (!dir.is_open()) {
      std::cerr << "Not enough permissions to open " << dir_path << '\n';
      exit(EXIT_FAILURE);
    }
  }

  size_t n_searched{};
  std::vector<std::thread> tasks{};
  tasks.reserve(thread_max);
  std::mutex m{};
  std::unique_lock<std::mutex> lock {m};

  auto start{ std::chrono::high_resolution_clock::now() };

  for (const auto& entry : std::filesystem::directory_iterator{ dir_path,
                                                                std::filesystem::directory_options::skip_permission_denied }) {
    ++n_searched;
    cv.wait(lock, [&] {
      return available_threads > 0;
    });
    --available_threads;
    tasks.emplace_back(std::thread(inspect_file_task, entry));
  }

  for (auto &thread : tasks)
    thread.join();

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

static void inspect_file_task(const std::filesystem::directory_entry& entry)
{
  std::ifstream file{ entry.path() };
  if (!file.is_open()) {
    ++n_errors;
    ++available_threads;
    cv.notify_all();
    return;
  }

  const char* js_suspicious{ "<script>evil_script()</script>" };
  const char* unix_suspicious{ "rm -rf ~/Documents" };
  const char* macos_suspicious{ "system(\"launchctl load /Library/LaunchAgents/com.malware.agent\")" };

  std::string line;
  const auto& extension = entry.path().extension().string();
  if (extension == ".js") {
    while (getline(file, line)) {
      if (line.find(js_suspicious) != std::string::npos) {
        ++n_js_detects;
        ++available_threads;
        cv.notify_all();
        return;
      }
    }
  }

  while (getline(file, line)) {
    if (line.find(unix_suspicious) != std::string::npos) {
      ++n_unix_detects;
      break;
    }
    if (line.find(macos_suspicious) != std::string::npos) {
      ++n_macos_detects;
      break;
    }
  }
  ++available_threads;
  cv.notify_all();
}
