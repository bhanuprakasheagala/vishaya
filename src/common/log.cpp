#include "common/log.h"

#include <chrono>
#include <ctime>
#include <iomanip>
#include <iostream>
#include <mutex>
#include <sstream>

namespace vishaya::log {

namespace {

Level g_level = Level::Info;
std::mutex g_mutex;

const char* level_prefix(Level lvl) {
  switch (lvl) {
    case Level::Debug: return "DEBUG";
    case Level::Info:  return "INFO ";
    case Level::Warn:  return "WARN ";
    case Level::Error: return "ERROR";
  }
  return "?????";
}

std::string current_iso_time() {
  using namespace std::chrono;
  const auto now  = system_clock::now();
  const auto tt   = system_clock::to_time_t(now);
  const auto ms   = duration_cast<milliseconds>(now.time_since_epoch()) % 1000;
  std::tm tm_utc{};
  gmtime_r(&tt, &tm_utc);
  std::ostringstream oss;
  oss << std::put_time(&tm_utc, "%Y-%m-%dT%H:%M:%S")
      << '.' << std::setfill('0') << std::setw(3) << ms.count() << 'Z';
  return oss.str();
}

} // namespace

void set_level(Level lvl) {
  std::lock_guard<std::mutex> lock(g_mutex);
  g_level = lvl;
}

void write(Level lvl, std::string_view msg) {
  std::lock_guard<std::mutex> lock(g_mutex);
  if (static_cast<int>(lvl) < static_cast<int>(g_level)) return;
  std::cerr << '[' << current_iso_time() << "] " << level_prefix(lvl) << " " << msg << '\n';
}

} // namespace vishaya::log
