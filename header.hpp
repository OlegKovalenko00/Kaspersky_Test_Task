#pragma once
#include <algorithm>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <map>
#include <mutex>
#include <openssl/evp.h>
#include <queue>
#include <sstream>
#include <string>
#include <system_error>
#include <thread>
#include <vector>

//------------Очередь многопоточки--------------

template <typename T> class ThreadSafeQueue {
public:
  ThreadSafeQueue() = default;
  void notify_all() { cv_.notify_all(); }

  void push(T value) {
    std::unique_lock<std::mutex> lock(mtx_);
    q_.push(std::move(value));
    lock.unlock();
    cv_.notify_one();
  }

  bool wait_pop(T &out, std::atomic<bool> &producer_done) {
    std::unique_lock<std::mutex> lock(mtx_);
    cv_.wait(lock, [&] { return !q_.empty() || producer_done.load(); });
    if (q_.empty())
      return false;
    out = std::move(q_.front());
    q_.pop();
    return true;
  }

  bool empty() {
    std::lock_guard<std::mutex> lock(mtx_);
    return q_.empty();
  }

  size_t size() {
    std::lock_guard<std::mutex> lock(mtx_);
    return q_.size();
  }

private:
  std::queue<T> q_;
  std::mutex mtx_;
  std::condition_variable cv_;
};

// -------------------- MD5Hasher --------------------
class MD5Hasher {
public:
  MD5Hasher();
  ~MD5Hasher();

  MD5Hasher(const MD5Hasher &) = delete;
  MD5Hasher &operator=(const MD5Hasher &) = delete;

  bool valid() const;
  bool update(const void *data, size_t len);
  bool finalize(std::string &out_hex);

private:
  EVP_MD_CTX *ctx_;
  bool finished_;
};

// -------------------- FileReader --------------------
class FileReader {
public:
  // Читает файл по блокам и обновляет hasher; возвращает true и устанавливает
  // hash_hex при успехе.
  static bool read_and_hash(const std::filesystem::path &path,
                            MD5Hasher &hasher, std::string &hash_hex,
                            std::string &err_msg);
};

// -------------------- Scanner --------------------
class Scanner {
public:
  Scanner() = default;

  void start_workers(unsigned int num_threads);
  void stop_and_join_workers();

  bool load_bad_hash(const std::filesystem::path &csv_path);
  bool open_log(const std::filesystem::path &log_path);
  void scan(const std::filesystem::path &root);

  void report() const;
  void dump_bad_hash() const;

private:
  void process_path(const std::filesystem::path &p);
  static std::string trim_copy(std::string s);

private:
  std::map<std::string, std::string> bad_hash_;
  std::ofstream log_;

  std::atomic<long long> count_files_{0};
  std::atomic<long long> count_bad_{0};
  std::atomic<long long> count_error_{0};
  long long elapsed_seconds_ = 0;
  ThreadSafeQueue<std::filesystem::path> work_queue_;
  std::vector<std::thread> workers_;
  std::atomic<bool> producer_done_{false};

  std::mutex out_mtx_;
};