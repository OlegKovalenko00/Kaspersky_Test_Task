#include "header.hpp"

#include <chrono>

// -------------------- MD5Hasher implementation --------------------
MD5Hasher::MD5Hasher() : ctx_(EVP_MD_CTX_new()), finished_(false) {
    if (ctx_) {
        const EVP_MD* md = EVP_md5();
        if (EVP_DigestInit_ex(ctx_, md, nullptr) != 1) {
            EVP_MD_CTX_free(ctx_);
            ctx_ = nullptr;
        }
    }
}

MD5Hasher::~MD5Hasher() {
    if (ctx_) EVP_MD_CTX_free(ctx_);
}

bool MD5Hasher::valid() const { return ctx_ != nullptr; }

bool MD5Hasher::update(const void* data, size_t len) {
    if (!ctx_) return false;
    if (finished_) return false;
    return EVP_DigestUpdate(ctx_, data, len) == 1;
}

bool MD5Hasher::finalize(std::string &out_hex) {
    if (!ctx_ || finished_) return false;
    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int digest_len = 0;
    if (EVP_DigestFinal_ex(ctx_, digest, &digest_len) != 1) return false;
    finished_ = true;

    std::ostringstream oss;
    oss << std::hex << std::setfill('0');
    for (unsigned int i = 0; i < digest_len; ++i) {
        oss << std::setw(2) << static_cast<unsigned int>(digest[i]);
    }
    out_hex = oss.str();
    return true;
}

// -------------------- FileReader implementation --------------------
bool FileReader::read_and_hash(const std::filesystem::path &path, MD5Hasher &hasher, std::string &hash_hex, std::string &err_msg) {
    std::ifstream file(path, std::ios::binary);
    if (!file) {
        err_msg = "Can't open file: " + path.string();
        return false;
    }

    constexpr std::size_t BUF_SIZE = 160000;
    std::vector<char> buffer(BUF_SIZE);

    while (file) {
        file.read(buffer.data(), static_cast<std::streamsize>(buffer.size()));
        std::streamsize read_bytes = file.gcount();
        if (read_bytes > 0) {
            if (!hasher.update(buffer.data(), static_cast<size_t>(read_bytes))) {
                err_msg = "Hasher update failed for file: " + path.string();
                return false;
            }
        }
    }

    if (file.bad()) {
        err_msg = "I/O error while reading file: " + path.string();
        return false;
    }

    if (!hasher.finalize(hash_hex)) {
        err_msg = "Hasher finalize failed for file: " + path.string();
        return false;
    }

    return true;
}

// -------------------- Scanner implementation --------------------
bool Scanner::load_bad_hash(const std::filesystem::path &csv_path) {
    std::ifstream in(csv_path);
    if (!in) {
        std::cerr << "Не удалось открыть базовый файл: " << csv_path << std::endl;
        return false;
    }
    std::string line;
    while (std::getline(in, line)) {
        if (line.empty()) continue;
        auto pos = line.find(';');
        if (pos == std::string::npos) continue;
        std::string key = trim_copy(line.substr(0, pos));
        std::string val = trim_copy(line.substr(pos + 1));
        if (!key.empty()) bad_hash_.emplace(std::move(key), std::move(val));
    }
    return true;
}

bool Scanner::open_log(const std::filesystem::path &log_path) {
    log_.open(log_path, std::ios::app);
    if (!log_) {
        std::cerr << "Не удалось открыть лог: " << log_path << std::endl;
        return false;
    }
    return true;
}

void Scanner::scan(const std::filesystem::path &root) {
    unsigned int hw = std::max(1u, std::thread::hardware_concurrency());
    unsigned int num_threads = hw;
    start_workers(num_threads);

    std::error_code ec;
    if (!std::filesystem::exists(root, ec) || !std::filesystem::is_directory(root, ec)) {
        std::cerr << "Путь не существует или не директория: " << root << std::endl;
        return;
    }

    using clock = std::chrono::steady_clock;
    auto t0 = clock::now();

    for (std::filesystem::recursive_directory_iterator it(root, std::filesystem::directory_options::skip_permission_denied, ec), end; it != end; it.increment(ec)) {
        if (ec) {
            std::cerr << "Ошибка при обходе: " << ec.message() << " (path: " << it->path().string() << ")\n";
            ++count_error_;
            continue;
        }
        try {
            const std::filesystem::path p = it->path();
            if (std::filesystem::is_regular_file(p, ec)) {
                work_queue_.push(p);
            }
        } catch (const std::exception &ex) {
            std::cerr << "Исключение при обработке " << it->path().string() << " : " << ex.what() << std::endl;
            ++count_error_;
        }
    }


    producer_done_.store(true);
    work_queue_.notify_all();
    stop_and_join_workers();

    auto t1 = clock::now();
    elapsed_seconds_ = std::chrono::duration_cast<std::chrono::seconds>(t1 - t0).count();
}

void Scanner::process_path(const std::filesystem::path &p) {
    MD5Hasher hasher;
    if (!hasher.valid()) {
        std::lock_guard<std::mutex> lock(out_mtx_);
        std::cerr << "Не удалось инициализировать MD5 hasher" << std::endl;
        ++count_error_;
        return;
    }

    std::string hex;
    std::string err;
    if (!FileReader::read_and_hash(p, hasher, hex, err)) {
        std::lock_guard<std::mutex> lock(out_mtx_);
        std::cerr << err << std::endl;
        ++count_error_;
        return;
    }

    {
        std::lock_guard<std::mutex> lock(out_mtx_);
        std::cout << hex << "  " << p.string() << std::endl;

        auto it = bad_hash_.find(hex);
        if (it != bad_hash_.end()) {
            ++count_bad_;
            std::cout << it->second << " Find" << std::endl;
            if (log_) {
                log_ << hex << ';' << p.string() << ';' << it->second << '\n';
            } else {
                std::cerr << "Log stream not open\n";
            }
        }
    }
}

std::string Scanner::trim_copy(std::string s) {
    auto not_space = [](unsigned char ch) { return !std::isspace(ch); };
    s.erase(s.begin(), std::find_if(s.begin(), s.end(), not_space));
    s.erase(std::find_if(s.rbegin(), s.rend(), not_space).base(), s.end());
    if (!s.empty() && s.back() == '\r') s.pop_back();
    return s;
}

void Scanner::start_workers(unsigned int num_threads) {
    if (!workers_.empty()) return;
    for (unsigned int i = 0; i < num_threads; ++i) {
        workers_.emplace_back([this]() {
            while (true) {
                std::filesystem::path p;
                bool got = work_queue_.wait_pop(p, producer_done_);
                if (!got) {
                    break;
                }

                try {
                    ++count_files_;
                    process_path(p);
                } catch (const std::exception &ex) {
                    std::lock_guard<std::mutex> lock(out_mtx_);
                    std::cerr << "Exception in worker for " << p << " : " << ex.what() << std::endl;
                    ++count_error_;
                } catch (...) {
                    std::lock_guard<std::mutex> lock(out_mtx_);
                    std::cerr << "Unknown exception in worker for " << p << std::endl;
                    ++count_error_;
                }
            }
        });
    }
}


void Scanner::stop_and_join_workers() {
    producer_done_.store(true);
    for (auto &t : workers_) {
        if (t.joinable()) t.join();
    }
    workers_.clear();
}


void Scanner::report() const {
    std::cout << "Обработано файлов: " << count_files_ << '\n';
    std::cout << "Найдено плохих файлов: " << count_bad_ << '\n';
    std::cout << "Ошибок: " << count_error_ << '\n';
    std::cout << "Время работы (s): " << elapsed_seconds_ << '\n';
}

void Scanner::dump_bad_hash() const {
    for (const auto &p : bad_hash_) {
        std::cout << p.first << " -> " << p.second << '\n';
    }
}

// -------------------- main --------------------
int main(int argc, char **argv) {
    std::string base_file = "bad_hash.csv";
    std::string log_file = "report.log";
    std::filesystem::path root;

#ifdef _WIN32
    root = "C:\\";
#else
    root = "/home/olozavr/Documents/projects/c++/kasperky";
#endif

    for (int i = 1; i < argc; ++i) {
        std::string a = argv[i];
        if (a == "--base" && i + 1 < argc) {
            base_file = argv[++i];
        } else if (a == "--log" && i + 1 < argc) {
            log_file = argv[++i];
        } else if (a == "--path" && i + 1 < argc) {
            root = std::filesystem::path(argv[++i]);
        } else if (a == "--help" || a == "-h") {
            std::cout << "Usage: " << argv[0] << " [--base base.csv] [--log report.log] [--path <dir>]\n";
            return 0;
        } else {
            std::cerr << "Unknown or incomplete option: " << a << "\n";
            std::cerr << "Use --help for usage.\n";
            return 1;
        }
    }

    Scanner scanner;
    if (!scanner.load_bad_hash(base_file)) return 1;
    if (!scanner.open_log(log_file)) return 1;

    std::cout << "Start walk at: " << root << std::endl;
    scanner.scan(root);

    scanner.report();
    return 0;
}