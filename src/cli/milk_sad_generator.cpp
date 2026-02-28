/**
 * Milk Sad Scanner - Optimized Legacy Edition (v4)
 * Features:
 * - 24 Byte Entropy (192-bit / 18 Words)
 * - UTC Time (timegm)
 * - Cached Derivation Path (High Performance)
 * - Persistent OpenSSL Objects (No malloc inside loop)
 * - BIP32 Validation (Il < n, child != 0)
 * - 64-bit Time Loop
 */

// Define macros for timegm if on Linux/BSD
#define _DEFAULT_SOURCE
#define _BSD_SOURCE

#include <iostream>
#include <fstream>
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
#include <openssl/hmac.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/bn.h>
#include <openssl/obj_mac.h>
#include <thread>
#include <atomic>
#include <random>
#include <cstring>
#include <climits>

// --- KONFIGURASI ---
const std::string WORDLIST_FILE = "english.txt";
const std::string OUTPUT_PREFIX = "found_legacy_keys_";
const uint64_t REPORT_INTERVAL = 20000;
const std::string BRAINFLAYER_BIN = "./brainflayer/brainflayer";
const std::string BLOOM_FILTER = "./040823BF.blf";

// [UPGRADE] Entropy diset ke 24 bytes (192 bits -> 18 words)
const int ENTROPY_BYTES = 24;

// --- GLOBAL VARIABLES ---
std::vector<pid_t> g_child_pids;
std::atomic<bool> g_stop_flag(false);

// --- HELPER FUNCTIONS ---

void signal_handler(int) {
    if (g_stop_flag) return;
    g_stop_flag = true;
    const char* msg = "\n[!] Interrupt. Stopping...\n";
    write(STDOUT_FILENO, msg, strlen(msg));
    for (pid_t pid : g_child_pids) if (pid > 0) kill(pid, SIGTERM);
}

bool file_exists(const std::string& filename) {
    struct stat buffer;
    return (stat(filename.c_str(), &buffer) == 0);
}

std::vector<std::string> load_wordlist(const std::string& filename) {
    std::vector<std::string> wordlist;
    std::string path = file_exists(filename) ? filename : "./Wordlist/" + filename;
    std::ifstream file(path);
    if (!file) throw std::runtime_error("Wordlist not found: " + path);
    std::string word;
    while (std::getline(file, word)) {
        size_t last = word.find_last_not_of(" \t\r\n");
        if (last != std::string::npos) wordlist.push_back(word.substr(0, last + 1));
    }
    if (wordlist.size() != 2048) throw std::runtime_error("Wordlist must be 2048 words");
    return wordlist;
}

// [UPGRADE] Portable timegm (UTC) replacement if not available
time_t timegm_portable(struct tm *tm) {
    #ifdef _WIN32
        return _mkgmtime(tm);
    #else
        return timegm(tm);
    #endif
}

std::vector<uint8_t> sha256(const std::vector<uint8_t>& data) {
    std::vector<uint8_t> hash(SHA256_DIGEST_LENGTH);
    SHA256_CTX ctx;
    SHA256_Init(&ctx);
    SHA256_Update(&ctx, data.data(), data.size());
    SHA256_Final(hash.data(), &ctx);
    return hash;
}

// --- OPENSSL CONTEXT WRAPPER (OPTIMIZATION) ---
// Kelas ini menyimpan objek OpenSSL agar tidak dialokasi ulang setiap loop
struct CryptoContext {
    EC_GROUP* group;
    BN_CTX* ctx;
    BIGNUM* order; // Curve order (n)
    BIGNUM* bn_temp;
    BIGNUM* bn_temp2;
    EC_POINT* point_temp;

    CryptoContext() {
        group = EC_GROUP_new_by_curve_name(NID_secp256k1);
        ctx = BN_CTX_new();
        order = BN_new();
        EC_GROUP_get_order(group, order, ctx);
        bn_temp = BN_new();
        bn_temp2 = BN_new();
        point_temp = EC_POINT_new(group);
    }

    ~CryptoContext() {
        EC_POINT_free(point_temp);
        BN_free(bn_temp); BN_free(bn_temp2);
        BN_free(order);
        BN_CTX_free(ctx);
        EC_GROUP_free(group);
    }
};

struct HDKey {
    std::vector<uint8_t> key;        // 32 bytes private key
    std::vector<uint8_t> chain_code; // 32 bytes chain code
    bool valid;                      // BIP32 validation flag
};

// --- CORE LOGIC ---

// [UPGRADE] Generator Mnemonic dengan Buffer 24 Bytes (192-bit)
std::string generate_mnemonic_bip39(uint32_t seed_value, const std::vector<std::string>& wordlist) {
    std::mt19937 engine(seed_value);
    std::vector<uint8_t> entropy(ENTROPY_BYTES); 
    
    // Generate entropy per 4 byte block
    for (size_t i = 0; i < ENTROPY_BYTES; i += 4) {
        uint32_t random_block = engine();
        // Little Endian extraction explicit
        entropy[i]     = static_cast<uint8_t>(random_block & 0xFF);
        entropy[i + 1] = static_cast<uint8_t>((random_block >> 8) & 0xFF);
        entropy[i + 2] = static_cast<uint8_t>((random_block >> 16) & 0xFF);
        entropy[i + 3] = static_cast<uint8_t>((random_block >> 24) & 0xFF);
    }

    // Checksum: SHA256 first byte
    std::vector<uint8_t> hash = sha256(entropy);
    uint8_t checksum_byte = hash[0];

    // Combine for bit processing
    // Total bits = 192 + (192/32) = 198 bits? No.
    // BIP39: CS = ENTROPY / 32 bits. 192 / 32 = 6 bits checksum.
    
    // Bit manipulation to get indices
    std::string mnemonic;
    mnemonic.reserve(150);

    // We process bits manually from the byte array
    // Total 192 bits entropy. Plus 6 bits checksum.
    // Logic umum untuk arbitrary length:
    
    // Copy entropy to a larger buffer to handle checksum bits easily
    std::vector<uint8_t> combined = entropy;
    combined.push_back(checksum_byte); 

    int total_bits = ENTROPY_BYTES * 8;
    int checksum_len = total_bits / 32;
    int total_len_bits = total_bits + checksum_len;
    int num_words = total_len_bits / 11; // Should be 18 for 192 bits

    for (int i = 0; i < num_words; ++i) {
        int word_idx = 0;
        for (int b = 0; b < 11; ++b) {
            int pos = i * 11 + b;
            int byte_pos = pos / 8;
            int bit_rem = 7 - (pos % 8);
            
            uint8_t val = (combined[byte_pos] >> bit_rem) & 1;
            word_idx |= (val << (10 - b));
        }
        if (i > 0) mnemonic += " ";
        mnemonic += wordlist[word_idx];
    }
    return mnemonic;
}

std::vector<uint8_t> mnemonic_to_seed(const std::string& mnemonic) {
    std::string salt = "mnemonic"; 
    std::vector<uint8_t> seed(64);
    PKCS5_PBKDF2_HMAC(mnemonic.c_str(), mnemonic.length(),
                      (const unsigned char*)salt.c_str(), salt.length(),
                      2048, EVP_sha512(), 64, seed.data());
    return seed;
}

// Helper: Serialize 32-bit int to Big Endian
void uint32_to_be(uint32_t i, uint8_t* out) {
    out[0] = (i >> 24) & 0xFF;
    out[1] = (i >> 16) & 0xFF;
    out[2] = (i >> 8) & 0xFF;
    out[3] = i & 0xFF;
}

// Master Key Generation
HDKey hd_master_key_from_seed(const std::vector<uint8_t>& seed) {
    unsigned char hash[64];
    HMAC(EVP_sha512(), "Bitcoin seed", 12, seed.data(), seed.size(), hash, NULL);
    HDKey hk;
    hk.key.assign(hash, hash + 32);
    hk.chain_code.assign(hash + 32, hash + 64);
    hk.valid = true;
    return hk;
}

// [UPGRADE] Optimized CKDpriv with Reused Context & BIP32 Validation
HDKey CKDpriv_fast(const HDKey& parent, uint32_t index, CryptoContext& cc) {
    if (!parent.valid) return { {}, {}, false };

    uint8_t data[37]; // 33 byte pubkey/0x00 + 4 byte index
    bool hardened = (index & 0x80000000);

    if (hardened) {
        data[0] = 0x00;
        memcpy(data + 1, parent.key.data(), 32);
    } else {
        // Calculate PubKey: pub = priv * G
        BN_bin2bn(parent.key.data(), 32, cc.bn_temp); // priv
        EC_POINT_mul(cc.group, cc.point_temp, cc.bn_temp, NULL, NULL, cc.ctx); // G * priv
        // Serialize compressed
        EC_POINT_point2oct(cc.group, cc.point_temp, POINT_CONVERSION_COMPRESSED, data, 33, cc.ctx);
    }
    
    uint32_to_be(index, data + 33);

    unsigned char I[64];
    HMAC(EVP_sha512(), parent.chain_code.data(), 32, data, 37, I, NULL);

    // [UPGRADE] BIP32 Validation: Il < n
    BIGNUM* Il = BN_bin2bn(I, 32, cc.bn_temp);
    if (BN_cmp(Il, cc.order) >= 0) {
        return { {}, {}, false }; // Invalid key
    }

    // k_child = (Il + k_par) mod n
    BIGNUM* kpar = BN_bin2bn(parent.key.data(), 32, cc.bn_temp2);
    BIGNUM* kchild = BN_new(); // Result
    
    BN_mod_add(kchild, Il, kpar, cc.order, cc.ctx);

    // [UPGRADE] BIP32 Validation: check if 0
    if (BN_is_zero(kchild)) {
        BN_free(kchild);
        return { {}, {}, false };
    }

    std::vector<uint8_t> child_key(32);
    BN_bn2binpad(kchild, child_key.data(), 32);
    
    HDKey res;
    res.key = child_key;
    res.chain_code.assign(I + 32, I + 64);
    res.valid = true;

    BN_free(kchild);
    return res;
}

std::string to_hex(const std::vector<uint8_t>& data) {
    static const char hex_chars[] = "0123456789abcdef";
    std::string res(data.size() * 2, ' ');
    for (size_t i = 0; i < data.size(); ++i) {
        res[i*2] = hex_chars[(data[i] >> 4) & 0xF];
        res[i*2+1] = hex_chars[data[i] & 0xF];
    }
    return res;
}

// --- WORKER PROCESS ---

void worker_process(int id, uint64_t start, uint64_t end, int step, 
                    const std::vector<std::string>& wordlist, int num_derivations) {
    
    // [UPGRADE] Init OpenSSL Global Objects once per worker
    CryptoContext cc; 
    
    std::string log_file = OUTPUT_PREFIX + std::to_string(id) + ".log";
    std::string cmd = BRAINFLAYER_BIN + " -v -b " + BLOOM_FILTER + " -t priv -x > " + log_file;
    
    FILE* pipe = popen(cmd.c_str(), "w");
    if (!pipe) {
        std::cerr << "[Worker " << id << "] Pipe error\n";
        return;
    }

    // Buffer output untuk performa pipe
    char buffer[4096];
    setvbuf(pipe, buffer, _IOFBF, sizeof(buffer));

    std::streampos last_pos = 0;
    uint64_t processed = 0;

    // Hardened constants
    const uint32_t H = 0x80000000;

    // [UPGRADE] Loop timestamp 64-bit
    for (uint64_t ts = start; ts <= end && !g_stop_flag; ts += step) {
        // 1. Mnemonic (192-bit / 18 words)
        std::string m = generate_mnemonic_bip39((uint32_t)ts, wordlist);
        
        // 2. Seed
        std::vector<uint8_t> seed = mnemonic_to_seed(m);
        HDKey master = hd_master_key_from_seed(seed);

        // [UPGRADE] Cache Base Path: m/44'/0'/0'/0
        // Daripada derive dari m setiap kali, kita hitung parent kunci untuk address
        HDKey k44 = CKDpriv_fast(master, 44 | H, cc);
        HDKey kCoin = CKDpriv_fast(k44, 0 | H, cc);
        HDKey kAcc = CKDpriv_fast(kCoin, 0 | H, cc);
        HDKey kChange = CKDpriv_fast(kAcc, 0, cc); // 0 = External/Receive

        if (!kChange.valid) continue;

        // 3. Derive Children (0, 1, 2...) from cached parent
        for (int i = 0; i < num_derivations; ++i) {
            HDKey child = CKDpriv_fast(kChange, (uint32_t)i, cc);
            if (child.valid) {
                // Fast hex conversion directly to pipe
                std::string hex = to_hex(child.key);
                fprintf(pipe, "%s\n", hex.c_str());
            }
        }

        processed++;

        // 4. Lightweight Monitoring
        if (processed % REPORT_INTERVAL == 0) {
            // Check file output
            struct stat st;
            if (stat(log_file.c_str(), &st) == 0 && st.st_size > last_pos) {
                std::ifstream log(log_file);
                log.seekg(last_pos);
                std::string line;
                while(std::getline(log, line)) {
                    if (line.length() > 20) {
                        std::cout << "\n\033[1;32m[!] HIT WORKER " << id << ": " << line << "\033[0m" << std::endl;
                    }
                }
                last_pos = st.st_size;
            }
            // Update UI
            // Menggunakan write low-level untuk thread-safety di console
            // printf("[W%d] %lu \r", id, ts); 
        }
    }

    pclose(pipe);
}

// --- MAIN ---

int main() {
    signal(SIGINT, signal_handler);
    
    // Checks
    if (!file_exists(BRAINFLAYER_BIN) || !file_exists(BLOOM_FILTER)) {
        std::cerr << "Missing binaries/files.\n";
        return 1;
    }

    auto wordlist = load_wordlist(WORDLIST_FILE);
    
    std::string start_str, end_str;
    std::cout << "Start Date (YYYY-MM-DD): "; std::cin >> start_str;
    std::cout << "End Date   (YYYY-MM-DD): "; std::cin >> end_str;

    // [UPGRADE] UTC Parsing
    struct tm tm_start{};
    struct tm tm_end{};
    strptime((start_str + " 00:00:00").c_str(), "%Y-%m-%d %H:%M:%S", &tm_start);
    strptime((end_str + " 23:59:59").c_str(), "%Y-%m-%d %H:%M:%S", &tm_end);
    
    // Gunakan timegm (UTC) alih-alih mktime (Local)
    uint64_t start_ts = (uint64_t)timegm_portable(&tm_start);
    uint64_t end_ts = (uint64_t)timegm_portable(&tm_end);

    int num_procs = std::thread::hardware_concurrency();
    std::cout << "Threads: "; std::cin >> num_procs;
    
    std::cout << "Scan Range (UTC): " << start_ts << " -> " << end_ts << "\n";
    std::cout << "Entropy: 192-bit (24 bytes)\n";
    std::cout << "Path: m/44'/0'/0'/0/x (Legacy)\n";

    g_child_pids.resize(num_procs);
    
    for (int i = 0; i < num_procs; ++i) {
        pid_t pid = fork();
        if (pid == 0) {
            worker_process(i, start_ts + i, end_ts, num_procs, wordlist, 5);
            exit(0);
        } else {
            g_child_pids[i] = pid;
        }
    }

    int status;
    while(wait(&status) > 0);
    
    std::cout << "\nDone.\n";
    return 0;
}
