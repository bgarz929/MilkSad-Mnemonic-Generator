/**
 * Milk Sad Scanner - Legacy Edition (BIP44)
 * Gabungan: Multiprocessing (Fork) + BIP32 Math + Brainflayer Scanning
 * Target: Legacy Address (1...) via path m/44'/0'/0'/0/i
 */

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
#include <thread>
#include <atomic>
#include <random>
#include <cstring>

// --- KONFIGURASI ---
const std::string WORDLIST_FILE = "english.txt"; // Pastikan file ini ada
const std::string OUTPUT_PREFIX = "found_legacy_keys_";
const uint64_t REPORT_INTERVAL = 10000; // Cek file log setiap N keys

// Path ke Brainflayer dan Bloom Filter
const std::string BRAINFLAYER_BIN = "./brainflayer/brainflayer";
const std::string BLOOM_FILTER = "./040823BF.blf";

// --- GLOBAL VARIABLES ---
std::vector<pid_t> g_child_pids;
std::atomic<bool> g_stop_flag(false);

// --- HELPER FUNCTIONS ---

// Signal handler untuk membersihkan proses anak jika di-interrupt
void signal_handler(int signum) {
    if (g_stop_flag) return;
    g_stop_flag = true;
    const char* msg = "\n[!] Interrupt received. Terminating workers...\n";
    write(STDOUT_FILENO, msg, strlen(msg));
    
    for (pid_t pid : g_child_pids) {
        if (pid > 0) kill(pid, SIGTERM);
    }
}

bool file_exists(const std::string& filename) {
    struct stat buffer;
    return (stat(filename.c_str(), &buffer) == 0);
}

std::vector<std::string> load_wordlist(const std::string& filename) {
    std::vector<std::string> wordlist;
    std::string path = file_exists(filename) ? filename : "./Wordlist/" + filename;
    
    std::ifstream file(path);
    if (!file) {
        throw std::runtime_error("Could not open wordlist: " + path);
    }
    std::string word;
    while (std::getline(file, word)) {
        size_t last = word.find_last_not_of(" \t\r\n");
        if (last != std::string::npos) word = word.substr(0, last + 1);
        if (!word.empty()) wordlist.push_back(word);
    }
    if (wordlist.size() != 2048) throw std::runtime_error("Wordlist invalid size");
    return wordlist;
}

// --- CRYPTO FUNCTIONS (BIP39 & SHA) ---

std::vector<uint8_t> sha256(const std::vector<uint8_t>& data) {
    std::vector<uint8_t> hash(SHA256_DIGEST_LENGTH);
    SHA256_CTX sha256_ctx;
    SHA256_Init(&sha256_ctx);
    SHA256_Update(&sha256_ctx, data.data(), data.size());
    SHA256_Final(hash.data(), &sha256_ctx);
    return hash;
}

// Milk Sad Generator (Endian Safe version)
std::string generate_mnemonic_bip39(uint32_t seed_value, const std::vector<std::string>& wordlist) {
    std::mt19937 engine(seed_value);
    const int ENTROPY_BYTES = 24; // 192 bits = 18 words (Standard Milk Sad) or 32 bytes for 24 words
    // Note: Original Milk Sad usually implies specific RNG issues. 
    // We stick to the explicitly requested logic: 32-bit seed -> RNG -> Bytes.
    
    // Kita gunakan 32 byte entropy (256 bits) untuk 24 kata agar aman, 
    // atau 16-24 byte sesuai kebutuhan. Default library biasanya 24 kata (32 bytes).
    std::vector<uint8_t> entropy(32); 
    
    for (size_t i = 0; i < 32; i += 4) {
        uint32_t random_block = engine();
        entropy[i]     = static_cast<uint8_t>(random_block & 0xFF);
        entropy[i + 1] = static_cast<uint8_t>((random_block >> 8) & 0xFF);
        entropy[i + 2] = static_cast<uint8_t>((random_block >> 16) & 0xFF);
        entropy[i + 3] = static_cast<uint8_t>((random_block >> 24) & 0xFF);
    }

    std::vector<uint8_t> hash = sha256(entropy);
    std::vector<uint8_t> combined = entropy;
    combined.push_back(hash[0]); // Checksum byte

    std::string mnemonic;
    // Logic konversi bit ke kata (standard BIP39)
    // 32 bytes (256 bits) + 8 bit checksum = 264 bits. 264 / 11 = 24 words.
    for (int i = 0; i < 24; ++i) {
        int idx = 0;
        for (int b = 0; b < 11; ++b) {
            int total_bit = i * 11 + b;
            int byte_pos = total_bit / 8;
            int bit_pos = 7 - (total_bit % 8);
            if ((combined[byte_pos] >> bit_pos) & 1) idx |= (1 << (10 - b));
        }
        if (i > 0) mnemonic += " ";
        mnemonic += wordlist[idx];
    }
    return mnemonic;
}

std::vector<uint8_t> mnemonic_to_seed(const std::string& mnemonic) {
    std::string salt = "mnemonic"; // Standard salt without passphrase
    std::vector<uint8_t> seed(64);
    PKCS5_PBKDF2_HMAC(mnemonic.c_str(), mnemonic.length(),
                      (const unsigned char*)salt.c_str(), salt.length(),
                      2048, EVP_sha512(), 64, seed.data());
    return seed;
}

// --- BIP32 LOGIC (MATEMATIKA ELLIPTIC CURVE) ---

struct HDKey {
    std::vector<uint8_t> key;        // 32 bytes private key
    std::vector<uint8_t> chain_code; // 32 bytes chain code
};

std::vector<uint8_t> uint32_to_be(uint32_t i) {
    return {static_cast<uint8_t>(i >> 24), static_cast<uint8_t>(i >> 16),
            static_cast<uint8_t>(i >> 8), static_cast<uint8_t>(i)};
}

// Master Key Generation
HDKey hd_master_key_from_seed(const std::vector<uint8_t>& seed) {
    const char* key = "Bitcoin seed";
    unsigned char hash[64];
    HMAC(EVP_sha512(), key, strlen(key), seed.data(), seed.size(), hash, NULL);
    HDKey hk;
    hk.key.assign(hash, hash + 32);
    hk.chain_code.assign(hash + 32, hash + 64);
    return hk;
}

std::vector<uint8_t> get_pub_key(const std::vector<uint8_t>& priv_key) {
    EC_KEY* ec = EC_KEY_new_by_curve_name(NID_secp256k1);
    BIGNUM* priv = BN_bin2bn(priv_key.data(), 32, NULL);
    EC_KEY_set_private_key(ec, priv);
    const EC_GROUP* group = EC_KEY_get0_group(ec);
    EC_POINT* pub = EC_POINT_new(group);
    EC_POINT_mul(group, pub, priv, NULL, NULL, NULL);
    
    std::vector<uint8_t> pub_bytes(33);
    EC_POINT_point2oct(group, pub, POINT_CONVERSION_COMPRESSED, pub_bytes.data(), 33, NULL);
    
    EC_POINT_free(pub); BN_free(priv); EC_KEY_free(ec);
    return pub_bytes;
}

// Child Key Derivation (Private -> Private)
HDKey CKDpriv(const HDKey& parent, uint32_t index) {
    std::vector<uint8_t> data;
    bool hardened = (index & 0x80000000);

    if (hardened) {
        data.push_back(0);
        data.insert(data.end(), parent.key.begin(), parent.key.end());
    } else {
        std::vector<uint8_t> pub = get_pub_key(parent.key);
        data.insert(data.end(), pub.begin(), pub.end());
    }
    std::vector<uint8_t> idx_bytes = uint32_to_be(index);
    data.insert(data.end(), idx_bytes.begin(), idx_bytes.end());

    unsigned char hash[64];
    HMAC(EVP_sha512(), parent.chain_code.data(), parent.chain_code.size(),
         data.data(), data.size(), hash, NULL);

    std::vector<uint8_t> Il(hash, hash + 32);
    std::vector<uint8_t> Ir(hash + 32, hash + 64);

    BIGNUM* il_bn = BN_bin2bn(Il.data(), 32, NULL);
    BIGNUM* kpar_bn = BN_bin2bn(parent.key.data(), 32, NULL);
    BIGNUM* order = BN_new();
    BIGNUM* child_bn = BN_new();
    BN_CTX* ctx = BN_CTX_new();
    
    BN_hex2bn(&order, "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141");
    BN_mod_add(child_bn, il_bn, kpar_bn, order, ctx);

    std::vector<uint8_t> child_key(32);
    BN_bn2binpad(child_bn, child_key.data(), 32);

    BN_free(il_bn); BN_free(kpar_bn); BN_free(order); BN_free(child_bn); BN_CTX_free(ctx);
    return {child_key, Ir};
}

HDKey derive_path(HDKey k, const std::string& path) {
    std::stringstream ss(path);
    std::string segment;
    std::getline(ss, segment, '/'); // skip m
    while (std::getline(ss, segment, '/')) {
        bool hardened = false;
        if (segment.back() == '\'') {
            hardened = true;
            segment.pop_back();
        }
        uint32_t idx = std::stoul(segment);
        if (hardened) idx |= 0x80000000;
        k = CKDpriv(k, idx);
    }
    return k;
}

std::string to_hex(const std::vector<uint8_t>& data) {
    std::stringstream ss;
    ss << std::hex << std::setfill('0');
    for (int c : data) ss << std::setw(2) << c;
    return ss.str();
}

// --- WORKER PROCESS ---

void worker_process(int id, uint32_t start, uint32_t end, int step, 
                    const std::vector<std::string>& wordlist, int num_derivations) {
    
    // File log sementara untuk output brainflayer proses ini
    std::string log_file = OUTPUT_PREFIX + std::to_string(id) + ".log";
    
    // Command: Input Hex Private Key -> Brainflayer -> Log File
    // -t priv: Input type private key
    // -x: Input format HEX
    // -b: Bloom filter file
    std::string cmd = BRAINFLAYER_BIN + " -v -b " + BLOOM_FILTER + " -t priv -x > " + log_file;
    
    FILE* pipe = popen(cmd.c_str(), "w");
    if (!pipe) {
        std::cerr << "[Worker " << id << "] Error opening brainflayer pipe!\n";
        return;
    }

    // BIP44 Legacy Path: m / 44' / 0' / 0' / 0 / i
    std::string base_path = "m/44'/0'/0'/0/";
    
    std::streampos last_pos = 0;
    uint64_t processed = 0;

    for (uint32_t ts = start; ts <= end && !g_stop_flag; ts += step) {
        try {
            // 1. Generate Mnemonic
            std::string m = generate_mnemonic_bip39(ts, wordlist);
            
            // 2. Derive Master
            std::vector<uint8_t> seed = mnemonic_to_seed(m);
            HDKey master = hd_master_key_from_seed(seed);
            
            // 3. Derive Children (Legacy Address)
            for (int i = 0; i < num_derivations; ++i) {
                // Path lengkap: m/44'/0'/0'/0/i
                std::string full_path = base_path + std::to_string(i);
                HDKey child = derive_path(master, full_path);
                
                // Kirim Hex Private Key ke Brainflayer
                fprintf(pipe, "%s\n", to_hex(child.key).c_str());
            }

            processed++;

            // 4. Monitoring Output (Incremental Read)
            if (processed % REPORT_INTERVAL == 0) {
                std::ifstream log(log_file);
                if (log.is_open()) {
                    log.seekg(0, std::ios::end);
                    std::streampos current_pos = log.tellg();
                    if (current_pos > last_pos) {
                        log.clear();
                        log.seekg(last_pos);
                        std::string line;
                        while(std::getline(log, line)) {
                            if (line.find("Found") != std::string::npos || line.length() > 20) {
                                std::cout << "\n\033[1;32m[!] WORKER " << id << " FOUND SOMETHING!\033[0m" << std::endl;
                                std::cout << "Data: " << line << std::endl;
                                std::cout << "Mnemonic (Check this): " << m << std::endl;
                            }
                        }
                        last_pos = current_pos;
                    }
                }
                std::cout << "[Worker " << id << "] TS: " << ts << " | Processed: " << processed << "\r" << std::flush;
            }

        } catch (std::exception& e) {
            continue; 
        }
    }

    pclose(pipe);
    std::cout << "[Worker " << id << "] Finished." << std::endl;
}

// --- MAIN ---

int main() {
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    // Pre-flight checks
    if (!file_exists(BRAINFLAYER_BIN)) {
        std::cerr << "Error: " << BRAINFLAYER_BIN << " not found!\n";
        return 1;
    }
    if (!file_exists(BLOOM_FILTER)) {
        std::cerr << "Error: " << BLOOM_FILTER << " not found!\n";
        return 1;
    }

    std::cout << "=== Milk Sad Legacy Scanner (BIP44 / 1... Addresses) ===\n";
    std::cout << "Integrates BIP32 Derivation + Brainflayer Scanning\n";

    auto wordlist = load_wordlist(WORDLIST_FILE);
    
    // Input Range
    std::string start_str, end_str;
    std::cout << "Start Date (YYYY-MM-DD): "; std::cin >> start_str;
    std::cout << "End Date   (YYYY-MM-DD): "; std::cin >> end_str;

    std::tm tm_start = {}, tm_end = {};
    strptime((start_str + " 00:00:00").c_str(), "%Y-%m-%d %H:%M:%S", &tm_start);
    strptime((end_str + " 23:59:59").c_str(), "%Y-%m-%d %H:%M:%S", &tm_end);
    
    uint32_t start_ts = mktime(&tm_start);
    uint32_t end_ts = mktime(&tm_end);

    // Input Config
    int num_procs = std::thread::hardware_concurrency();
    std::cout << "Processes [" << num_procs << "]: ";
    if (std::cin.peek() == '\n') std::cin.ignore();
    else std::cin >> num_procs;

    int num_addr = 5;
    std::cout << "Addresses per Mnemonic (Derivation Limit) [5]: ";
    std::cin >> num_addr;

    std::cout << "\n[*] Starting Scan from " << start_ts << " to " << end_ts << "\n";
    std::cout << "[*] Path: m/44'/0'/0'/0/0..." << (num_addr-1) << "\n";

    // Forking Logic
    g_child_pids.resize(num_procs);
    for (int i = 0; i < num_procs; ++i) {
        pid_t pid = fork();
        if (pid == 0) { // Child
            // Offset logic: Child i mulai dari start + i, loncat sebanyak num_procs
            worker_process(i, start_ts + i, end_ts, num_procs, wordlist, num_addr);
            exit(0);
        } else if (pid > 0) { // Parent
            g_child_pids[i] = pid;
        } else {
            std::cerr << "Fork failed!\n";
        }
    }

    // Wait for children
    int status;
    for (pid_t pid : g_child_pids) {
        if (pid > 0) waitpid(pid, &status, 0);
    }

    std::cout << "\nScan Complete.\n";
    return 0;
}
