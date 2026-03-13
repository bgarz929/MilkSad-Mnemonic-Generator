import sys
import base58

def addresses_to_files(filein, fileout_txt, fileout_bin):
    with open(filein, 'r') as inf, \
         open(fileout_txt, 'w') as outf_txt, \
         open(fileout_bin, 'wb') as outf_bin:

        count = 0
        skip = 0
        for line in inf:
            addr = line.strip()
            if not addr:
                continue
            try:
                decoded = base58.b58decode_check(addr)
                if len(decoded) != 21:   # [version (1) + hash160 (20)]
                    skip += 1
                    print(f"skipped (wrong length {len(decoded)}): {addr}")
                    continue
                hash160 = decoded[1:]     # 20 byte hash
                outf_txt.write(hash160.hex() + '\n')
                outf_bin.write(hash160)
                count += 1
            except Exception as e:
                skip += 1
                print(f"skipped {addr}: {e}")

        print(f"processed: {count} addresses")
        print(f"skipped  : {skip} addresses")
        print(f"Ukuran file biner: {count * 20} byte (seharusnya)")

if __name__ == "__main__":
    if len(sys.argv) != 4:
        print("Usage: python3 addr2files.py addresses.txt hash160.txt tablefile.tab")
    else:
        addresses_to_files(sys.argv[1], sys.argv[2], sys.argv[3])
