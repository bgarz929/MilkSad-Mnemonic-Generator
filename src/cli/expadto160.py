import sys
import base58

def addresses_to_hash160(filein, fileout):
    """
    Membaca file berisi alamat Bitcoin (satu per baris) dan menulis hash160-nya
    ke file output dalam format teks heksadesimal (40 karakter per baris).
    """
    with open(filein, 'r') as inf, open(fileout, 'w') as outf:
        count = 0
        skip = 0
        for line in inf:
            address = line.strip()
            if not address:
                continue  # lewati baris kosong
            try:
                # Decode base58check (termasuk verifikasi checksum)
                decoded = base58.b58decode_check(address)
                # Hasil decode: [version (1 byte) + hash160 (20 byte)]
                if len(decoded) != 21:
                    # Panjang tidak sesuai standar (1 byte versi + 20 hash)
                    skip += 1
                    print(f"skipped address (unexpected length {len(decoded)}): {address}")
                    continue
                hash160_bytes = decoded[1:]  # ambil 20 byte hash160
                hash160_hex = hash160_bytes.hex()
                outf.write(hash160_hex + '\n')
                count += 1
            except Exception as e:
                skip += 1
                print(f"skipped address: {address} - error: {e}")

        print(f"processed : {count} addresses")
        print(f"skipped   : {skip} addresses")

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage:")
        print(f"\tpython3 {sys.argv[0]} addresses_in.txt hash160_out.txt")
    else:
        addresses_to_hash160(sys.argv[1], sys.argv[2])
