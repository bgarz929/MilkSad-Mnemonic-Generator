# create_table.py
with open('hash160.txt', 'r') as f:
    lines = f.readlines()

with open('tablefile.tab', 'wb') as out:
    for line in lines:
        hex_str = line.strip()
        if not hex_str:
            continue  # lewati baris kosong
        # Pastikan panjangnya 40 karakter hex
        if len(hex_str) != 40:
            print(f"Peringatan: barus dengan panjang {len(hex_str)}: {hex_str[:30]}...")
        try:
            out.write(bytes.fromhex(hex_str))
        except ValueError as e:
            print(f"Error: {e} pada baris: {hex_str}")
