import os

prefix = "brainflayer_found"
start = 0
end = 21

out_file = "brainflayer_privkeys.txt"

seen = set()

with open(out_file, "w") as out:
    for i in range(start, end + 1):
        fname = f"{prefix}_{i}.txt"

        if not os.path.exists(fname):
            print(f"[!] Skip missing: {fname}")
            continue

        print(f"[+] Reading: {fname}")

        with open(fname, "r", errors="ignore") as f:
            for line in f:
                line = line.strip()

                if "(hex)priv:" in line:
                    priv = line.split("(hex)priv:")[-1]

                    if priv not in seen:
                        seen.add(priv)
                        out.write(priv + "\n")

print(f"\n✅ Done. Total unique keys: {len(seen)}")
