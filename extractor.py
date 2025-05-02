# Standard library
import json, sqlite3, argparse
from hashlib import sha1, pbkdf2_hmac
from binascii import unhexlify
from base64 import b64decode
from pathlib import Path
# Third-party
from Crypto.Cipher import DES3, AES
from Crypto.Util.Padding import unpad
from pyasn1.codec.der import decoder
from tabulate import tabulate
from tqdm import tqdm


# ========== Hàm xử lý lỗi ==========
def safe_open(path, mode='r', encoding='utf-8'):
    try:
        return open(path, mode, encoding=encoding)
    except Exception as e:
        print(f"Failed to open file {path}: {e}")
        return None


# ========== Hàm giải mã PBE (Password-Based Encryption) ==========
def decrypt_pbe(decoded_item, primary_password: bytes, global_salt: bytes):
    try:
        pbe_algo = str(decoded_item[0][0][0])
        if pbe_algo == "1.2.840.113549.1.5.13":
            entry_salt = decoded_item[0][0][1][0][1][0].asOctets()
            iteration_count = int(decoded_item[0][0][1][0][1][1])
            key_length = int(decoded_item[0][0][1][0][1][2])
            iv = b"\x04\x0e" + decoded_item[0][0][1][1][1].asOctets()
            cipher_text = decoded_item[0][1].asOctets()

            k = sha1(global_salt + primary_password).digest()
            key = pbkdf2_hmac("sha256", k, entry_salt, iteration_count, dklen=key_length)
            decrypted = AES.new(key, AES.MODE_CBC, iv).decrypt(cipher_text)
            return decrypted, pbe_algo
    except Exception as e:
        print(f"Error decrypting PBE: {e}")
    return None, None


# ========== Giải mã thông tin đăng nhập ==========
def decode_login_data(data: str):
    try:
        asn1_data = decoder.decode(b64decode(data))
        key_id = asn1_data[0][0].asOctets()
        iv = asn1_data[0][1][1].asOctets()
        ciphertext = asn1_data[0][2].asOctets()
        return key_id, iv, ciphertext
    except Exception as e:
        print(f"Failed to decode login data: {e}")
        return None, None, None


# ========== Đọc file logins.json ==========
def get_login_data(profile_dir: Path):
    logins = []
    json_file = profile_dir / "logins.json"

    if not json_file.exists():
        print("File logins.json not found.")
        return logins

    with safe_open(json_file, 'r') as f:
        if not f:
            return logins
        try:
            json_logins = json.load(f)
            for entry in json_logins.get("logins", []):
                username_data = decode_login_data(entry["encryptedUsername"])
                password_data = decode_login_data(entry["encryptedPassword"])
                if None not in (*username_data, *password_data):
                    logins.append((username_data, password_data, entry["hostname"]))
        except json.JSONDecodeError:
            print("Invalid JSON format in logins.json.")
    return logins


# ========== Đọc khóa mã hóa ==========
CKA_ID = unhexlify("f8000000000000000000000000000001")

# ========== Lấy khóa giải mã ==========
def extract_master_key(profile_dir: Path, primary_password: str):
    db_path = profile_dir / "key4.db"
    if not db_path.exists():
        print("File key4.db not found.")
        return None

    try:
        with sqlite3.connect(db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT item1, item2 FROM metadata WHERE id = 'password';")
            row = cursor.fetchone()
            if not row:
                print ("This profile may not be encrypted.")
                return None

            global_salt, item2 = row
            decoded_item2 = decoder.decode(item2)
            check_text, _ = decrypt_pbe(decoded_item2, primary_password.encode(), global_salt)

            if check_text != b"password-check\x02\x02":
                return None

            cursor.execute("SELECT a11, a102 FROM nssPrivate;")
            for a11, a102 in cursor.fetchall():
                if a102 == CKA_ID:
                    decoded_a11 = decoder.decode(a11)
                    clear_text, _ = decrypt_pbe(decoded_a11, primary_password.encode(), global_salt)
                    return clear_text[:24]  # DES3 key size
    except Exception as e:
        print(f"Failed to extract master key: {e}")
    return None


# ========== Giải mã tất cả tài khoản ==========
def decrypt_saved_logins(profile_dir: Path, primary_password: str):
    key = extract_master_key(profile_dir, primary_password)
    if not key:
        return False

    logins = get_login_data(profile_dir)
    if not logins:
        return False

    table_data = []
    for user_entry, pass_entry, hostname in logins:
        if user_entry[0] != CKA_ID:
            continue
        try:
            username = unpad(DES3.new(key, DES3.MODE_CBC, user_entry[1]).decrypt(user_entry[2]), 8).decode("utf-8")
            password = unpad(DES3.new(key, DES3.MODE_CBC, pass_entry[1]).decrypt(pass_entry[2]), 8).decode("utf-8")
            table_data.append([hostname, username, password])
        except Exception as e:
            print(f"Decryption failed for {hostname}: {e}")

    if table_data:
        tqdm.write(tabulate(table_data, headers=["Hostname", "Username", "Password"], tablefmt="grid"))
        return True

    return False


# ========== Brute-force mật khẩu chính ==========
def brute_force_primary_password(profile_dir: Path, wordlist_path: Path):
    try:
        passwords = wordlist_path.read_text(encoding="utf-8").splitlines()
    except Exception as e:
        print(f"Failed to load wordlist: {e}")
        return False

    for password in tqdm(passwords, desc="Brute-force", ncols=77, leave=False, bar_format="{l_bar}{bar}   |   [{n_fmt}/{total_fmt}] [{elapsed} - {remaining}]"):
        if decrypt_saved_logins(profile_dir, password):
            tqdm.write(f"Success! Primary password is: {password}")
            return True

    print("Failed to find valid primary password.")
    return False


# ========== Entry Point ==========
def main():
    parser = argparse.ArgumentParser(description="Firefox Passwords Extractor")
    parser.add_argument("-d", "--dir", required=True, help="Path to Firefox profile directory")
    parser.add_argument("-p", "--password", help="Primary password for decryption")
    parser.add_argument("-f", "--fuzzing", help="Path to password wordlist for brute-force")

    args = parser.parse_args()
    profile_dir = Path(args.dir)

    if not profile_dir.exists() or not profile_dir.is_dir():
        print("Provided profile path is invalid.")
        return

    if args.password:
        if not decrypt_saved_logins(profile_dir, args.password):
            print("Decryption failed! Wrong primary password?")
    elif args.fuzzing:
        try:
            wordlist_path = Path(args.fuzzing)
            brute_force_primary_password(profile_dir, wordlist_path)
        except KeyboardInterrupt:
            print("Brute-force interrupted.")
    else:
        if not decrypt_saved_logins(profile_dir, ""):
            print("Decryption failed. This profile seems to require a primary password.")
            print ("Use -p to provide one or -f to brute-force with a wordlist.")


# ========== Main Program ==========
if __name__ == "__main__":
    main()