from Crypto.Cipher import DES3, AES
from Crypto.Util.Padding import unpad
from hashlib import sha1, pbkdf2_hmac
from pyasn1.codec.der import decoder
from binascii import unhexlify
from base64 import b64decode
from pathlib import Path
from optparse import OptionParser
from tabulate import tabulate
import sys, json, sqlite3

# ======== Hằng số: Định danh khóa giải mã (CKA_ID) ========
CKA_ID = unhexlify('f8000000000000000000000000000001')


# ======== Hàm giải mã dữ liệu được mã hóa bằng PBE (Password-Based Encryption) ========
def decryptPBE(decodedItem, primaryPassword, globalSalt):
    pbeAlgo = str(decodedItem[0][0][0])  # Lấy định danh thuật toán

    # Giải mã dữ liệu dựa trên thuật toán AES + PBKDF2
    if pbeAlgo == '1.2.840.113549.1.5.13':
        entrySalt = decodedItem[0][0][1][0][1][0].asOctets()
        iterationCount = int(decodedItem[0][0][1][0][1][1])
        keyLength = int(decodedItem[0][0][1][0][1][2])
        iv = b'\x04\x0e' + decodedItem[0][0][1][1][1].asOctets()
        cipherT = decodedItem[0][1].asOctets()

        k = sha1(globalSalt + primaryPassword).digest()
        key = pbkdf2_hmac('sha256', k, entrySalt, iterationCount, dklen=keyLength)

        return AES.new(key, AES.MODE_CBC, iv).decrypt(cipherT), pbeAlgo

    return None, None


# ======== Hàm giải mã dữ liệu username/password theo định dạng ASN.1 ========
def decodeLoginData(data):
    asn1data = decoder.decode(b64decode(data))
    key_id = asn1data[0][0].asOctets()
    iv = asn1data[0][1][1].asOctets()
    ciphertext = asn1data[0][2].asOctets()
    return key_id, iv, ciphertext


# ======== Hàm lấy thông tin tài khoản từ file logins.json ========
def getLoginData():
    logins = []
    json_file = options.directory / 'logins.json'
    
    if json_file.exists():
        jsonLogins = json.loads(open(json_file, 'r').read())
        for row in jsonLogins.get('logins', []):
            logins.append((
                decodeLoginData(row['encryptedUsername']),
                decodeLoginData(row['encryptedPassword']),
                row['hostname']
            ))
    else:
        print('Missing logins.json file.')
    
    return logins


# ======== Hàm trích xuất khóa giải mã từ file key4.db ========
def getKey(primaryPassword, directory):
    if (directory / 'key4.db').exists():
        conn = sqlite3.connect(directory / 'key4.db')
        c = conn.cursor()

        # Lấy globalSalt và dữ liệu password-check
        c.execute("SELECT item1,item2 FROM metadata WHERE id = 'password';")
        row = c.fetchone()
        globalSalt, item2 = row
        decodedItem2 = decoder.decode(item2)
        clearText, algo = decryptPBE(decodedItem2, primaryPassword, globalSalt)

        # Kiểm tra xem mật khẩu chính có đúng không
        if clearText == b'password-check\x02\x02':
            # Lấy khóa giải mã từ bảng nssPrivate
            c.execute("SELECT a11,a102 FROM nssPrivate;")
            for row in c:
                if row[0] is not None:
                    break
            a11, a102 = row

            # So khớp với khóa định danh CKA_ID
            if a102 == CKA_ID:
                decoded_a11 = decoder.decode(a11)
                clearText, algo = decryptPBE(decoded_a11, primaryPassword, globalSalt)
                return clearText[:24], algo
            else:
                print('No matching decryption key found.')
        else:
            sys.exit()
        return None, None
    else:
        print('key4.db not found in this directory.')
        return None, None


# ======== Định nghĩa các tham số ========
parser = OptionParser()
parser.add_option("-d", "--dir", type="string", dest="directory",
                  help="Path to the Firefox profile directory", default='')
parser.add_option("-p", "--password", type="string", dest="primaryPassword",
                  help="Primary password (if set)", default='')
(options, args) = parser.parse_args()
options.directory = Path(options.directory)


# ======== Main ========
if __name__ == "__main__":
    key, algo = getKey(options.primaryPassword.encode(), options.directory)
    if key is None:
        sys.exit()

    logins = getLoginData()
    if not logins:
        print('No saved login entries found.')
        sys.exit()

    table_data = []
    for login in logins:
        assert login[0][0] == CKA_ID  # Đảm bảo đúng ID của khóa dùng để mã hóa
        username = unpad(DES3.new(key, DES3.MODE_CBC, login[0][1]).decrypt(login[0][2]), 8).decode('utf-8')
        password = unpad(DES3.new(key, DES3.MODE_CBC, login[1][1]).decrypt(login[1][2]), 8).decode('utf-8')
        table_data.append([login[2], username, password])

    # In kết quả ra bảng
    print(tabulate(table_data, headers=["Hostname", "Username", "Password"], tablefmt="grid"))