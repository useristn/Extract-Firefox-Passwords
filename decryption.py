import sys
import json
import sqlite3
from struct import unpack
from binascii import hexlify, unhexlify
import hmac
from Crypto.Cipher import DES3, AES
from Crypto.Util.number import long_to_bytes
from Crypto.Util.Padding import unpad
from hashlib import sha1, pbkdf2_hmac
from pyasn1.codec.der import decoder
from base64 import b64decode
from optparse import OptionParser
from pathlib import Path
from tabulate import tabulate

# ======== Các hàm đọc dữ liệu nhị phân ========
def getShortLE(d, a):
    return unpack('<H', d[a:a+2])[0]

def getLongBE(d, a):
    return unpack('>L', d[a:a+4])[0]

# ======== Bảng ánh xạ mã ASN.1 và OID ========
asn1Types = {
    0x30: 'SEQUENCE',
    4: 'OCTETSTRING',
    6: 'OBJECTIDENTIFIER',
    2: 'INTEGER',
    5: 'NULL'
}

oidValues = {
    b'2a864886f70d010c050103': '1.2.840.113549.1.12.5.1.3 pbeWithSha1AndTripleDES-CBC',
    b'2a864886f70d0307': '1.2.840.113549.3.7 des-ede3-cbc',
    b'2a864886f70d010101': '1.2.840.113549.1.1.1 pkcs-1',
    b'2a864886f70d01050d': '1.2.840.113549.1.5.13 pkcs5 pbes2',
    b'2a864886f70d01050c': '1.2.840.113549.1.5.12 pkcs5 PBKDF2',
    b'2a864886f70d0209': '1.2.840.113549.2.9 hmacWithSHA256',
    b'60864801650304012a': '2.16.840.1.101.3.4.1.42 aes256-CBC'
}

# ======== Hàm in cấu trúc ASN.1 để debug ========
def printASN1(d, l, rl):
    type = d[0]
    length = d[1]
    if length & 0x80 > 0:
        nByteLength = length & 0x7f
        length = d[2]
        skip = 1
    else:
        skip = 0

    print('  ' * rl, asn1Types[type], end=' ')
    if type == 0x30:
        print('{')
        seqLen = length
        readLen = 0
        while seqLen > 0:
            len2 = printASN1(d[2 + skip + readLen:], seqLen, rl + 1)
            seqLen -= len2
            readLen += len2
        print('  ' * rl, '}')
        return length + 2
    elif type == 6:
        oidVal = hexlify(d[2:2 + length])
        print(oidValues.get(oidVal, f'oid? {oidVal}'))
    elif type == 4 or type == 2:
        print(hexlify(d[2:2 + length]))
    elif type == 5:
        print(0)
    return length + 2

# ======== Giải mã khóa sử dụng thuật toán 3DES đặc trưng của Firefox ========
def decryptMoz3DES(globalSalt, masterPassword, entrySalt, encryptedData):
    hp = sha1(globalSalt + masterPassword).digest()
    pes = entrySalt + b'\x00' * (20 - len(entrySalt))
    chp = sha1(hp + entrySalt).digest()
    k1 = hmac.new(chp, pes + entrySalt, sha1).digest()
    tk = hmac.new(chp, pes, sha1).digest()
    k2 = hmac.new(chp, tk + entrySalt, sha1).digest()
    k = k1 + k2
    iv = k[-8:]
    key = k[:24]
    return DES3.new(key, DES3.MODE_CBC, iv).decrypt(encryptedData)

# ======== Giải mã thông tin đăng nhập từ định dạng ASN.1 trong logins.json ========
def decodeLoginData(data):
    asn1data = decoder.decode(b64decode(data))
    key_id = asn1data[0][0].asOctets()
    iv = asn1data[0][1][1].asOctets()
    ciphertext = asn1data[0][2].asOctets()
    return key_id, iv, ciphertext

# ======== Đọc dữ liệu từ file key3.db (định dạng BSD DB 1.85 cũ) ========
def readBsddb(name):
    f = open(name, 'rb')
    header = f.read(4 * 15)
    magic = getLongBE(header, 0)
    if magic != 0x61561:
        print('bad magic number')
        sys.exit()
    version = getLongBE(header, 4)
    if version != 2:
        print('bad version, !=2 (1.85)')
        sys.exit()
    pagesize = getLongBE(header, 12)
    nkeys = getLongBE(header, 0x38)
    readkeys = 0
    page = 1
    db1 = []
    while readkeys < nkeys:
        f.seek(pagesize * page)
        offsets = f.read((nkeys + 1) * 4 + 2)
        offsetVals = []
        i = 0
        nval = 0
        val = 1
        keys = 0
        while nval != val:
            keys += 1
            key = getShortLE(offsets, 2 + i)
            val = getShortLE(offsets, 4 + i)
            nval = getShortLE(offsets, 8 + i)
            offsetVals.append(key + pagesize * page)
            offsetVals.append(val + pagesize * page)
            readkeys += 1
            i += 4
        offsetVals.append(pagesize * (page + 1))
        valKey = sorted(offsetVals)
        for i in range(keys * 2):
            f.seek(valKey[i])
            data = f.read(valKey[i + 1] - valKey[i])
            db1.append(data)
        page += 1
    f.close()

    db = {}
    for i in range(0, len(db1), 2):
        db[db1[i + 1]] = db1[i]
    return db

# ======== Trích xuất secret key từ key3.db ========
def extractSecretKey(masterPassword, keyData):
    pwdCheck = keyData[b'password-check']
    entrySaltLen = pwdCheck[1]
    entrySalt = pwdCheck[3: 3 + entrySaltLen]
    encryptedPasswd = pwdCheck[-16:]
    globalSalt = keyData[b'global-salt']
    cleartextData = decryptMoz3DES(globalSalt, masterPassword, entrySalt, encryptedPasswd)
    if cleartextData != b'password-check\x02\x02':
        print('password check error, Master Password is certainly used, please provide it with -p option')
        sys.exit()

    if CKA_ID not in keyData:
        return None
    privKeyEntry = keyData[CKA_ID]
    saltLen = privKeyEntry[1]
    nameLen = privKeyEntry[2]
    data = privKeyEntry[3 + saltLen + nameLen:]
    privKeyEntryASN1 = decoder.decode(data)
    printASN1(data, len(data), 0)
    entrySalt = privKeyEntryASN1[0][0][1][0].asOctets()
    privKeyData = privKeyEntryASN1[0][1].asOctets()
    privKey = decryptMoz3DES(globalSalt, masterPassword, entrySalt, privKeyData)
    prKey = decoder.decode(privKey)[0][2].asOctets()
    return long_to_bytes(decoder.decode(prKey)[0][3])

# ======== Giải mã PBE (Password-Based Encryption) ========
def decryptPBE(decodedItem, masterPassword, globalSalt):
    pbeAlgo = str(decodedItem[0][0][0])
    if pbeAlgo == '1.2.840.113549.1.12.5.1.3':
        entrySalt = decodedItem[0][0][1][0].asOctets()
        cipherT = decodedItem[0][1].asOctets()
        key = decryptMoz3DES(globalSalt, masterPassword, entrySalt, cipherT)
        return key[:24], pbeAlgo
    elif pbeAlgo == '1.2.840.113549.1.5.13':
        entrySalt = decodedItem[0][0][1][0][1][0].asOctets()
        iterationCount = int(decodedItem[0][0][1][0][1][1])
        keyLength = int(decodedItem[0][0][1][0][1][2])
        k = sha1(globalSalt + masterPassword).digest()
        key = pbkdf2_hmac('sha256', k, entrySalt, iterationCount, dklen=keyLength)
        iv = b'\x04\x0e' + decodedItem[0][0][1][1][1].asOctets()
        cipherT = decodedItem[0][1].asOctets()
        return AES.new(key, AES.MODE_CBC, iv).decrypt(cipherT), pbeAlgo

# ======== Trích xuất key giải mã từ key4.db hoặc key3.db ========
def getKey(masterPassword, directory):
    if (directory / 'key4.db').exists():
        conn = sqlite3.connect(directory / 'key4.db')
        c = conn.cursor()
        c.execute("SELECT item1,item2 FROM metadata WHERE id = 'password';")
        row = c.fetchone()
        globalSalt, item2 = row
        decodedItem2 = decoder.decode(item2)
        clearText, algo = decryptPBE(decodedItem2, masterPassword, globalSalt)
        if clearText == b'password-check\x02\x02':
            c.execute("SELECT a11,a102 FROM nssPrivate;")
            for row in c:
                if row[0] is not None:
                    break
            a11, a102 = row
            if a102 == CKA_ID:
                decoded_a11 = decoder.decode(a11)
                clearText, algo = decryptPBE(decoded_a11, masterPassword, globalSalt)
                return clearText[:24], algo
            else:
                print('No saved username/password')
        return None, None
    elif (directory / 'key3.db').exists():
        keyData = readBsddb(directory / 'key3.db')
        key = extractSecretKey(masterPassword, keyData)
        return key, '1.2.840.113549.1.12.5.1.3'
    else:
        print('Can not find key4.db')
        return None, None

# ======== Đọc thông tin tài khoản đã lưu từ logins.json hoặc signons.sqlite ========
def getLoginData():
    logins = []
    sqlite_file = options.directory / 'signons.sqlite'
    json_file = options.directory / 'logins.json'
    if json_file.exists():
        jsonLogins = json.loads(open(json_file, 'r').read())
        for row in jsonLogins.get('logins', []):
            logins.append((decodeLoginData(row['encryptedUsername']), decodeLoginData(row['encryptedPassword']), row['hostname']))
    elif sqlite_file.exists():
        conn = sqlite3.connect(sqlite_file)
        for row in conn.execute("SELECT * FROM moz_logins;"):
            logins.append((decodeLoginData(row[6]), decodeLoginData(row[7]), row[1]))
    else:
        print('missing logins.json or signons.sqlite')
    return logins

# ======== Hằng số nhận dạng khóa (CKA_ID) ========
CKA_ID = unhexlify('f8000000000000000000000000000001')

# ======== Nhận thông tin từ dòng lệnh ========
parser = OptionParser()
parser.add_option("-d", "--dir", type="string", dest="directory", help="Path to Firefox profile directory", default='')
parser.add_option("-p", "--password", type="string", dest="masterPassword", help="Primary Password", default='')
(options, args) = parser.parse_args()
options.directory = Path(options.directory)

# ======== Giải mã và hiển thị tài khoản ========
key, algo = getKey(options.masterPassword.encode(), options.directory)
if key is None:
    sys.exit()

logins = getLoginData()
if not logins:
    print('No stored passwords')
else:
    table_data = []
    for login in logins:
        assert login[0][0] == CKA_ID
        username = unpad(DES3.new(key, DES3.MODE_CBC, login[0][1]).decrypt(login[0][2]), 8).decode('utf-8')
        password = unpad(DES3.new(key, DES3.MODE_CBC, login[1][1]).decrypt(login[1][2]), 8).decode('utf-8')
        table_data.append([login[2], username, password])
    print(tabulate(table_data, headers=["Hostname", "Username", "Password"], tablefmt="grid"))