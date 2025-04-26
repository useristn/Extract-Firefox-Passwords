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

# Hàm trợ giúp để đọc dữ liệu nhị phân
def getShortLE(d, a):
    return unpack('<H', d[a:a+2])[0]

def getLongBE(d, a):
    return unpack('>L', d[a:a+4])[0]

# Bản đồ các kiểu ASN.1 và giá trị OID để giải mã
asn1Types = {
    0x30: 'SEQUENCE',  # Chuỗi
    4: 'OCTETSTRING',  # Chuỗi bát phân
    6: 'OBJECTIDENTIFIER',  # Định danh đối tượng
    2: 'INTEGER',  # Số nguyên
    5: 'NULL'  # Giá trị NULL
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

# Hàm để phân tích và in dữ liệu ASN.1
def printASN1(d, l, rl):
    type = d[0]  # Loại ASN.1
    length = d[1]  # Độ dài
    if length & 0x80 > 0:  # Nếu là độ dài dạng long form
        nByteLength = length & 0x7f
        length = d[2]
        skip = 1
    else:
        skip = 0

    print('  ' * rl, asn1Types[type], end=' ')
    if type == 0x30:  # Nếu là SEQUENCE
        print('{')
        seqLen = length
        readLen = 0
        while seqLen > 0:
            len2 = printASN1(d[2+skip+readLen:], seqLen, rl+1)
            seqLen -= len2
            readLen += len2
        print('  ' * rl, '}')
        return length + 2
    elif type == 6:  # Nếu là OBJECTIDENTIFIER
        oidVal = hexlify(d[2:2+length])
        print(oidValues.get(oidVal, f'oid? {oidVal}'))
        return length + 2
    elif type == 4:  # Nếu là OCTETSTRING
        print(hexlify(d[2:2+length]))
        return length + 2
    elif type == 5:  # Nếu là NULL
        print(0)
        return length + 2
    elif type == 2:  # Nếu là INTEGER
        print(hexlify(d[2:2+length]))
        return length + 2
    else:
        if length == l - 2:
            printASN1(d[2:], length, rl+1)
            return length

# Hàm giải mã dữ liệu được mã hóa bằng 3DES của Firefox
def decryptMoz3DES(globalSalt, masterPassword, entrySalt, encryptedData):
    # Tạo các khóa cần thiết từ globalSalt và masterPassword
    hp = sha1(globalSalt + masterPassword).digest()
    pes = entrySalt + b'\x00' * (20 - len(entrySalt))
    chp = sha1(hp + entrySalt).digest()
    k1 = hmac.new(chp, pes + entrySalt, sha1).digest()
    tk = hmac.new(chp, pes, sha1).digest()
    k2 = hmac.new(chp, tk + entrySalt, sha1).digest()
    k = k1 + k2
    iv = k[-8:]  # Vector khởi tạo
    key = k[:24]  # Khóa 3DES
    return DES3.new(key, DES3.MODE_CBC, iv).decrypt(encryptedData)

# Hàm giải mã dữ liệu đăng nhập từ logins.json hoặc cơ sở dữ liệu SQLite
def decodeLoginData(data):
    asn1data = decoder.decode(b64decode(data))
    key_id = asn1data[0][0].asOctets()
    iv = asn1data[0][1][1].asOctets()
    ciphertext = asn1data[0][2].asOctets()
    return key_id, iv, ciphertext

# Hàm đọc dữ liệu từ cơ sở dữ liệu BSD DB 1.85
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
    if options.verbose > 1:
        print('pagesize=0x%x' % pagesize)
        print('nkeys=%d' % nkeys)

    # Đọc các khóa và giá trị từ cơ sở dữ liệu
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

    # Chuyển đổi dữ liệu thành dictionary
    db = {}
    for i in range(0, len(db1), 2):
        db[db1[i + 1]] = db1[i]
    if options.verbose > 1:
        for i in db:
            print('%s: %s' % (repr(i), hexlify(db[i])))
    return db

# Hàm trích xuất khóa bí mật từ key4.db
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
    privKeyEntryASN1 = decoder.decode(privKeyEntry[3 + saltLen + nameLen:])
    data = privKeyEntry[3 + saltLen + nameLen:]
    printASN1(data, len(data), 0)
    entrySalt = privKeyEntryASN1[0][0][1][0].asOctets()
    privKeyData = privKeyEntryASN1[0][1].asOctets()
    privKey = decryptMoz3DES(globalSalt, masterPassword, entrySalt, privKeyData)
    privKeyASN1 = decoder.decode(privKey)
    prKey = privKeyASN1[0][2].asOctets()
    prKeyASN1 = decoder.decode(prKey)
    key = long_to_bytes(prKeyASN1[0][3])
    return key

# Hàm giải mã dữ liệu được mã hóa PBE
def decryptPBE(decodedItem, masterPassword, globalSalt):
    pbeAlgo = str(decodedItem[0][0][0])
    if pbeAlgo == '1.2.840.113549.1.12.5.1.3':  # pbeWithSha1AndTripleDES-CBC
        entrySalt = decodedItem[0][0][1][0].asOctets()
        cipherT = decodedItem[0][1].asOctets()
        key = decryptMoz3DES(globalSalt, masterPassword, entrySalt, cipherT)
        return key[:24], pbeAlgo
    elif pbeAlgo == '1.2.840.113549.1.5.13':  # pkcs5 pbes2
        entrySalt = decodedItem[0][0][1][0][1][0].asOctets()
        iterationCount = int(decodedItem[0][0][1][0][1][1])
        keyLength = int(decodedItem[0][0][1][0][1][2])
        k = sha1(globalSalt + masterPassword).digest()
        key = pbkdf2_hmac('sha256', k, entrySalt, iterationCount, dklen=keyLength)
        iv = b'\x04\x0e' + decodedItem[0][0][1][1][1].asOctets()
        cipherT = decodedItem[0][1].asOctets()
        clearText = AES.new(key, AES.MODE_CBC, iv).decrypt(cipherT)
        return clearText, pbeAlgo

# Hàm lấy khóa giải mã từ key4.db
def getKey(masterPassword, directory):
    if (directory / 'key4.db').exists():
        conn = sqlite3.connect(directory / 'key4.db')
        c = conn.cursor()
        c.execute("SELECT item1,item2 FROM metadata WHERE id = 'password';")
        row = c.fetchone()
        globalSalt = row[0]
        item2 = row[1]
        decodedItem2 = decoder.decode(item2)
        clearText, algo = decryptPBE(decodedItem2, masterPassword, globalSalt)

        if clearText == b'password-check\x02\x02':
            c.execute("SELECT a11,a102 FROM nssPrivate;")
            for row in c:
                if row[0] is not None:
                    break
            a11 = row[0]
            a102 = row[1]
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

# Hàm lấy dữ liệu đăng nhập từ logins.json hoặc signons.sqlite
def getLoginData():
    logins = []
    sqlite_file = options.directory / 'signons.sqlite'
    json_file = options.directory / 'logins.json'
    if json_file.exists():
        loginf = open(json_file, 'r').read()
        jsonLogins = json.loads(loginf)
        if 'logins' not in jsonLogins:
            print('error: no \'logins\' key in logins.json')
            return []
        for row in jsonLogins['logins']:
            encUsername = row['encryptedUsername']
            encPassword = row['encryptedPassword']
            logins.append((decodeLoginData(encUsername), decodeLoginData(encPassword), row['hostname']))
        return logins
    elif sqlite_file.exists():
        conn = sqlite3.connect(sqlite_file)
        c = conn.cursor()
        c.execute("SELECT * FROM moz_logins;")
        for row in c:
            encUsername = row[6]
            encPassword = row[7]
            logins.append((decodeLoginData(encUsername), decodeLoginData(encPassword), row[1]))
        return logins
    else:
        print('missing logins.json or signons.sqlite')

CKA_ID = unhexlify('f8000000000000000000000000000001')

parser = OptionParser(usage="Usage: python %prog [options]")
parser.add_option("-d", "--dir", type="string", dest="directory",help="Path to Firefox profile directory", default='')
parser.add_option("-p", "--password", type="string", dest="masterPassword", help="Primary Password",default='')
(options, args) = parser.parse_args()
options.directory = Path(options.directory)

key, algo = getKey(options.masterPassword.encode(), options.directory)
if key is None:
    sys.exit()

logins = getLoginData()
if len(logins) == 0:
    print('No stored passwords')
else:
    # Tạo danh sách để hiển thị dưới dạng bảng
    table_data = []
    if algo in ['1.2.840.113549.1.12.5.1.3', '1.2.840.113549.1.5.13']:
        for i in logins:
            assert i[0][0] == CKA_ID
            # Giải mã username
            iv = i[0][1]
            ciphertext = i[0][2]
            username = unpad(DES3.new(key, DES3.MODE_CBC, iv).decrypt(ciphertext), 8).decode('utf-8')

            # Giải mã password
            iv = i[1][1]
            ciphertext = i[1][2]
            password = unpad(DES3.new(key, DES3.MODE_CBC, iv).decrypt(ciphertext), 8).decode('utf-8')

            # Thêm vào bảng
            table_data.append([i[2], username, password])

    # Hiển thị bảng với tabulate
    headers = ["Hostname", "Username", "Password"]
    print(tabulate(table_data, headers=headers, tablefmt="grid"))