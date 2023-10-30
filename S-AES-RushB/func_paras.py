import random
from tqdm import tqdm

# 定义S盒
S = [[9, 4, 10, 11], [13, 1, 8, 5], [6, 2, 0, 3], [12, 14, 15, 7]]

# 定义逆S盒
IS = [[10, 5, 9, 11], [1, 7, 8, 15], [6, 0, 2, 3], [12, 4, 13, 14]]

# 定义轮常数
RCON1, RCON2= '10000000','00110000'

# 异或
def XOR(bits1, bits2):
    result = ''
    for bit1, bit2 in zip(bits1, bits2):
        result += str(((int(bit1) + int(bit2)) % 2))
    return result

# 密钥加
def RoundKey_Add(bits1, bits2):
    result = ''
    for bit1, bit2 in zip(bits1, bits2):
        result += str(int(bit1) ^ int(bit2))
    return result

# 半字节代替
def SubNib(bits):
    result = ''
    for i in range(0, len(bits), 4):
        row = int(bits[i:i + 2], 2)
        col = int(bits[i + 2:i + 4], 2)
        new_value = S[row][col]
        result += format(new_value, '04b')
    return result

# 逆半字节代替
def InvSubNib(bits):
    result = ''
    for i in range(0, len(bits), 4):
        row = int(bits[i:i + 2], 2)
        col = int(bits[i + 2:i + 4], 2)
        result += format(IS[row][col], '04b')
    return result

# 行移位
def ShiftRows(bits):
    new = bits[0:4] + bits[12:16] + bits[8:12] + bits[4:8]
    return new
# 左移
def RotNib(bits):
    new = bits[4:8] + bits[0:4]
    return new

# GF(2^4)上的加法
def GF_Multi(a, b):
    # 定义GF(2^4)上的乘法表
    add_table = [[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
                  [1, 0, 3, 2, 5, 4, 7, 6, 9, 8, 11, 10, 13, 12, 15, 14],
                  [2, 3, 0, 1, 6, 7, 4, 5, 10, 11, 8, 9, 14, 15, 12, 13],
                  [3, 2, 1, 0, 7, 6, 5, 4, 11, 10, 9, 8, 15, 14, 13, 12],
                  [4, 5, 6, 7, 0, 1, 2, 3, 12, 13, 14, 15, 8, 9, 10, 11],
                  [5, 4, 7, 6, 1, 0, 3, 2, 13, 12, 15, 14, 9, 8, 11, 10],
                  [6, 7, 4, 5, 2, 3, 0, 1, 14, 15, 12, 13, 10, 11, 8, 9],
                  [7, 6, 5, 4, 3, 2, 1, 0, 15, 14, 13, 12, 11, 10, 9, 8],
                  [8, 9, 10, 11, 12, 13, 14, 15, 0, 1, 2, 3, 4, 5, 6, 7],
                  [9, 8, 11, 10, 13, 12, 15, 14, 1, 0, 3, 2, 5, 4, 7, 6],
                  [10, 11, 8, 9, 14, 15, 12, 13, 2, 3, 0, 1, 6, 7, 4, 5],
                  [11, 10, 9, 8, 15, 14, 13, 12, 3, 2, 1, 0, 7, 6, 5, 4],
                  [12, 13, 14, 15, 8, 9, 10, 11, 4, 5, 6, 7, 0, 1, 2, 3],
                  [13, 12, 15, 14, 9, 8, 11, 10, 5, 4, 7, 6, 1, 0, 3, 2],
                  [14, 15, 12, 13, 10, 11, 8, 9, 6, 7, 4, 5, 2, 3, 0, 1],
                  [15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0]]
    # 执行乘法运算
    result_int = add_table[int(a, 2)][int(b, 2)]
    # 将结果转换为4位的二进制字符串
    result_str = bin(result_int)[2:].zfill(4)
    return result_str

# GF(2^4)上的乘法
def GF_Multi(a, b):
    # 定义GF(2^4)上的乘法表
    mul_table = [
        [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
        [0, 2, 4, 6, 8, 10, 12, 14, 3, 1, 7, 5, 11, 9, 15, 13],
        [0, 3, 6, 5, 12, 15, 10, 9, 11, 8, 13, 14, 7, 4, 1, 2],
        [0, 4, 8, 12, 3, 7, 11, 15, 6, 2, 14, 10, 5, 1, 13, 9],
        [0, 5, 10, 15, 7, 2, 13, 8, 14, 11, 4, 1, 9, 12, 3, 6],
        [0, 6, 12, 10, 11, 13, 7, 1, 5, 3, 9, 15, 14, 8, 2, 4],
        [0, 7, 14, 9, 15, 8, 1, 6, 13, 10, 3, 4, 2, 5, 12, 11],
        [0, 8, 3, 11, 6, 14, 5, 13, 12, 4, 15, 7, 10, 2, 9, 1],
        [0, 9, 1, 8, 2, 11, 3, 10, 4, 13, 5, 12, 6, 15, 7, 14],
        [0, 10, 7, 13, 14, 4, 9, 3, 15, 5, 8, 2, 1, 11, 6, 12],
        [0, 11, 5, 14, 10, 1, 15, 4, 7, 12, 2, 9, 13, 6, 8, 3],
        [0, 12, 11, 7, 5, 9, 14, 2, 10, 6, 1, 13, 15, 3, 4, 8],
        [0, 13, 9, 4, 1, 12, 8, 5, 2, 15, 11, 6, 3, 14, 10, 7],
        [0, 14, 15, 1, 13, 3, 2, 12, 9, 7, 6, 8, 4, 10, 11, 5],
        [0, 15, 13, 2, 9, 6, 4, 11, 1, 14, 12, 3, 8, 7, 5, 10]
    ]
    # 执行乘法运算
    result_int = mul_table[int(a, 2)][int(b, 2)]
    # 将结果转换为4位的二进制字符串
    result_str = bin(result_int)[2:].zfill(4)
    return result_str

# 混淆矩阵
def MixColumns(bits):
    result = XOR(bits[0:4], GF_Multi('0100', bits[4:8])) + XOR(GF_Multi('0100', bits[0:4]), bits[4:8]) + \
        XOR(bits[8:12], GF_Multi('0100', bits[12:16])) + \
        XOR(GF_Multi('0100', bits[8:12]), bits[12:16])
    return result

# 逆混淆矩阵
def InvMixColumns(bits):
    result = XOR(GF_Multi('1001', bits[0:4]), GF_Multi('0010', bits[4:8])) + XOR(GF_Multi('0010', bits[0:4]), GF_Multi('1001', bits[4:8])) + XOR(
        GF_Multi('1001', bits[8:12]), GF_Multi('0010', bits[12:16])) + XOR(GF_Multi('0010', bits[8:12]), GF_Multi('1001', bits[12:16]))
    return result

# 密钥扩展
def KeyExpansion(key):
    w0 = key[0:8]
    w1 = key[8:16]
    w2 = XOR(w0, XOR(RCON1, SubNib(RotNib(w1))))
    w3 = XOR(w2, w1)
    w4 = XOR(w2, XOR(RCON2, SubNib(RotNib(w3))))
    w5 = XOR(w4, w3)
    return [w0 + w1, w2 + w3, w4 + w5]

# 加密
def Encrypt(plainText, key):
    # 密钥扩展
    expandedKey = KeyExpansion(key)
    # 密钥加
    cipherText = RoundKey_Add(plainText, expandedKey[0])
    # 轮函数
    cipherText = SubNib(cipherText)
    cipherText = ShiftRows(cipherText)
    cipherText = MixColumns(cipherText)
    # 密钥加
    cipherText = RoundKey_Add(cipherText, expandedKey[1])
    # 轮函数
    cipherText = SubNib(cipherText)
    cipherText = ShiftRows(cipherText)
    # 密钥加
    cipherText = RoundKey_Add(cipherText, expandedKey[2])
    return cipherText

# print(Encrypt('1100110011001100','0000000011111111'))
# 实现解密
def Decrypt(cipherText, key):
    # 密钥扩展
    expandedKey = KeyExpansion(key)
    # 密钥加
    plainText = RoundKey_Add(cipherText, expandedKey[2])
    # 轮函数
    plainText = ShiftRows(plainText)
    plainText = InvSubNib(plainText)
    # 密钥加
    plainText = RoundKey_Add(plainText, expandedKey[1])
    plainText = InvMixColumns(plainText)
    # 轮函数
    plainText = ShiftRows(plainText)
    plainText = InvSubNib(plainText)
    # 密钥加
    plainText = RoundKey_Add(plainText, expandedKey[0])
    return plainText

# ascll转二进制
def ascii2binary(asciiText):
    binaryText = ''.join(bin(ord(char))[2:].zfill(8) for char in asciiText)
    return binaryText

# 二进制转ascll
def binary2ascii(binaryText):
    asciiText = ''.join(chr(int(binaryText[i:i+8], 2)) for i in range(0, len(binaryText), 8))
    return asciiText

# ascll码加密
def ascii_encrypt(plainText, key):
    result = ''
    if len(plainText) % 2 != 0:
        plainText += ' '
    for i in range(0, len(plainText), 2):
        # 将明文转换为2进制字符串
        char = ascii2binary(plainText[i])
        char += ascii2binary(plainText[i + 1])
        # 执行加密
        char = Encrypt(char, key)
        # 将密文转换为ASCII码字符串
        char = binary2ascii(char)
        result += char
    return result

# ascll码解密
def ascii_decrypt(cipherText, key):
    new = ''
    for i in range(0, len(cipherText), 2):
        # 将密文转换为2进制字符串
        char = ascii2binary(cipherText[i])
        char += ascii2binary(cipherText[i+1])
        # 执行解密
        char = Decrypt(char, key)
        # 将明文转换为ASCII码字符串
        char = binary2ascii(char)
        new += char
    return new

# 二进制双重加密
def binary_double_encrypt(plainText, key1, key2):
    cipherText1 = Encrypt(plainText, key1)
    cipherText2 = Decrypt(cipherText1, key2)
    return cipherText2

# 二进制双重解密
def binary_double_decrypt(cipherText, key1, key2):
    plainText1 = Encrypt(cipherText, key2)
    plainText2 = Decrypt(plainText1, key1)
    return plainText2

# ascll双重加密
def ascll_double_encrypt(plainText, key1, key2):
    cipherText1 = ascii_encrypt(plainText, key1)
    cipherText2 = ascii_decrypt(cipherText1, key2)
    return cipherText2

# ascll双重解密
def ascll_double_decrypt(cipherText, key1, key2):
    plainText1 = ascii_encrypt(cipherText, key2)
    plainText2 = ascii_decrypt(plainText1, key1)
    return plainText2

# 二进制三重加密
def binary_triple_encrypt(plainText, key1, key2):
    cipherText1 = Encrypt(plainText, key1)
    cipherText2 = Decrypt(cipherText1, key2)
    cipherText3 = Encrypt(cipherText2, key1)
    return cipherText3

# 二进制三重解密
def binary_triple_decrypt(cipherText, key1, key2):
    plainText1 = Decrypt(cipherText, key1)
    plainText2 = Encrypt(plainText1, key2)
    plainText3 = Decrypt(plainText2, key1)
    return plainText3

# ascll三重加密
def ascll_triple_encrypt(plainText, key1, key2):
    cipherText1 = ascii_encrypt(plainText, key1)
    cipherText2 = ascii_decrypt(cipherText1, key2)
    cipherText3 = ascii_encrypt(cipherText1, key1)
    return cipherText3

# ascll三重解密
def ascll_triple_decrypt(cipherText, key1, key2):
    plainText1 = ascii_decrypt(cipherText, key1)
    plainText2 = ascii_encrypt(plainText1, key2)
    plainText3 = ascii_decrypt(plainText1, key1)
    return plainText3

# 密钥破解
def crack(plainText, cipherText):
    possibleKeys = []

    for i in range(2 ** 16):
        key = bin(i)[2:].zfill(16)
        encryptedText = Encrypt(plainText, key)
        # print(key)
        if encryptedText == cipherText:
            possibleKeys.append(key)

    return '     '.join(possibleKeys)

# print(crack('1100110011001100','1000000101010100'))
# 所有可能的密钥对
def generate_all_keys():
    for i in range(2 ** 32):
        key = bin(i)[2:].zfill(32)
        yield (key[:16], key[16:])

# 中间相遇攻击
def middle_meet_attack(knownPlainTextList, knownCipherTextList):
    allKeys = generate_all_keys()
    foundKeyList = []
    counter = 0
    total_keys = 2 ** 32

    for key1, key2 in tqdm(allKeys, total=total_keys):
        flag = True
        for knownPlainText, knownCipherText in zip(knownPlainTextList, knownCipherTextList):
            middleText1 = Encrypt(knownPlainText, key1)
            middleText2 = Decrypt(knownCipherText, key2)
            if middleText1 != middleText2:
                flag = False
                break
        if flag:
            print("找到密钥对：", key1, key2)
            foundKeyList.append((key1, key2))

        counter += 1
        if counter % (2 ** 20) == 0:
            print("正在检索...")

    return foundKeyList

# 判断数字个数
def is_multiple_of_16(text):
    # 移除空格等非数字字符，然后检查数字个数是否为16的倍数
    digit_count = sum(1 for char in text if char.isdigit())
    return digit_count % 16 == 0

# 已知的明文和密文对组合
# known_plain_text_list = ['0011000011111011']
# known_cipher_text_list = ['0100101001110100']

# 测试中间相遇攻击
# def test_attack():
#     print("测试中间相遇攻击")
#     found_key_list = middle_meet_attack(
#         known_plain_text_list, known_cipher_text_list)
#     if found_key_list:
#         print("所有密钥对：", found_key_list)
#     else:
#         print("未找到密钥对")
# test_attack()

# 随机初始向量IV
def generate_IV():
    IV = ''.join(random.choice('01') for _ in range(16))
    return IV

# CBC加密模式
def binary_CBC_encrypt(plainText, key, IV):
    # 将明文分组
    plainTextList = [plainText[i:i + 16] for i in range(0, len(plainText), 16)]
    # 用于存储密文
    cipherTextList = []
    # 对每个分组进行加密
    for plainText in plainTextList:
        # 执行加密
        cipherText = Encrypt(XOR(plainText, IV), key)
        # 更新初始向量
        IV = cipherText
        # 将密文添加到密文列表
        cipherTextList.append(cipherText)
    # 将密文列表转换为字符串
    cipherText = ''.join(cipherTextList)
    return cipherText

# CBC解密模式
def binary_CBC_decrypt(cipherText, key, IV):
    # 将密文分组
    cipherTextList = [cipherText[i:i + 16] for i in range(0, len(cipherText), 16)]
    # 用于存储明文
    plainTextList = []
    # 对每个分组进行解密
    for cipherText in cipherTextList:
        # 执行解密
        plainText = XOR(Decrypt(cipherText, key), IV)
        # 更新初始向量
        IV = cipherText
        # 将明文添加到明文列表
        plainTextList.append(plainText)
    # 将明文列表转换为字符串
    plainText = ''.join(plainTextList)
    return plainText