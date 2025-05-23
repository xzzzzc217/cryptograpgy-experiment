# 定义DES算法所需的置换表和S盒
IP = [
    58, 50, 42, 34, 26, 18, 10, 2,
    60, 52, 44, 36, 28, 20, 12, 4,
    62, 54, 46, 38, 30, 22, 14, 6,
    64, 56, 48, 40, 32, 24, 16, 8,
    57, 49, 41, 33, 25, 17, 9, 1,
    59, 51, 43, 35, 27, 19, 11, 3,
    61, 53, 45, 37, 29, 21, 13, 5,
    63, 55, 47, 39, 31, 23, 15, 7
]

PC1 = [
    57, 49, 41, 33, 25, 17, 9,
    1, 58, 50, 42, 34, 26, 18,
    10, 2, 59, 51, 43, 35, 27,
    19, 11, 3, 60, 52, 44, 36,
    63, 55, 47, 39, 31, 23, 15,
    7, 62, 54, 46, 38, 30, 22,
    14, 6, 61, 53, 45, 37, 29,
    21, 13, 5, 28, 20, 12, 4
]

PC2 = [
    14, 17, 11, 24, 1, 5,
    3, 28, 15, 6, 21, 10,
    23, 19, 12, 4, 26, 8,
    16, 7, 27, 20, 13, 2,
    41, 52, 31, 37, 47, 55,
    30, 40, 51, 45, 33, 48,
    44, 49, 39, 56, 34, 53,
    46, 42, 50, 36, 29, 32
]

E = [
    32, 1, 2, 3, 4, 5,
    4, 5, 6, 7, 8, 9,
    8, 9, 10, 11, 12, 13,
    12, 13, 14, 15, 16, 17,
    16, 17, 18, 19, 20, 21,
    20, 21, 22, 23, 24, 25,
    24, 25, 26, 27, 28, 29,
    28, 29, 30, 31, 32, 1
]

P = [
    16, 7, 20, 21,
    29, 12, 28, 17,
    1, 15, 23, 26,
    5, 18, 31, 10,
    2, 8, 24, 14,
    32, 27, 3, 9,
    19, 13, 30, 6,
    22, 11, 4, 25
]

# 定义8个S盒（以下仅列出S1和S2，其余S3到S8需补充完整）
S_boxes = [
    [  # S1
        [14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7],
        [0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8],
        [4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0],
        [15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13]
    ],
    [  # S2
        [15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10],
        [3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5],
        [0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15],
        [13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9]
    ],
    [  # S3
        [10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8],
        [13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1],
        [13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7],
        [1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12]
    ],
    [  # S4
        [7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15],
        [13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9],
        [10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4],
        [3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14]
    ],
    [  # S5
        [2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9],
        [14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6],
        [4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14],
        [11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3]
    ],
    [  # S6
        [12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11],
        [10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8],
        [9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6],
        [4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13]
    ],
    [  # S7
        [4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1],
        [13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6],
        [1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2],
        [6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12]
    ],
    [  # S8
        [13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7],
        [1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2],
        [7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8],
        [2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11]
    ]
]

# 定义辅助函数
def hex_to_bin(hex_str):
    """将十六进制字符串转换为64位二进制字符串"""
    return bin(int(hex_str, 16))[2:].zfill(64)

def permute(bits, table):
    """根据置换表对位进行重排"""
    return ''.join(bits[i-1] for i in table)

def left_shift(bits, n):
    """循环左移n位"""
    return bits[n:] + bits[:n]

def xor(a, b):
    """对两个二进制字符串进行异或操作"""
    return ''.join('0' if a[i] == b[i] else '1' for i in range(len(a)))

def s_box_substitution(bits):
    """对48位输入进行S盒代换，输出32位"""
    assert len(bits) == 48
    output = ''
    s_outputs = []
    for i in range(8):
        group = bits[i*6:(i+1)*6]
        row = int(group[0] + group[5], 2)  # 首尾位作为行号
        col = int(group[1:5], 2)           # 中间4位作为列号
        s_value = S_boxes[i][row][col]
        s_bin = bin(s_value)[2:].zfill(4)
        s_outputs.append(s_bin)
        output += s_bin
    return output, s_outputs

# 主程序
# 输入明文和密钥
plaintext_hex = "0123456789ABCDEF"
key_hex = "0123456789ABCDEF"

# 转换为二进制
plaintext_bin = hex_to_bin(plaintext_hex)
key_bin = hex_to_bin(key_hex)

# 小问1：推导第一轮子密钥K₁
permuted_key = permute(key_bin, PC1)  # PC-1置换得到56位
C0 = permuted_key[:28]
D0 = permuted_key[28:]
C1 = left_shift(C0, 1)  # 第一轮左移1位
D1 = left_shift(D0, 1)
K1 = permute(C1 + D1, PC2)  # PC-2置换得到48位K₁

# 小问2：推导L₀和R₀
permuted_plaintext = permute(plaintext_bin, IP)  # 初始置换IP
L0 = permuted_plaintext[:32]
R0 = permuted_plaintext[32:]

# 小问3：扩展R₀求E[R₀]
E_R0 = permute(R0, E)  # 扩展置换E，32位到48位

# 小问4：计算A = E[R₀] ⊕ K₁
A = xor(E_R0, K1)

# 小问5和6：S盒代换求B
B, s_box_outputs = s_box_substitution(A)  # B是32位，s_box_outputs是8个4位输出

# 小问7：应用置换求P(B)
P_B = permute(B, P)

# 小问8：计算R₁ = P(B) ⊕ L₀
R1 = xor(P_B, L0)

# 小问9：一轮加密后的密文（L₁ || R₁）
L1 = R0  # DES中L₁ = R₀
ciphertext_one_round = L1 + R1

# 输出结果
print("1. 第一轮子密钥 K₁:", K1)
print("2. L₀:", L0)
print("   R₀:", R0)
print("3. E[R₀]:", E_R0)
print("4. A = E[R₀] ⊕ K₁:", A)
print("5. S盒代换的值:", ' '.join(s_box_outputs))
print("6. B:", B)
print("7. P(B):", P_B)
print("8. R₁:", R1)
print("9. 一轮加密后的密文:", ciphertext_one_round)