import os
import tkinter as tk
from tkinter import ttk, messagebox

# 定义AES算法的S盒，用于字节替换（SubBytes）操作，提供非线性变换
sbox = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
]

# 定义逆S盒，用于解密的逆字节替换（InvSubBytes）操作
inv_sbox = [
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
    0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
    0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
    0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
    0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
    0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
    0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
    0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
    0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
    0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
    0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d
]

# 定义轮常数（Rcon），用于密钥扩展中的轮常数异或操作
rcon = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36]

# 字节替换（SubBytes）：将状态矩阵中的每个字节通过S盒替换
def sub_bytes(state):
    return [sbox[b] for b in state]

# 逆字节替换（InvSubBytes）：将状态矩阵中的每个字节通过逆S盒替换
def inv_sub_bytes(state):
    return [inv_sbox[b] for b in state]

# 行移位（ShiftRows）：对状态矩阵的每一行进行循环左移，行号决定移位量
def shift_rows(state):
    s = [state[i*4:(i+1)*4] for i in range(4)]  # 将状态矩阵按行分割
    return [s[0][0], s[1][1], s[2][2], s[3][3],  # 第一列：第0行不移，第1行左移1位，依次类推
            s[1][0], s[2][1], s[3][2], s[0][3],
            s[2][0], s[3][1], s[0][2], s[1][3],
            s[3][0], s[0][1], s[1][2], s[2][3]]

# 逆行移位（InvShiftRows）：对状态矩阵的每一行进行循环右移，行号决定移位量
def inv_shift_rows(state):
    s = [state[i*4:(i+1)*4] for i in range(4)]  # 将状态矩阵按行分割
    return [s[0][0], s[3][1], s[2][2], s[1][3],  # 第一列：第0行不移，第1行右移1位，依次类推
            s[1][0], s[0][1], s[3][2], s[2][3],
            s[2][0], s[1][1], s[0][2], s[3][3],
            s[3][0], s[2][1], s[1][2], s[0][3]]

# 列混合（MixColumns）：对状态矩阵的每一列进行的线性变换
# 因为是一列一列进行操作，故s返回4行1列的列向量，每行是一个字节
def mix_columns(state):
    def gf_mult(a, b):  # 乘法，处理有限域GF(2^8)的运算
        p = 0
        for _ in range(8):
            if b & 1: p ^= a # 如果b的最低位是1，p异或a(相当于加法)
            a <<= 1 # a左移一位
            if a & 0x100: a ^= 0x1b  # # 如果a溢出（第8位为1），异或模多项式0x1b(x^8 + x^4 + x^3 + x + 1)
            b >>= 1 # b右移一位
        return p & 0xff # 保证结果在8位范围内
    s = [0] * 16
    for i in range(4):
        # 每列按照固定多项式进行变换：{02}x^3 + {03}x^2 + {01}x + {01}
        s[i] = gf_mult(2, state[i]) ^ gf_mult(3, state[4+i]) ^ state[8+i] ^ state[12+i]
        s[4+i] = state[i] ^ gf_mult(2, state[4+i]) ^ gf_mult(3, state[8+i]) ^ state[12+i]
        s[8+i] = state[i] ^ state[4+i] ^ gf_mult(2, state[8+i]) ^ gf_mult(3, state[12+i])
        s[12+i] = gf_mult(3, state[i]) ^ state[4+i] ^ state[8+i] ^ gf_mult(2, state[12+i])
    return s

# 逆列混合（InvMixColumns）：对状态矩阵的每一列进行逆线性变换
def inv_mix_columns(state):
    def gf_mult(a, b):  # 乘法，处理有限域GF(2^8)的运算
        p = 0
        for _ in range(8):
            if b & 1: p ^= a
            a <<= 1
            if a & 0x100: a ^= 0x1b
            b >>= 1
        return p & 0xff
    s = [0] * 16
    for i in range(4):
        # 每列按照逆多项式进行变换：{0e}x^3 + {0b}x^2 + {0d}x + {09}
        s[i] = gf_mult(0x0e, state[i]) ^ gf_mult(0x0b, state[4+i]) ^ gf_mult(0x0d, state[8+i]) ^ gf_mult(0x09, state[12+i])
        s[4+i] = gf_mult(0x09, state[i]) ^ gf_mult(0x0e, state[4+i]) ^ gf_mult(0x0b, state[8+i]) ^ gf_mult(0x0d, state[12+i])
        s[8+i] = gf_mult(0x0d, state[i]) ^ gf_mult(0x09, state[4+i]) ^ gf_mult(0x0e, state[8+i]) ^ gf_mult(0x0b, state[12+i])
        s[12+i] = gf_mult(0x0b, state[i]) ^ gf_mult(0x0d, state[4+i]) ^ gf_mult(0x09, state[8+i]) ^ gf_mult(0x0e, state[12+i])
    return s

# 密钥加（AddRoundKey）：将状态矩阵与轮密钥进行逐字节异或
def add_round_key(state, round_key):
    return [s ^ k for s, k in zip(state, round_key)]

# 密钥扩展（KeyExpansion）：根据初始密钥生成所有轮密钥
def key_expansion(key, nk, nr):
    def sub_word(word): return [sbox[b] for b in word]  # 对4字节字进行S盒替换
    def rot_word(word): return word[1:] + word[:1]      # 对4字节字进行循环左移
    expanded_key = list(key)
    i = nk  # 计数器，表示当前扩展的字数
    while len(expanded_key) < 16 * (nr + 1):  # 扩展到所需长度（每轮16字节，共nr+1轮）
        temp = expanded_key[-4:]  # 取最后4字节
        if i % nk == 0:  # 每nk个字，执行轮常数变换
            temp = sub_word(rot_word(temp))
            temp[0] ^= rcon[i // nk - 1]
        elif nk > 6 and i % nk == 4:  # 对于256位密钥的额外变换
            temp = sub_word(temp)
        # 新字由前nk字与temp异或生成
        expanded_key += [expanded_key[i*4 - nk*4] ^ temp[0], expanded_key[i*4 - nk*4 + 1] ^ temp[1],
                         expanded_key[i*4 - nk*4 + 2] ^ temp[2], expanded_key[i*4 - nk*4 + 3] ^ temp[3]]
        i += 1
    # 将扩展密钥按每16字节分割为轮密钥
    return [expanded_key[j:j+16] for j in range(0, len(expanded_key), 16)]

# AES单块加密：对16字节明文块进行加密
def aes_encrypt_block(plaintext, expanded_key, nr):
    state = list(plaintext)
    state = add_round_key(state, expanded_key[0])  # 初始轮密钥加
    for i in range(1, nr):  # 中间nr-1轮
        state = sub_bytes(state)    # 字节替换
        state = shift_rows(state)   # 行移位
        state = mix_columns(state)  # 列混淆
        state = add_round_key(state, expanded_key[i])  # 轮密钥加
    # 最后一轮（无列混淆）
    state = sub_bytes(state)
    state = shift_rows(state)
    state = add_round_key(state, expanded_key[nr])
    return bytes(state)

# AES单块解密：对16字节密文块进行解密
def aes_decrypt_block(ciphertext, expanded_key, nr):
    state = list(ciphertext)
    state = add_round_key(state, expanded_key[nr])  # 最后一轮密钥加
    for i in range(nr-1, 0, -1):  # 中间nr-1轮，逆序
        state = inv_shift_rows(state)   # 逆行移位
        state = inv_sub_bytes(state)    # 逆字节替换
        state = add_round_key(state, expanded_key[i])  # 轮密钥加
        state = inv_mix_columns(state)  # 逆列混淆
    # 最后一轮（无逆列混淆）
    state = inv_shift_rows(state)
    state = inv_sub_bytes(state)
    state = add_round_key(state, expanded_key[0])
    return bytes(state)

# PKCS7填充：对明文进行填充，使其长度为16字节的整数倍
def pad_pkcs7(data, block_size=16):
    padding_len = block_size - (len(data) % block_size)
    return data + bytes([padding_len] * padding_len)

# 去除PKCS7填充：从解密后的明文中移除填充字节
def unpad_pkcs7(data):
    padding_len = data[-1]
    return data[:-padding_len]

# CBC模式加密：对任意长度的明文进行加密
def aes_cbc_encrypt(plaintext, key, nk, nr):
    iv = os.urandom(16)  # 随机生成16字节初始向量（IV）
    plaintext = pad_pkcs7(plaintext)  # 填充明文
    expanded_key = key_expansion(key, nk, nr)  # 扩展密钥
    ciphertext = iv  # 密文以IV开头
    prev_block = iv  # 前一块密文初始化为IV
    for i in range(0, len(plaintext), 16):
        block = plaintext[i:i+16]
        block = bytes(a ^ b for a, b in zip(block, prev_block))  # 当前块与前一块密文异或
        encrypted_block = aes_encrypt_block(block, expanded_key, nr)  # 加密当前块
        ciphertext += encrypted_block
        prev_block = encrypted_block  # 更新前一块密文
    return ciphertext

# CBC模式解密：对任意长度的密文进行解密
def aes_cbc_decrypt(ciphertext, key, nk, nr):
    iv = ciphertext[:16]  # 提取密文开头的IV
    ciphertext = ciphertext[16:]  # 剩余部分为实际密文
    expanded_key = key_expansion(key, nk, nr)  # 扩展密钥
    plaintext = b""
    prev_block = iv  # 前一块密文初始化为IV
    for i in range(0, len(ciphertext), 16):
        block = ciphertext[i:i+16]
        decrypted_block = aes_decrypt_block(block, expanded_key, nr)  # 解密当前块
        plaintext += bytes(a ^ b for a, b in zip(decrypted_block, prev_block))  # 与前一块密文异或
        prev_block = block  # 更新前一块密文
    return unpad_pkcs7(plaintext)  # 去除填充

# GUI界面类：实现AES加解密的图形化界面
class AESApp:
    def __init__(self, root):
        self.root = root
        self.root.title("AES 加解密工具")  # 设置窗口标题
        self.root.geometry("600x650")  # 设置窗口大小
        self.root.configure(bg="#f0f0f0")  # 设置浅灰色背景
        self.notebook = ttk.Notebook(root)  # 创建选项卡容器
        self.notebook.pack(fill='both', expand=True, padx=10, pady=10)  # 填充窗口

        # 配置 ttk 样式以实现现代化外观
        self.style = ttk.Style()  # 将样式对象存储为类属性
        self.style.configure("TNotebook", background="#f0f0f0")  # 设置选项卡背景
        self.style.configure("TFrame", background="#f0f0f0")  # 设置框架背景
        self.style.configure("TButton", font=("Helvetica", 10, "bold"), padding=10)  # 设置按钮样式
        self.style.configure("TRadiobutton", font=("Helvetica", 10))  # 设置单选按钮样式
        self.style.configure("TLabel", font=("Helvetica", 11), background="#f0f0f0")  # 设置标签样式

        # 加密选项卡
        self.encrypt_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.encrypt_frame, text='加密')  # 添加加密选项卡
        self.create_encrypt_ui()  # 初始化加密界面

        # 解密选项卡
        self.decrypt_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.decrypt_frame, text='解密')  # 添加解密选项卡
        self.create_decrypt_ui()  # 初始化解密界面

    def create_encrypt_ui(self):
        # 创建加密界面的主框架
        container = ttk.Frame(self.encrypt_frame)
        container.grid(row=0, column=0, padx=20, pady=20, sticky="nsew")
        self.encrypt_frame.configure(padding=(10, 10))  # 设置框架内边距

        # 密钥长度选择区域
        ttk.Label(container, text="选择密钥长度:", font=("Helvetica", 12, "bold")).grid(row=0, column=0, sticky="w",
                                                                                        pady=5)
        self.encrypt_key_length = tk.StringVar(value="128")  # 默认选择128位密钥

        key_lengths = [("128位（16字节）", "128"), ("192位（24字节）", "192"), ("256位（32字节）", "256")]
        for i, (text, value) in enumerate(key_lengths):
            ttk.Radiobutton(container, text=text, variable=self.encrypt_key_length, value=value).grid(row=i + 1,
                                                                                                      column=0,
                                                                                                      sticky="w",
                                                                                                      padx=10, pady=2)

        # 密钥输入区域
        ttk.Label(container, text="密钥:", font=("Helvetica", 12, "bold")).grid(row=4, column=0, sticky="w", pady=5)
        self.encrypt_key_entry = ttk.Entry(container, width=50, font=("Helvetica", 10))
        self.encrypt_key_entry.grid(row=5, column=0, sticky="ew", pady=5)

        # 明文输入区域
        ttk.Label(container, text="明文:", font=("Helvetica", 12, "bold")).grid(row=6, column=0, sticky="w", pady=5)
        self.encrypt_input_text = tk.Text(container, height=6, width=50, font=("Helvetica", 10), relief="sunken",
                                          borderwidth=2)
        self.encrypt_input_text.grid(row=7, column=0, sticky="ew", pady=5)
        scrollbar_input = ttk.Scrollbar(container, orient="vertical", command=self.encrypt_input_text.yview)
        scrollbar_input.grid(row=7, column=1, sticky="ns", pady=5)
        self.encrypt_input_text.config(yscrollcommand=scrollbar_input.set)  # 配置输入文本框的滚动条

        # 加密按钮
        self.style.configure("Accent.TButton", background="#4CAF50", foreground="white")  # 设置绿色按钮样式
        ttk.Button(container, text="加密", command=self.encrypt, style="Accent.TButton").grid(row=8, column=0, pady=10)

        # 密文输出区域
        ttk.Label(container, text="密文 (十六进制):", font=("Helvetica", 12, "bold")).grid(row=9, column=0, sticky="w",
                                                                                           pady=5)
        self.encrypt_output_text = tk.Text(container, height=6, width=50, font=("Helvetica", 10), relief="sunken",
                                           borderwidth=2)
        self.encrypt_output_text.grid(row=10, column=0, sticky="ew", pady=5)
        scrollbar_output = ttk.Scrollbar(container, orient="vertical", command=self.encrypt_output_text.yview)
        scrollbar_output.grid(row=10, column=1, sticky="ns", pady=5)
        self.encrypt_output_text.config(yscrollcommand=scrollbar_output.set)  # 配置输出文本框的滚动条

        # 配置网格权重以支持响应式布局
        container.grid_columnconfigure(0, weight=1)

    def create_decrypt_ui(self):
        # 创建解密界面的主框架
        container = ttk.Frame(self.decrypt_frame)
        container.grid(row=0, column=0, padx=20, pady=20, sticky="nsew")
        self.decrypt_frame.configure(padding=(10, 10))  # 设置框架内边距

        # 密钥长度选择区域
        ttk.Label(container, text="选择密钥长度:", font=("Helvetica", 12, "bold")).grid(row=0, column=0, sticky="w",
                                                                                        pady=5)
        self.decrypt_key_length = tk.StringVar(value="128")  # 默认选择128位密钥

        key_lengths = [("128位（16字节）", "128"), ("192位（24字节）", "192"), ("256位（32字节）", "256")]
        for i, (text, value) in enumerate(key_lengths):
            ttk.Radiobutton(container, text=text, variable=self.decrypt_key_length, value=value).grid(row=i + 1,
                                                                                                      column=0,
                                                                                                      sticky="w",
                                                                                                      padx=10, pady=2)

        # 密钥输入区域
        ttk.Label(container, text="密钥:", font=("Helvetica", 12, "bold")).grid(row=4, column=0, sticky="w", pady=5)
        self.decrypt_key_entry = ttk.Entry(container, width=50, font=("Helvetica", 10))
        self.decrypt_key_entry.grid(row=5, column=0, sticky="ew", pady=5)

        # 密文输入区域
        ttk.Label(container, text="密文 (十六进制):", font=("Helvetica", 12, "bold")).grid(row=6, column=0, sticky="w",
                                                                                           pady=5)
        self.decrypt_input_text = tk.Text(container, height=6, width=50, font=("Helvetica", 10), relief="sunken",
                                          borderwidth=2)
        self.decrypt_input_text.grid(row=7, column=0, sticky="ew", pady=5)
        scrollbar_input = ttk.Scrollbar(container, orient="vertical", command=self.decrypt_input_text.yview)
        scrollbar_input.grid(row=7, column=1, sticky="ns", pady=5)
        self.decrypt_input_text.config(yscrollcommand=scrollbar_input.set)  # 配置输入文本框的滚动条

        # 解密按钮
        self.style.configure("Accent.TButton", background="#4CAF50", foreground="white")  # 设置绿色按钮样式
        ttk.Button(container, text="解密", command=self.decrypt, style="Accent.TButton").grid(row=8, column=0, pady=10)

        # 明文输出区域
        ttk.Label(container, text="明文:", font=("Helvetica", 12, "bold")).grid(row=9, column=0, sticky="w", pady=5)
        self.decrypt_output_text = tk.Text(container, height=6, width=50, font=("Helvetica", 10), relief="sunken",
                                           borderwidth=2)
        self.decrypt_output_text.grid(row=10, column=0, sticky="ew", pady=5)
        scrollbar_output = ttk.Scrollbar(container, orient="vertical", command=self.decrypt_output_text.yview)
        scrollbar_output.grid(row=10, column=1, sticky="ns", pady=5)
        self.decrypt_output_text.config(yscrollcommand=scrollbar_output.set)  # 配置输出文本框的滚动条

        # 配置网格权重以支持响应式布局
        container.grid_columnconfigure(0, weight=1)

    def encrypt(self):
        # 获取用户输入
        key_length = int(self.encrypt_key_length.get())
        key = self.encrypt_key_entry.get().encode()  # 密钥编码为字节
        plaintext = self.encrypt_input_text.get("1.0", tk.END).strip().encode()  # 明文编码为字节

        # 验证密钥长度
        if key_length == 128 and len(key) != 16:
            messagebox.showerror("错误", "128位密钥必须是16字节")
            return
        elif key_length == 192 and len(key) != 24:
            messagebox.showerror("错误", "192位密钥必须是24字节")
            return
        elif key_length == 256 and len(key) != 32:
            messagebox.showerror("错误", "256位密钥必须是32字节")
            return

        # 计算nk（密钥字数）和nr（轮数）
        nk = key_length // 32  # 128位=4字，192位=6字，256位=8字
        nr = nk + 6  # 轮数：10（128位），12（192位），14（256位）
        ciphertext = aes_cbc_encrypt(plaintext, key, nk, nr)  # 执行CBC加密
        self.encrypt_output_text.delete("1.0", tk.END)
        self.encrypt_output_text.insert(tk.END, ciphertext.hex())  # 输出十六进制密文

    def decrypt(self):
        # 获取用户输入
        key_length = int(self.decrypt_key_length.get())
        key = self.decrypt_key_entry.get().encode()  # 密钥编码为字节
        ciphertext_hex = self.decrypt_input_text.get("1.0", tk.END).strip()  # 获取十六进制密文

        # 验证密钥长度
        if key_length == 128 and len(key) != 16:
            messagebox.showerror("错误", "128位密钥必须是16字节")
            return
        elif key_length == 192 and len(key) != 24:
            messagebox.showerror("错误", "192位密钥必须是24字节")
            return
        elif key_length == 256 and len(key) != 32:
            messagebox.showerror("错误", "256位密钥必须是32字节")
            return

        # 转换十六进制密文为字节
        try:
            ciphertext = bytes.fromhex(ciphertext_hex)
        except ValueError:
            messagebox.showerror("错误", "无效的十六进制输入")
            return

        # 计算nk和nr
        nk = key_length // 32
        nr = nk + 6
        plaintext = aes_cbc_decrypt(ciphertext, key, nk, nr)  # 执行CBC解密
        self.decrypt_output_text.delete("1.0", tk.END)
        self.decrypt_output_text.insert(tk.END, plaintext.decode())  # 输出解密后的明文


if __name__ == "__main__":
    root = tk.Tk()  # 创建主窗口
    app = AESApp(root)  # 初始化应用
    root.mainloop()  # 运行主循环
