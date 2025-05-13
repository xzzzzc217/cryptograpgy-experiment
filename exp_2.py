# -*- coding: utf-8 -*-

import tkinter as tk
from tkinter import ttk, messagebox

# -------------------- DES 算法部分 --------------------
# 初始置换表 IP
IP = [58, 50, 42, 34, 26, 18, 10, 2,
      60, 52, 44, 36, 28, 20, 12, 4,
      62, 54, 46, 38, 30, 22, 14, 6,
      64, 56, 48, 40, 32, 24, 16, 8,
      57, 49, 41, 33, 25, 17, 9, 1,
      59, 51, 43, 35, 27, 19, 11, 3,
      61, 53, 45, 37, 29, 21, 13, 5,
      63, 55, 47, 39, 31, 23, 15, 7]

# 逆初始置换表 FP
FP = [40, 8, 48, 16, 56, 24, 64, 32,
      39, 7, 47, 15, 55, 23, 63, 31,
      38, 6, 46, 14, 54, 22, 62, 30,
      37, 5, 45, 13, 53, 21, 61, 29,
      36, 4, 44, 12, 52, 20, 60, 28,
      35, 3, 43, 11, 51, 19, 59, 27,
      34, 2, 42, 10, 50, 18, 58, 26,
      33, 1, 41, 9, 49, 17, 57, 25]

# 扩展置换表 E
E = [32, 1, 2, 3, 4, 5,
     4, 5, 6, 7, 8, 9,
     8, 9, 10, 11, 12, 13,
     12, 13, 14, 15, 16, 17,
     16, 17, 18, 19, 20, 21,
     20, 21, 22, 23, 24, 25,
     24, 25, 26, 27, 28, 29,
     28, 29, 30, 31, 32, 1]

# 8 个 S-Box
S_BOX = [
    # S1
    [[14,4,13,1,2,15,11,8,3,10,6,12,5,9,0,7],
     [0,15,7,4,14,2,13,1,10,6,12,11,9,5,3,8],
     [4,1,14,8,13,6,2,11,15,12,9,7,3,10,5,0],
     [15,12,8,2,4,9,1,7,5,11,3,14,10,0,6,13]],

    # S2
    [[15,1,8,14,6,11,3,4,9,7,2,13,12,0,5,10],
     [3,13,4,7,15,2,8,14,12,0,1,10,6,9,11,5],
     [0,14,7,11,10,4,13,1,5,8,12,6,9,3,2,15],
     [13,8,10,1,3,15,4,2,11,6,7,12,0,5,14,9]],

    # S3
    [[10,0,9,14,6,3,15,5,1,13,12,7,11,4,2,8],
     [13,7,0,9,3,4,6,10,2,8,5,14,12,11,15,1],
     [13,6,4,9,8,15,3,0,11,1,2,12,5,10,14,7],
     [1,10,13,0,6,9,8,7,4,15,14,3,11,5,2,12]],

    # S4
    [[7,13,14,3,0,6,9,10,1,2,8,5,11,12,4,15],
     [13,8,11,5,6,15,0,3,4,7,2,12,1,10,14,9],
     [10,6,9,0,12,11,7,13,15,1,3,14,5,2,8,4],
     [3,15,0,6,10,1,13,8,9,4,5,11,12,7,2,14]],

    # S5
    [[2,12,4,1,7,10,11,6,8,5,3,15,13,0,14,9],
     [14,11,2,12,4,7,13,1,5,0,15,10,3,9,8,6],
     [4,2,1,11,10,13,7,8,15,9,12,5,6,3,0,14],
     [11,8,12,7,1,14,2,13,6,15,0,9,10,4,5,3]],

    # S6
    [[12,1,10,15,9,2,6,8,0,13,3,4,14,7,5,11],
     [10,15,4,2,7,12,9,5,6,1,13,14,0,11,3,8],
     [9,14,15,5,2,8,12,3,7,0,4,10,1,13,11,6],
     [4,3,2,12,9,5,15,10,11,14,1,7,6,0,8,13]],

    # S7
    [[4,11,2,14,15,0,8,13,3,12,9,7,5,10,6,1],
     [13,0,11,7,4,9,1,10,14,3,5,12,2,15,8,6],
     [1,4,11,13,12,3,7,14,10,15,6,8,0,5,9,2],
     [6,11,13,8,1,4,10,7,9,5,0,15,14,2,3,12]],

    # S8
    [[13,2,8,4,6,15,11,1,10,9,3,14,5,0,12,7],
     [1,15,13,8,10,3,7,4,12,5,6,11,0,14,9,2],
     [7,11,4,1,9,12,14,2,0,6,10,13,15,3,5,8],
     [2,1,14,7,4,10,8,13,15,12,9,0,3,5,6,11]]
]

# P 置换表
P = [16,7,20,21,
     29,12,28,17,
     1,15,23,26,
     5,18,31,10,
     2,8,24,14,
     32,27,3,9,
     19,13,30,6,
     22,11,4,25]

# 密钥置换表 PC-1
PC_1 = [57,49,41,33,25,17,9,
        1,58,50,42,34,26,18,
        10,2,59,51,43,35,27,
        19,11,3,60,52,44,36,
        63,55,47,39,31,23,15,
        7,62,54,46,38,30,22,
        14,6,61,53,45,37,29,
        21,13,5,28,20,12,4]

# 密钥置换表 PC-2
PC_2 = [14,17,11,24,1,5,
        3,28,15,6,21,10,
        23,19,12,4,26,8,
        16,7,27,20,13,2,
        41,52,31,37,47,55,
        30,40,51,45,33,48,
        44,49,39,56,34,53,
        46,42,50,36,29,32]

# 左移位数
SHIFT = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1]


def string_to_bit_array(text):
    """
    将字符串转换为比特数组。

    参数:
        text (str): 输入的字符串

    返回:
        list: 比特列表，每个字符转换为8位二进制数
    """
    array = []
    for char in text:
        # 将字符的ASCII码转换为二进制，去掉前缀"0b"，并用0填充至8位
        binval = bin(ord(char))[2:].rjust(8, '0')
        # 将二进制字符串的每一位转换为整数并添加到数组
        array.extend([int(x) for x in binval])
    return array


def bit_array_to_string(array):
    """
    将比特数组转换回字符串。

    参数:
        array (list): 比特列表

    返回:
        str: 转换后的字符串，每8位转换为一个字符
    """
    res = ""
    # 每8位处理一次
    for i in range(0, len(array), 8):
        byte = array[i:i + 8]
        # 将8个比特拼接成字符串
        s = "".join(str(bit) for bit in byte)
        # 将二进制字符串转换为整数，再转为字符
        res += chr(int(s, 2))
    return res


def permute(block, table):
    """
    根据给定的置换表对比特块进行置换。

    参数:
        block (list): 输入的比特块
        table (list): 置换表，指定新位置

    返回:
        list: 置换后的比特块
    """
    # 根据置换表重新排列比特，注意table中的索引从1开始，故减1
    return [block[x - 1] for x in table]


def xor(t1, t2):
    """
    对两个比特列表进行异或操作。

    参数:
        t1 (list): 第一个比特列表
        t2 (list): 第二个比特列表

    返回:
        list: 异或结果
    """
    # 使用zip配对两个列表的元素，进行异或操作
    return [x ^ y for x, y in zip(t1, t2)]


def left_shift(array, n):
    """
    将比特数组向左循环移位n位。

    参数:
        array (list): 输入的比特数组
        n (int): 移位数

    返回:
        list: 移位后的比特数组
    """
    # 循环左移：将前n位移到末尾
    return array[n:] + array[:n]


# -------------------- 子密钥生成 --------------------
def generate_subkeys(key):
    """
    生成16个DES子密钥。

    参数:
        key (str): 8字符的密钥

    返回:
        list: 包含16个子密钥的列表，每个子密钥为48位比特列表

    异常:
        ValueError: 如果密钥长度不为8个字符
    """
    if len(key) != 8:
        raise ValueError("密钥长度必须为8个字符！")
    # 将密钥字符串转换为64位比特数组
    key_bits = string_to_bit_array(key)
    # 使用PC_1表将64位密钥置换为56位
    key_permuted = permute(key_bits, PC_1)
    # 将56位分为左右两半，各28位
    left = key_permuted[:28]
    right = key_permuted[28:]
    subkeys = []
    # 根据SHIFT表进行16轮子密钥生成
    for shift in SHIFT:
        # 左右两半分别左移
        left = left_shift(left, shift)
        right = left_shift(right, shift)
        # 合并左右两半
        combined = left + right
        # 使用PC_2表从56位中选出48位作为子密钥
        subkey = permute(combined, PC_2)
        subkeys.append(subkey)
    return subkeys


# -------------------- DES轮函数 --------------------
def des_round(left, right, subkey):
    """
    执行一轮DES加密。

    参数:
        left (list): 32位左半部分
        right (list): 32位右半部分
        subkey (list): 48位子密钥

    返回:
        list: 新右半部分（32位）
    """
    # 将右半部分从32位扩展到48位
    right_expanded = permute(right, E)
    # 与子密钥进行异或
    xored = xor(right_expanded, subkey)
    sbox_result = []
    # 处理8个6位块，通过S盒转换为4位
    for i in range(8):
        block = xored[i * 6:(i + 1) * 6]
        # 计算S盒的行号（首尾位）和列号（中间4位）
        row = (block[0] << 1) + block[5]
        col = (block[1] << 3) + (block[2] << 2) + (block[3] << 1) + block[4]
        # 从S盒中查找值
        val = S_BOX[i][row][col]
        # 将值转换为4位二进制
        binval = bin(val)[2:].rjust(4, '0')
        sbox_result += [int(x) for x in binval]
    # 对S盒输出进行P置换
    sbox_result = permute(sbox_result, P)
    # 左半部分与S盒输出异或，生成新右半部分
    new_right = xor(left, sbox_result)
    return new_right


# -------------------- DES加解密 --------------------
def des_encrypt_block(block, subkeys):
    """
    对一个64位块进行DES加密。

    参数:
        block (list): 64位比特块
        subkeys (list): 16个子密钥

    返回:
        list: 加密后的64位比特块
    """
    # 初始置换
    block = permute(block, IP)
    # 分成左右两半，各32位
    left = block[:32]
    right = block[32:]
    # 16轮加密
    for i in range(16):
        temp = right
        right = des_round(left, right, subkeys[i])
        left = temp
    # 合并时交换左右顺序
    combined = right + left
    # 最终置换
    ciphertext = permute(combined, FP)
    return ciphertext


def des_decrypt_block(block, subkeys):
    """
    对一个64位块进行DES解密。

    参数:
        block (list): 64位密文比特块
        subkeys (list): 16个子密钥

    返回:
        list: 解密后的64位比特块
    """
    # 解密与加密相同，只是子密钥顺序逆转
    return des_encrypt_block(block, subkeys[::-1])


# -------------------- 填充和去填充 --------------------
def pad(text):
    """
    对明文进行PKCS#5填充，使长度为8的倍数。

    参数:
        text (str): 输入明文

    返回:
        str: 填充后的明文
    """
    pad_len = 8 - (len(text) % 8)
    # 填充字符为填充长度值
    return text + chr(pad_len) * pad_len


def unpad(text):
    """
    去除PKCS#5填充。

    参数:
        text (str): 带填充的字符串

    返回:
        str: 去除填充后的字符串
    """
    pad_len = ord(text[-1])
    return text[:-pad_len]


# -------------------- 加密和解密函数 --------------------
def encrypt(plaintext, key):
    """
    对明文进行DES加密。

    参数:
        plaintext (str): 明文
        key (str): 8字符密钥

    返回:
        str: 密文
    """
    # 生成子密钥
    subkeys = generate_subkeys(key)
    # 填充明文
    padded_text = pad(plaintext)
    ciphertext = ""
    # 按8字节块处理
    for i in range(0, len(padded_text), 8):
        block = padded_text[i:i + 8]
        block_bits = string_to_bit_array(block)
        encrypted_bits = des_encrypt_block(block_bits, subkeys)
        ciphertext += bit_array_to_string(encrypted_bits)
    return ciphertext


def decrypt(ciphertext, key):
    """
    对密文进行DES解密。

    参数:
        ciphertext (str): 密文
        key (str): 8字符密钥

    返回:
        str: 解密后的明文
    """
    # 生成子密钥
    subkeys = generate_subkeys(key)
    plaintext = ""
    # 按8字节块处理
    for i in range(0, len(ciphertext), 8):
        block = ciphertext[i:i + 8]
        block_bits = string_to_bit_array(block)
        decrypted_bits = des_decrypt_block(block_bits, subkeys)
        plaintext += bit_array_to_string(decrypted_bits)
    # 去除填充
    return unpad(plaintext)


# -------------------- Tkinter UI 部分 --------------------
class DESGUI(tk.Tk):
    """DES加密解密的图形用户界面类"""

    def __init__(self):
        """初始化GUI窗口"""
        super().__init__()
        self.title("DES 加解密")  # 设置窗口标题
        self.geometry("600x500")  # 设置窗口大小
        self.create_widgets()  # 创建界面控件

    def create_widgets(self):
        """创建GUI中的所有控件"""
        # 创建Notebook作为标签页容器
        notebook = ttk.Notebook(self)
        notebook.pack(fill=tk.BOTH, expand=True)

        # 加密页面
        self.frame_encrypt = ttk.Frame(notebook)
        notebook.add(self.frame_encrypt, text="加密")

        # 解密页面
        self.frame_decrypt = ttk.Frame(notebook)
        notebook.add(self.frame_decrypt, text="解密")

        # ----------------- 加密页面控件 -----------------
        # 密钥输入标签和输入框
        lbl_key_enc = ttk.Label(self.frame_encrypt, text="密钥 (8字符):")
        lbl_key_enc.grid(row=0, column=0, padx=5, pady=5, sticky=tk.W)
        self.entry_key_enc = ttk.Entry(self.frame_encrypt, width=30)
        self.entry_key_enc.grid(row=0, column=1, padx=5, pady=5)

        # 明文输入标签和文本框
        lbl_plaintext = ttk.Label(self.frame_encrypt, text="明文:")
        lbl_plaintext.grid(row=1, column=0, padx=5, pady=5, sticky=tk.NW)
        self.text_plaintext = tk.Text(self.frame_encrypt, width=50, height=10)
        self.text_plaintext.grid(row=1, column=1, padx=5, pady=5)

        # 加密按钮
        btn_encrypt = ttk.Button(self.frame_encrypt, text="加密", command=self.do_encrypt)
        btn_encrypt.grid(row=2, column=1, padx=5, pady=5, sticky=tk.E)

        # 密文输出标签和文本框
        lbl_ciphertext = ttk.Label(self.frame_encrypt, text="密文 (16进制):")
        lbl_ciphertext.grid(row=3, column=0, padx=5, pady=5, sticky=tk.NW)
        self.text_ciphertext = tk.Text(self.frame_encrypt, width=50, height=10)
        self.text_ciphertext.grid(row=3, column=1, padx=5, pady=5)
        self.text_ciphertext.configure(state="disabled")  # 初始为只读

        # ----------------- 解密页面控件 -----------------
        # 密钥输入标签和输入框
        lbl_key_dec = ttk.Label(self.frame_decrypt, text="密钥 (8字符):")
        lbl_key_dec.grid(row=0, column=0, padx=5, pady=5, sticky=tk.W)
        self.entry_key_dec = ttk.Entry(self.frame_decrypt, width=30)
        self.entry_key_dec.grid(row=0, column=1, padx=5, pady=5)

        # 密文输入标签和文本框
        lbl_hex_cipher = ttk.Label(self.frame_decrypt, text="密文 (16进制):")
        lbl_hex_cipher.grid(row=1, column=0, padx=5, pady=5, sticky=tk.NW)
        self.text_hex_cipher = tk.Text(self.frame_decrypt, width=50, height=10)
        self.text_hex_cipher.grid(row=1, column=1, padx=5, pady=5)

        # 解密按钮
        btn_decrypt = ttk.Button(self.frame_decrypt, text="解密", command=self.do_decrypt)
        btn_decrypt.grid(row=2, column=1, padx=5, pady=5, sticky=tk.E)

        # 明文输出标签和文本框
        lbl_plain_dec = ttk.Label(self.frame_decrypt, text="明文:")
        lbl_plain_dec.grid(row=3, column=0, padx=5, pady=5, sticky=tk.NW)
        self.text_plain_dec = tk.Text(self.frame_decrypt, width=50, height=10)
        self.text_plain_dec.grid(row=3, column=1, padx=5, pady=5)
        self.text_plain_dec.configure(state="disabled")  # 初始为只读

    def do_encrypt(self):
        """执行加密操作"""
        key = self.entry_key_enc.get()  # 获取密钥
        plaintext = self.text_plaintext.get("1.0", tk.END).rstrip("\n")  # 获取明文
        if len(key) != 8:
            messagebox.showerror("错误", "密钥长度必须为8个字符！")
            return
        try:
            cipher = encrypt(plaintext, key)  # 加密
            # 将密文转换为十六进制字符串
            hex_cipher = cipher.encode("utf-8").hex()
            # 更新密文文本框
            self.text_ciphertext.configure(state="normal")
            self.text_ciphertext.delete("1.0", tk.END)
            self.text_ciphertext.insert(tk.END, hex_cipher)
            self.text_ciphertext.configure(state="disabled")
        except Exception as e:
            messagebox.showerror("加密错误", str(e))

    def do_decrypt(self):
        """执行解密操作"""
        key = self.entry_key_dec.get()  # 获取密钥
        hex_cipher = self.text_hex_cipher.get("1.0", tk.END).strip()  # 获取十六进制密文
        if len(key) != 8:
            messagebox.showerror("错误", "密钥长度必须为8个字符！")
            return
        try:
            # 将十六进制密文转换为字符串
            cipher = bytes.fromhex(hex_cipher).decode("utf-8")
            plain = decrypt(cipher, key)  # 解密
            # 更新明文文本框
            self.text_plain_dec.configure(state="normal")
            self.text_plain_dec.delete("1.0", tk.END)
            self.text_plain_dec.insert(tk.END, plain)
            self.text_plain_dec.configure(state="disabled")
        except Exception as e:
            messagebox.showerror("解密错误", str(e))


# -------------------- 程序入口 --------------------
if __name__ == "__main__":
    """程序主入口，创建并运行GUI"""
    app = DESGUI()
    app.mainloop()