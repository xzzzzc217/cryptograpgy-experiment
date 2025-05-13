import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
import random
import math


# 判断一个数是否为素数
def is_prime(n):
    if n < 2:
        return False
    for i in range(2, int(math.sqrt(n)) + 1):
        if n % i == 0:
            return False
    return True


# 生成指定范围内的随机大素数
def generate_prime(min_value, max_value):
    prime = random.randint(min_value, max_value)
    while not is_prime(prime):
        prime = random.randint(min_value, max_value)
    return prime


# 计算最大公约数（欧几里得算法）
def gcd(a, b):
    while b:
        a, b = b, a % b
    return a


# 扩展欧几里得算法，计算模逆
def mod_inverse(e, phi):
    def extended_gcd(a, b):
        if a == 0:
            return b, 0, 1
        gcd, x1, y1 = extended_gcd(b % a, a)
        x = y1 - (b // a) * x1
        y = x1
        return gcd, x, y

    _, d, _ = extended_gcd(e, phi)
    if d < 0:
        d += phi
    return d


# 生成 RSA 密钥对
def generate_keys():
    p = generate_prime(100, 1000)
    q = generate_prime(100, 1000)
    n = p * q
    phi = (p - 1) * (q - 1)

    e = random.randint(2, phi - 1)
    while gcd(e, phi) != 1:
        e = random.randint(2, phi - 1)

    d = mod_inverse(e, phi)

    return p, q, n, e, d


# 将字符串转换为数字列表（支持任意长度）
def string_to_numbers(text):
    return [ord(char) for char in text]


# 将数字列表转换回字符串
def numbers_to_string(numbers):
    return ''.join(chr(num % 256) for num in numbers)


# RSA 加密
def rsa_encrypt(plain_text, e, n):
    numbers = string_to_numbers(plain_text)
    cipher_numbers = [pow(num, e, n) for num in numbers]
    return cipher_numbers


# RSA 解密
def rsa_decrypt(cipher_numbers, d, n):
    plain_numbers = [pow(num, d, n) for num in cipher_numbers]
    return numbers_to_string(plain_numbers)


# 主窗口类
class RSAApp:
    def __init__(self, root):
        self.root = root
        self.root.title("RSA 加解密工具")
        self.root.geometry("700x800")
        self.root.configure(bg="#f0f0f0")

        # 初始化密钥
        self.p, self.q, self.n, self.e, self.d = generate_keys()

        # 设置 ttk 样式
        self.style = ttk.Style()
        try:
            self.style.theme_use("clam")  # 使用 'clam' 主题，确保跨平台兼容
        except tk.TclError:
            self.style.theme_use("default")  # 回退到默认主题
        self.style.configure("TLabelFrame", background="#f0f0f0", font=("Arial", 12, "bold"))
        self.style.configure("TButton", font=("Arial", 10), padding=10)
        self.style.configure("TLabel", background="#f0f0f0", font=("Arial", 10))
        self.style.configure("Accent.TButton", background="#4CAF50", foreground="white")
        self.style.map("Accent.TButton",
                       background=[("active", "#45a049")],
                       foreground=[("active", "white")])

        # 创建界面元素
        self.create_widgets()

        # 更新密钥显示
        self.update_key_display()

    def create_widgets(self):
        # 主容器
        main_frame = ttk.Frame(self.root, padding=20)
        main_frame.pack(fill="both", expand=True)

        # 密钥显示区域
        self.key_frame = ttk.LabelFrame(main_frame, text="🔑 密钥信息", padding=15)
        self.key_frame.pack(padx=10, pady=10, fill="x")

        self.key_display = scrolledtext.ScrolledText(
            self.key_frame, height=6, width=60, wrap=tk.WORD,
            font=("Courier New", 10), bg="#ffffff", relief="flat", borderwidth=1
        )
        self.key_display.pack(pady=5)

        # 更新密钥按钮
        self.update_key_button = ttk.Button(
            self.key_frame, text="🔄 更新 p, q", command=self.update_keys,
            style="Accent.TButton"
        )
        self.update_key_button.pack(pady=10)

        # 输入区域
        self.input_frame = ttk.LabelFrame(main_frame, text="📝 输入明文/密文", padding=15)
        self.input_frame.pack(padx=10, pady=10, fill="x")

        self.input_text = scrolledtext.ScrolledText(
            self.input_frame, height=6, width=60, wrap=tk.WORD,
            font=("Arial", 10), bg="#ffffff", relief="flat", borderwidth=1
        )
        self.input_text.pack(pady=5)

        # 按钮区域
        self.button_frame = ttk.Frame(main_frame)
        self.button_frame.pack(pady=15)

        self.encrypt_button = ttk.Button(
            self.button_frame, text="🔒 加密", command=self.encrypt,
            style="Accent.TButton"
        )
        self.encrypt_button.pack(side=tk.LEFT, padx=10)

        self.decrypt_button = ttk.Button(
            self.button_frame, text="🔓 解密", command=self.decrypt,
            style="Accent.TButton"
        )
        self.decrypt_button.pack(side=tk.LEFT, padx=10)

        # 输出区域
        self.output_frame = ttk.LabelFrame(main_frame, text="📤 输出结果", padding=15)
        self.output_frame.pack(padx=10, pady=10, fill="both", expand=True)

        self.output_text = scrolledtext.ScrolledText(
            self.output_frame, height=10, width=60, wrap=tk.WORD,
            font=("Arial", 10), bg="#ffffff", relief="flat", borderwidth=1
        )
        self.output_text.pack(pady=5)

    def update_key_display(self):
        # 更新密钥信息的显示
        key_info = (
            f"🔢 p: {self.p}\n"
            f"🔢 q: {self.q}\n"
            f"🔢 n: {self.n}\n"
            f"🔑 e (公钥): {self.e}\n"
            f"🔑 d (私钥): {self.d}"
        )
        self.key_display.delete(1.0, tk.END)
        self.key_display.insert(tk.END, key_info)

    def update_keys(self):
        # 一键更新 p, q 和相关密钥
        self.p, self.q, self.n, self.e, self.d = generate_keys()
        self.update_key_display()
        messagebox.showinfo("提示", "已成功更新 p, q 和密钥！", parent=self.root)

    def encrypt(self):
        # 执行加密操作
        plain_text = self.input_text.get(1.0, tk.END).strip()
        if not plain_text:
            messagebox.showerror("错误", "请输入明文！", parent=self.root)
            return

        cipher_numbers = rsa_encrypt(plain_text, self.e, self.n)
        # 将加密结果格式化为以空格分隔的16进制字符串
        cipher_text = ' '.join(hex(num)[2:].zfill(4) for num in cipher_numbers)
        self.output_text.delete(1.0, tk.END)
        self.output_text.insert(tk.END, cipher_text)

    def decrypt(self):
        # 执行解密操作
        cipher_text = self.input_text.get(1.0, tk.END).strip()
        if not cipher_text:
            messagebox.showerror("错误", "请输入密文！", parent=self.root)
            return

        try:
            # 解析以空格分隔的16进制字符串为整数列表
            cipher_numbers = [int(num, 16) for num in cipher_text.split()]
            plain_text = rsa_decrypt(cipher_numbers, self.d, self.n)
            self.output_text.delete(1.0, tk.END)
            self.output_text.insert(tk.END, plain_text)
        except:
            messagebox.showerror("错误", "密文格式错误！请输入以空格分隔的16进制数字序列！", parent=self.root)


# 主程序入口
if __name__ == "__main__":
    root = tk.Tk()
    app = RSAApp(root)
    root.mainloop()