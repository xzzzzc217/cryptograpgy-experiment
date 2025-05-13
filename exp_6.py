import tkinter as tk
from tkinter import messagebox, scrolledtext
import random
from math import pow
import base64


class ElGamal:
    def __init__(self):
        # 初始化大素数 p 和生成元 g
        self.p = 7919  # 默认大素数
        self.g = 2  # 生成元
        self.x = None  # 私钥
        self.y = None  # 公钥

    def is_prime(self, n):
        # 判断一个数是否为素数
        if n < 2:
            return False
        for i in range(2, int(n ** 0.5) + 1):
            if n % i == 0:
                return False
        return True

    def update_prime(self, new_p):
        # 更新大素数 p，并验证其是否为素数
        try:
            new_p = int(new_p)
            if self.is_prime(new_p):
                self.p = new_p
                self.x = None  # 重置私钥
                self.y = None  # 重置公钥
                return True
            else:
                return False
        except ValueError:
            return False

    def generate_keys(self):
        # 生成私钥（随机数）
        self.x = random.randint(1, self.p - 2)
        # 计算公钥 y = g^x mod p
        self.y = self.mod_pow(self.g, self.x, self.p)
        return self.p, self.g, self.y, self.x

    def mod_pow(self, base, exponent, modulus):
        # 模幂运算，用于快速计算大数幂
        result = 1
        base = base % modulus
        while exponent > 0:
            if exponent & 1:
                result = (result * base) % modulus
            exponent = exponent >> 1
            base = (base * base) % modulus
        return result

    def encrypt(self, plaintext):
        # 将明文转换为字节
        plaintext_bytes = plaintext.encode('utf-8')
        # 将字节转换为Base64以便处理
        plaintext_b64 = base64.b64encode(plaintext_bytes).decode('utf-8')
        ciphertext = []

        # 对每个字符进行加密
        for char in plaintext_b64:
            k = random.randint(1, self.p - 2)  # 随机选择k
            # 计算 c1 = g^k mod p
            c1 = self.mod_pow(self.g, k, self.p)
            # 计算 c2 = (y^k * m) mod p，其中 m 是字符的ASCII值
            c2 = (self.mod_pow(self.y, k, self.p) * ord(char)) % self.p
            ciphertext.append((c1, c2))

        return ciphertext

    def decrypt(self, ciphertext):
        # 解密
        plaintext_b64 = ""
        for c1, c2 in ciphertext:
            # 计算 s = c1^x mod p
            s = self.mod_pow(c1, self.x, self.p)
            # 计算 s的模逆
            s_inv = self.mod_inverse(s, self.p)
            # 计算 m = (c2 * s_inv) mod p
            m = (c2 * s_inv) % self.p
            plaintext_b64 += chr(m)

        # 将Base64字符串解码回字节，再转换为字符串
        try:
            plaintext_bytes = base64.b64decode(plaintext_b64)
            return plaintext_bytes.decode('utf-8')
        except:
            return "解密失败：密文无效或密钥不匹配"

    def mod_inverse(self, a, m):
        # 计算模逆
        def extended_gcd(a, b):
            if a == 0:
                return b, 0, 1
            gcd, x1, y1 = extended_gcd(b % a, a)
            x = y1 - (b // a) * x1
            y = x1
            return gcd, x, y

        _, x, _ = extended_gcd(a, m)
        return (x % m + m) % m


class ElGamalGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("ElGamal 加解密系统")
        self.root.geometry("600x750")
        self.elgamal = ElGamal()

        # 设置窗口样式
        self.root.configure(bg="#f0f0f0")

        # 创建主框架
        self.frame = tk.Frame(self.root, bg="#f0f0f0")
        self.frame.pack(padx=20, pady=20, fill="both", expand=True)

        # 标题
        tk.Label(self.frame, text="ElGamal 加解密", font=("Arial", 16, "bold"), bg="#f0f0f0").pack(pady=10)

        # 更新大素数 p 输入框和按钮
        tk.Label(self.frame, text="输入新的大素数 p:", bg="#f0f0f0", font=("Arial", 10)).pack(anchor="w")
        self.prime_input = tk.Entry(self.frame, width=20, font=("Arial", 10))
        self.prime_input.pack(anchor="w", pady=5)
        tk.Button(self.frame, text="更新大素数 p", command=self.update_prime, bg="#FF5722", fg="white",
                  font=("Arial", 10)).pack(anchor="w", pady=5)

        # 密钥生成按钮
        tk.Button(self.frame, text="生成密钥对", command=self.generate_keys, bg="#4CAF50", fg="white",
                  font=("Arial", 10)).pack(pady=5)

        # 密钥显示区域
        self.key_display = scrolledtext.ScrolledText(self.frame, height=4, width=60, font=("Arial", 10))
        self.key_display.pack(pady=5)
        self.key_display.config(state='disabled')

        # 明文输入
        tk.Label(self.frame, text="输入明文:", bg="#f0f0f0", font=("Arial", 10)).pack(anchor="w")
        self.plaintext_input = scrolledtext.ScrolledText(self.frame, height=3, width=60, font=("Arial", 10))
        self.plaintext_input.pack(pady=5)

        # 加密按钮
        tk.Button(self.frame, text="加密", command=self.encrypt, bg="#2196F3", fg="white", font=("Arial", 10)).pack(
            pady=5)

        # 密文显示
        tk.Label(self.frame, text="密文:", bg="#f0f0f0", font=("Arial", 10)).pack(anchor="w")
        self.ciphertext_display = scrolledtext.ScrolledText(self.frame, height=3, width=60, font=("Arial", 10))
        self.ciphertext_display.pack(pady=5)
        self.ciphertext_display.config(state='disabled')

        # 密文输入
        tk.Label(self.frame, text="输入密文 (格式: c1 c2 c1 c2 ... 的16进制序列):", bg="#f0f0f0", font=("Arial", 10)).pack(anchor="w")
        self.ciphertext_input = scrolledtext.ScrolledText(self.frame, height=3, width=60, font=("Arial", 10))
        self.ciphertext_input.pack(pady=5)

        # 解密按钮
        tk.Button(self.frame, text="解密", command=self.decrypt, bg="#FF9800", fg="white", font=("Arial", 10)).pack(
            pady=5)

        # 解密结果显示
        tk.Label(self.frame, text="解密结果:", bg="#f0f0f0", font=("Arial", 10)).pack(anchor="w")
        self.decrypt_display = scrolledtext.ScrolledText(self.frame, height=3, width=60, font=("Arial", 10))
        self.decrypt_display.pack(pady=5)
        self.decrypt_display.config(state='disabled')

    def update_prime(self):
        # 更新大素数 p
        new_p = self.prime_input.get().strip()
        if self.elgamal.update_prime(new_p):
            messagebox.showinfo("成功", f"大素数 p 已更新为 {self.elgamal.p}")
            self.key_display.config(state='normal')
            self.key_display.delete(1.0, tk.END)
            self.key_display.insert(tk.END, f"新的大素数 p: {self.elgamal.p}\n请重新生成密钥对")
            self.key_display.config(state='disabled')
        else:
            messagebox.showerror("错误", "请输入一个有效的素数！")

    def generate_keys(self):
        # 生成密钥对并显示
        p, g, y, x = self.elgamal.generate_keys()
        key_info = f"公共参数:\n素数 p: {p}\n生成元 g: {g}\n公钥 y: {y}\n私钥 x: {x}"
        self.key_display.config(state='normal')
        self.key_display.delete(1.0, tk.END)
        self.key_display.insert(tk.END, key_info)
        self.key_display.config(state='disabled')

    def encrypt(self):
        # 加密明文
        plaintext = self.plaintext_input.get(1.0, tk.END).strip()
        if not plaintext:
            messagebox.showerror("错误", "请输入明文！")
            return
        if not self.elgamal.y:
            messagebox.showerror("错误", "请先生成密钥对！")
            return

        ciphertext = self.elgamal.encrypt(plaintext)
        # 将密文格式化为以空格分隔的16进制字符串
        cipher_text = ' '.join(f"{c1:04x} {c2:04x}" for c1, c2 in ciphertext)
        self.ciphertext_display.config(state='normal')
        self.ciphertext_display.delete(1.0, tk.END)
        self.ciphertext_display.insert(tk.END, cipher_text)
        self.ciphertext_display.config(state='disabled')

    def decrypt(self):
        # 解密密文
        ciphertext_str = self.ciphertext_input.get(1.0, tk.END).strip()
        if not ciphertext_str:
            messagebox.showerror("错误", "请输入密文！")
            return
        if not self.elgamal.x:
            messagebox.showerror("错误", "请先生成密钥对！")
            return

        try:
            # 解析以空格分隔的16进制字符串为 (c1, c2) 元组列表
            cipher_numbers = [int(num, 16) for num in ciphertext_str.split()]
            if len(cipher_numbers) % 2 != 0:
                raise ValueError("密文格式错误：数字数量必须为偶数！")
            ciphertext = [(cipher_numbers[i], cipher_numbers[i+1]) for i in range(0, len(cipher_numbers), 2)]
            plaintext = self.elgamal.decrypt(ciphertext)
            self.decrypt_display.config(state='normal')
            self.decrypt_display.delete(1.0, tk.END)
            self.decrypt_display.insert(tk.END, plaintext)
            self.decrypt_display.config(state='disabled')
        except:
            messagebox.showerror("错误", "密文格式错误！请输入以空格分隔的16进制数字序列（如 c1 c2 c1 c2 ...）")


if __name__ == "__main__":
    root = tk.Tk()
    app = ElGamalGUI(root)
    root.mainloop()