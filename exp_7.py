import tkinter as tk
from tkinter import messagebox
import random
import math


def is_prime(n):
    """检查是否为素数"""
    if n < 2:
        return False
    for i in range(2, int(math.sqrt(n)) + 1):
        if n % i == 0:
            return False
    return True


def generate_prime(min_value=100, max_value=1000):
    """生成随机素数"""
    while True:
        num = random.randint(min_value, max_value)
        if is_prime(num):
            return num


def mod_pow(base, exponent, modulus):
    """快速模幂运算"""
    result = 1
    base = base % modulus
    while exponent > 0:
        if exponent & 1:
            result = (result * base) % modulus
        base = (base * base) % modulus
        exponent >>= 1
    return result


class DiffieHellmanApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Diffie-Hellman 密钥交换")
        self.root.geometry("600x500")

        # 样式设置
        self.root.configure(bg="#f0f0f0")
        self.label_font = ("Arial", 12)
        self.entry_font = ("Arial", 11)

        # 主框架
        self.frame = tk.Frame(root, bg="#f0f0f0")
        self.frame.pack(padx=20, pady=20, fill="both", expand=True)

        # 参数输入区域
        tk.Label(self.frame, text="Diffie-Hellman 参数", font=("Arial", 14, "bold"), bg="#f0f0f0").pack(pady=10)

        # 素数 p
        tk.Label(self.frame, text="素数 p:", font=self.label_font, bg="#f0f0f0").pack()
        self.p_entry = tk.Entry(self.frame, font=self.entry_font, width=20)
        self.p_entry.pack(pady=5)

        # 模原根 a
        tk.Label(self.frame, text="模原根 a:", font=self.label_font, bg="#f0f0f0").pack()
        self.a_entry = tk.Entry(self.frame, font=self.entry_font, width=20)
        self.a_entry.pack(pady=5)

        # Alice 私钥 X_a
        tk.Label(self.frame, text="Alice 私钥 X_a:", font=self.label_font, bg="#f0f0f0").pack()
        self.xa_entry = tk.Entry(self.frame, font=self.entry_font, width=20)
        self.xa_entry.pack(pady=5)

        # Bob 私钥 X_b
        tk.Label(self.frame, text="Bob 私钥 X_b:", font=self.label_font, bg="#f0f0f0").pack()
        self.xb_entry = tk.Entry(self.frame, font=self.entry_font, width=20)
        self.xb_entry.pack(pady=5)

        # 按钮框架
        button_frame = tk.Frame(self.frame, bg="#f0f0f0")
        button_frame.pack(pady=20)

        # 按钮
        tk.Button(button_frame, text="自动生成参数", command=self.generate_params,
                  font=self.label_font, bg="#4CAF50", fg="white").pack(side=tk.LEFT, padx=10)
        tk.Button(button_frame, text="计算共享密钥", command=self.calculate_key,
                  font=self.label_font, bg="#2196F3", fg="white").pack(side=tk.LEFT, padx=10)

        # 结果显示区域
        tk.Label(self.frame, text="计算结果", font=("Arial", 14, "bold"), bg="#f0f0f0").pack(pady=10)
        self.result_text = tk.Text(self.frame, height=6, width=50, font=self.entry_font)
        self.result_text.pack(pady=10)

    def generate_params(self):
        """生成随机参数"""
        p = generate_prime()
        a = random.randint(2, p - 2)  # 模原根简单随机选择
        xa = random.randint(1, p - 2)
        xb = random.randint(1, p - 2)

        self.p_entry.delete(0, tk.END)
        self.a_entry.delete(0, tk.END)
        self.xa_entry.delete(0, tk.END)
        self.xb_entry.delete(0, tk.END)

        self.p_entry.insert(0, str(p))
        self.a_entry.insert(0, str(a))
        self.xa_entry.insert(0, str(xa))
        self.xb_entry.insert(0, str(xb))

    def calculate_key(self):
        """计算共享密钥"""
        try:
            p = int(self.p_entry.get())
            a = int(self.a_entry.get())
            xa = int(self.xa_entry.get())
            xb = int(self.xb_entry.get())

            # 验证输入
            if not is_prime(p):
                messagebox.showerror("错误", "p 必须是素数！")
                return
            if a <= 1 or a >= p:
                messagebox.showerror("错误", "a 必须在 2 到 p-1 之间！")
                return
            if xa <= 0 or xa >= p:
                messagebox.showerror("错误", "X_a 必须在 1 到 p-1 之间！")
                return
            if xb <= 0 or xb >= p:
                messagebox.showerror("错误", "X_b 必须在 1 到 p-1 之间！")
                return

            # 计算公开值
            ya = mod_pow(a, xa, p)  # Alice 的公开值
            yb = mod_pow(a, xb, p)  # Bob 的公开值

            # 计算共享密钥
            key_a = mod_pow(yb, xa, p)  # Alice 计算的共享密钥
            key_b = mod_pow(ya, xb, p)  # Bob 计算的共享密钥

            # 显示结果
            self.result_text.delete(1.0, tk.END)
            self.result_text.insert(tk.END, f"Alice 的公开值 Y_a: {ya}\n")
            self.result_text.insert(tk.END, f"Bob 的公开值 Y_b: {yb}\n")
            self.result_text.insert(tk.END, f"Alice 计算的共享密钥: {key_a}\n")
            self.result_text.insert(tk.END, f"Bob 计算的共享密钥: {key_b}\n")
            self.result_text.insert(tk.END, f"验证: {'成功' if key_a == key_b else '失败'}\n")

        except ValueError:
            messagebox.showerror("错误", "请输入有效的数字！")


if __name__ == "__main__":
    root = tk.Tk()
    app = DiffieHellmanApp(root)
    root.mainloop()