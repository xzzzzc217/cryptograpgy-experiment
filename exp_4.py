import tkinter as tk
from tkinter import messagebox

def extended_gcd(a, b):
    # 初始化
    x2, x1 = 1, 0
    y2, y1 = 0, 1
    a_original, b_original = a, b  # 保存原始的 a 和 b

    # 当 b 不为 0 时，执行算法循环
    while b > 0:
        # 计算商 q 和余数 r
        q = a // b
        r = a - q * b
        # 更新 x 和 y
        x = x2 - q * x1
        y = y2 - q * y1
        # 更新 a, b 和 x2, x1, y2, y1
        a, b = b, r
        x2, x1 = x1, x
        y2, y1 = y1, y
    # 循环结束后，a 是最大公约数 d，x2 和 y2 是对应的 x 和 y
    d = a
    x, y = x2, y2
    return d, x, y

# 计算模乘逆元
def mod_inverse(a, m):
    d, x, y = extended_gcd(a, m)
    if d != 1:  # 如果 gcd(a, m) != 1，则模逆元不存在
        return None
    # 确保 x 在 [0, m) 范围内
    x = x % m
    if x < 0:
        x += m
    return x

# 定义计算按钮的回调函数
def calculate(mode):
    try:
        # 获取用户输入的 a 和 b
        a = int(entry_a.get())
        b = int(entry_b.get())

        # 检查输入是否为正整数
        if a <= 0 or b <= 0:
            messagebox.showerror("输入错误", "请输入正整数！")
            return

        if mode == "gcd":
            # 确保 a >= b
            if a < b:
                a, b = b, a
            # 调用扩展欧几里得算法
            d, x, y = extended_gcd(a, b)
            # 显示结果
            result_text.set(f"最大公约数 d = {d}\n满足 {a}x + {b}y = {d} 的解为:\nx = {x}, y = {y}")
        elif mode == "mod_inverse":
            # 计算模乘逆元（a 是被求逆的数，b 是模数 m）
            inverse = mod_inverse(a, b)
            if inverse is None:
                result_text.set(f"{a} 在模 {b} 下没有模乘逆元\n（因为 gcd({a}, {b}) ≠ 1）")
            else:
                result_text.set(f"{a} 在模 {b} 下的模乘逆元为:\nx = {inverse}")
    except ValueError:
        messagebox.showerror("输入错误", "请输入有效的整数！")

# 创建主窗口
window = tk.Tk()
window.title("扩展欧几里得算法计算器")
window.geometry("450x400")
window.configure(bg="#f0f4f8")  # 设置背景颜色

# 创建标题标签
title_label = tk.Label(window, text="扩展欧几里得算法计算器", font=("Arial", 16, "bold"), bg="#f0f4f8", fg="#333")
title_label.pack(pady=15)

# 创建输入框架
input_frame = tk.Frame(window, bg="#f0f4f8")
input_frame.pack(pady=10)

# 创建输入标签和输入框
label_a = tk.Label(input_frame, text="请输入正整数 a:", font=("Arial", 12), bg="#f0f4f8", fg="#333")
label_a.grid(row=0, column=0, padx=10, pady=5, sticky="e")
entry_a = tk.Entry(input_frame, font=("Arial", 12), width=15, bd=2, relief="groove")
entry_a.grid(row=0, column=1, padx=10, pady=5)

label_b = tk.Label(input_frame, text="请输入正整数 b (或模数 m):", font=("Arial", 12), bg="#f0f4f8", fg="#333")
label_b.grid(row=1, column=0, padx=10, pady=5, sticky="e")
entry_b = tk.Entry(input_frame, font=("Arial", 12), width=15, bd=2, relief="groove")
entry_b.grid(row=1, column=1, padx=10, pady=5)

# 创建按钮框架
button_frame = tk.Frame(window, bg="#f0f4f8")
button_frame.pack(pady=10)

# 创建计算按钮
calc_gcd_button = tk.Button(button_frame, text="计算 GCD", font=("Arial", 12), bg="#4CAF50", fg="white", bd=2, relief="raised", command=lambda: calculate("gcd"))
calc_gcd_button.grid(row=0, column=0, padx=10)

calc_mod_inverse_button = tk.Button(button_frame, text="计算模逆元", font=("Arial", 12), bg="#2196F3", fg="white", bd=2, relief="raised", command=lambda: calculate("mod_inverse"))
calc_mod_inverse_button.grid(row=0, column=1, padx=10)

# 创建结果显示区域
result_text = tk.StringVar()
result_label = tk.Label(window, textvariable=result_text, font=("Arial", 12), bg="#ffffff", fg="#333", bd=2, relief="sunken", width=40, height=5, anchor="nw", justify="left", padx=10, pady=10)
result_label.pack(pady=10)

# 启动主循环
window.mainloop()