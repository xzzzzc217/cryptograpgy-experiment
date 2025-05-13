import tkinter as tk
from tkinter import messagebox


def extended_gcd(a, b):
    if b == 0:
        return a, 1, 0
    else:
        gcd, x1, y1 = extended_gcd(b, a % b)
        x = y1
        y = x1 - (a // b) * y1
        return gcd, x, y


def mod_inverse(a, b):
    gcd, x, _ = extended_gcd(a, b)
    if gcd != 1:
        return None  # 模乘逆元不存在
    else:
        return x % b  # 确保结果为正数


def calculate():
    try:
        # 获取输入值
        a = int(entry_a.get())
        b = int(entry_b.get())

        # 计算GCD和乘法逆元
        gcd_result = extended_gcd(a, b)[0]  # 计算GCD
        inverse_result = None
        if gcd_result == 1:  # 如果GCD为1，则计算乘法逆元
            inverse_result = mod_inverse(a, b)

        # 显示结果
        result_text = f"GCD({a}, {b}) = {gcd_result}\n"
        if inverse_result is not None:
            result_text += f"{a} 在模 {b} 下的乘法逆元是 {inverse_result}"
        else:
            result_text += f"{a} 在模 {b} 下没有乘法逆元"

        # 弹出消息框显示结果
        messagebox.showinfo("计算结果", result_text)
    except ValueError:
        messagebox.showerror("输入错误", "请输入有效的整数！")




root = tk.Tk()
root.title("EX_GCD")

# 标签和输入框
tk.Label(root, text="输入 a:").grid(row=0, column=0)
entry_a = tk.Entry(root)
entry_a.grid(row=0, column=1)

tk.Label(root, text="输入 b:").grid(row=1, column=0)
entry_b = tk.Entry(root)
entry_b.grid(row=1, column=1)



# 计算按钮
btn_calculate = tk.Button(root, text="计算", command=calculate)
btn_calculate.grid(row=3, columnspan=2)

# 运行 GUI
root.mainloop()