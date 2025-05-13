import tkinter as tk
from tkinter import ttk
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import numpy as np
import itertools
import string


class CipherApp:

    def __init__(self, root):
        self.root = root
        self.root.title("Cipher Decryption Tool")

        # 英语字母频率
        self.english_freq = {
            'e': 12.702, 't': 9.056, 'a': 8.167, 'o': 7.507, 'i': 6.966,
            'n': 6.749, 's': 6.327, 'h': 6.094, 'r': 5.987, 'd': 4.253,
            'l': 4.025, 'c': 2.782, 'u': 2.758, 'm': 2.406, 'w': 2.360,
            'f': 2.228, 'g': 2.015, 'y': 1.974, 'p': 1.929, 'b': 1.492,
            'v': 0.978, 'k': 0.772, 'j': 0.153, 'x': 0.150, 'q': 0.095, 'z': 0.074
        }

        # 常见双字母频率
        self.bigram_freq = {
            'TH': 3.2, 'HE': 3.05, 'IN': 2.3, 'ER': 2.1, 'TE': 2.0,
            'AN': 1.9, 'ON': 1.8, 'RE': 1.7, 'AT': 1.5, 'EN': 1.5,
            'ES': 1.5, 'OR': 1.3, 'TI': 1.3, 'ED': 1.2, 'ST': 1.2
        }

        # 当前映射 (ciphertext -> plaintext)至空
        self.mappings = {}
        self.ciphertext = ""

        # 打开第一个页面
        self.create_initial_interface()

    def clear_window(self):
        """清除所有组件"""
        for widget in self.root.winfo_children():
            widget.destroy()

    def create_initial_interface(self):
        """创建欢迎界面"""
        self.clear_window()
        tk.Label(self.root, text="Welcome to Cipher Decryption Tool", font=("Arial", 16)).pack(pady=20)
        tk.Label(self.root, text="This tool helps you decrypt substitution ciphers.", font=("Arial", 12)).pack(pady=10)
        tk.Button(self.root, text="Start Decryption", font=("Arial", 12), command=self.create_decryption_interface).pack(pady=10)

    def create_decryption_interface(self):
        """界面分为左中右三个部分"""
        self.clear_window()

        # 左边展示图表
        left_frame = tk.Frame(self.root)
        left_frame.pack(side=tk.LEFT, padx=10, pady=10)

        # 中间部分做展示
        middle_frame = tk.Frame(self.root)
        middle_frame.pack(side=tk.LEFT, padx=10, pady=10)

        # 右边做映射
        right_frame = tk.Frame(self.root)
        right_frame.pack(side=tk.LEFT, padx=10, pady=10)

        # 填充各个部分
        self.create_charts(left_frame)
        self.create_input_and_display(middle_frame)
        self.mapping_entries = {}
        self.create_mapping_interface(right_frame)
        self.create_combination_feature(middle_frame)

        # 返回按钮
        tk.Button(self.root, text="返回主菜单", command=self.create_initial_interface).pack(side=tk.BOTTOM, anchor=tk.W, padx=10, pady=10)

    ### 左边部分:图表 ###
    def create_charts(self, frame):
        """创建3个图表"""
        # English字母频率表
        fig1, ax1 = plt.subplots(figsize=(5, 3))
        ax1.bar(self.english_freq.keys(), self.english_freq.values(), color='skyblue')
        ax1.set_title("English Letter Frequencies (%)")
        ax1.tick_params(axis='x', rotation=45)
        canvas1 = FigureCanvasTkAgg(fig1, master=frame)
        canvas1.draw()
        canvas1.get_tk_widget().pack(pady=5)

        # 双字母频率表
        fig2, ax2 = plt.subplots(figsize=(5, 3))
        ax2.bar(self.bigram_freq.keys(), self.bigram_freq.values(), color='lightgreen')
        ax2.set_title("Common Bigram Frequencies (%)")
        ax2.tick_params(axis='x', rotation=45)
        canvas2 = FigureCanvasTkAgg(fig2, master=frame)
        canvas2.draw()
        canvas2.get_tk_widget().pack(pady=5)

        # 密文单字母频率
        self.fig3, self.ax3 = plt.subplots(figsize=(5, 3))
        self.ax3.set_title("Ciphertext Letter Frequencies (%)")
        self.canvas3 = FigureCanvasTkAgg(self.fig3, master=frame)
        self.canvas3.draw()
        self.canvas3.get_tk_widget().pack(pady=5)

    ### 中间部分：输入并展示 ###
    def create_input_and_display(self, frame):
        """输入框, 'Input accomplished' 按钮, 解密展示."""
        tk.Label(frame, text="Enter Ciphertext:", font=("Arial", 12)).pack()
        self.ciphertext_entry = tk.Entry(frame, width=50, font=("Arial", 10))
        self.ciphertext_entry.pack(pady=5)

        input_btn = tk.Button(frame, text="Input accomplished", font=("Arial", 10),
                              command=self.process_ciphertext)
        input_btn.pack(pady=5)

        self.display_text = tk.Text(frame, height=10, width=50, font=("Arial", 10))
        self.display_text.pack(pady=5)

    def process_ciphertext(self):
        """处理输入的密文: 更新频次图，在框里分行展示."""
        self.ciphertext = self.ciphertext_entry.get().upper()
        self.ciphertext = ''.join(filter(str.isalpha, self.ciphertext))
        if not self.ciphertext:
            return

        freq = self.calculate_frequencies(self.ciphertext)
        self.update_ciphertext_chart(freq)
        self.display_ciphertext()
        self.update_mapping_interface()

    def calculate_frequencies(self, text):
        """计算频次."""
        total = len(text)
        freq = {letter: text.count(letter) / total * 100 for letter in string.ascii_uppercase if letter in text}
        return freq

    def update_ciphertext_chart(self, freq):
        """更新 ciphertext 频率图表，并按频率降序排列。"""
        sorted_freq_items = sorted(freq.items(), key=lambda item: item[1], reverse=True)
        sorted_letters = [item[0] for item in sorted_freq_items]
        sorted_frequencies = [item[1] for item in sorted_freq_items]

        self.ax3.clear()
        self.ax3.bar(sorted_letters, sorted_frequencies, color='salmon')
        self.ax3.set_title("Ciphertext Letter Frequencies (%) - Sorted by Frequency")
        self.ax3.tick_params(axis='x', rotation=45)
        self.canvas3.draw()

    def display_ciphertext(self):
        """解密的时候小写字母隔开."""
        self.display_text.delete(1.0, tk.END)
        rows = [self.ciphertext[i:i + 10] for i in range(0, len(self.ciphertext), 10)]
        for row in rows:
            self.display_text.insert(tk.END, row + '\n')
            plaintext_row = ''.join([self.mappings.get(c, ' ') + ' ' for c in row])
            self.display_text.insert(tk.END, plaintext_row + '\n')

    ### 右边部分：映射 ###
    def create_mapping_interface(self, frame):
        """从密文到明纹的映射"""
        tk.Label(frame, text="Mappings (Cipher -> Plain):", font=("Arial", 12)).pack()
        self.mapping_frame = tk.Frame(frame)
        self.mapping_frame.pack()

        enter_btn = tk.Button(frame, text="Enter", font=("Arial", 10),
                              command=self.confirm_mappings)
        enter_btn.pack(pady=5)

    def update_mapping_interface(self):
        """从输入的密文创建映射框."""
        for widget in self.mapping_frame.winfo_children():
            widget.destroy()
        self.mapping_entries = {}

        unique_letters = sorted(set(self.ciphertext))
        for i, letter in enumerate(unique_letters):
            tk.Label(self.mapping_frame, text=letter, font=("Arial", 10)).grid(row=i, column=0, padx=5)
            entry = tk.Entry(self.mapping_frame, width=2, font=("Arial", 10))
            entry.grid(row=i, column=1, padx=5)
            self.mapping_entries[letter] = entry
            delete_btn = tk.Button(self.mapping_frame, text="Delete", font=("Arial", 8),
                                   command=lambda l=letter: self.delete_mapping(l))
            delete_btn.grid(row=i, column=2, padx=5)

    def confirm_mappings(self):
        """确认明文输入."""
        for letter, entry in self.mapping_entries.items():
            plaintext = entry.get().lower()
            if plaintext and len(plaintext) == 1 and plaintext.isalpha():
                self.mappings[letter] = plaintext
            elif not plaintext:
                self.mappings.pop(letter, None)
        self.display_ciphertext()

    def delete_mapping(self, letter):
        """删除某映射并更新."""
        if letter in self.mappings:
            del self.mappings[letter]
            self.mapping_entries[letter].delete(0, tk.END)
            self.display_ciphertext()

    ### 组合 ###
    def create_combination_feature(self, frame):
        """创建组合功能界面，在解密显示框下方。"""
        tk.Label(frame, text="Combination Feature:", font=("Arial", 12)).pack(pady=5)
        comb_frame = tk.Frame(frame)
        comb_frame.pack()

        tk.Label(comb_frame, text="Ciphertext letters:", font=("Arial", 10)).grid(row=0, column=0)
        self.comb_cipher_entry = tk.Entry(comb_frame, width=10, font=("Arial", 10))
        self.comb_cipher_entry.grid(row=0, column=1, padx=5, pady=2)

        tk.Label(comb_frame, text="Possible plaintext:", font=("Arial", 10)).grid(row=1, column=0)
        self.comb_plain_entry = tk.Entry(comb_frame, width=10, font=("Arial", 10))
        self.comb_plain_entry.grid(row=1, column=1, padx=5, pady=2)

        comb_btn = tk.Button(comb_frame, text="Combinate", font=("Arial", 10),
                             command=self.generate_combinations)
        comb_btn.grid(row=2, column=0, columnspan=2, pady=5)

        self.comb_result_text = tk.Text(frame, height=24, width=75, font=("Arial", 10))
        self.comb_result_text.pack(side=tk.LEFT, pady=5, fill=tk.BOTH, expand=True)

        comb_scrollbar = tk.Scrollbar(frame, orient=tk.VERTICAL, command=self.comb_result_text.yview)
        comb_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.comb_result_text.config(yscrollcommand=comb_scrollbar.set)

    def generate_combinations(self):
        """创建并展示所有可能的结果."""
        cipher_letters = self.comb_cipher_entry.get().upper()
        plain_letters = self.comb_plain_entry.get().lower()

        if not all(c.isalpha() for c in cipher_letters + plain_letters):
            self.comb_result_text.delete(1.0, tk.END)
            self.comb_result_text.insert(tk.END, "Error: Only letters allowed.\n")
            return
        if len(cipher_letters) > len(plain_letters):
            self.comb_result_text.delete(1.0, tk.END)
            self.comb_result_text.insert(tk.END, "Error: More ciphertext letters than plaintext possibilities.\n")
            return

        perms = list(itertools.permutations(plain_letters, len(cipher_letters)))
        self.comb_result_text.delete(1.0, tk.END)

        for perm in perms:
            temp_mappings = self.mappings.copy()
            mapping = dict(zip(cipher_letters, perm))
            temp_mappings.update(mapping)
            partial_decryption = ''.join(temp_mappings.get(c, '_') for c in self.ciphertext)
            self.comb_result_text.insert(tk.END, f"{mapping} -> {partial_decryption}\n")

# Run the application
if __name__ == "__main__":
    root = tk.Tk()
    root.geometry("1200x800")
    app = CipherApp(root)
    root.mainloop()