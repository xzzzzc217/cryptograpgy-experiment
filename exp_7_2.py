import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, font
import random
import hashlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes

# --- Diffie-Hellman 密钥交换逻辑 ---
class DiffieHellmanParty:
    def __init__(self, name):
        # 初始化 Diffie-Hellman 参与方
        self.name = name
        self.p = None  # 公共大素数
        self.g = None  # 公共生成元
        self.private_key = None  # 私钥
        self.public_key = None  # 公钥
        self.shared_secret = None  # 共享密钥
        self.encryption_key = None  # 派生的 AES 加密密钥

    def set_params(self, p, g):
        # 设置公共参数 p 和 g
        self.p = p
        self.g = g
        self.private_key = None
        self.public_key = None
        self.shared_secret = None
        self.encryption_key = None

    def generate_private_key(self):
        # 生成随机私钥
        if self.p:
            self.private_key = random.randint(2, self.p - 2)
        else:
            raise ValueError("必须先设置参数 p 和 g")
        return self.private_key

    def generate_public_key(self):
        # 根据私钥和公共参数生成公钥
        if self.private_key and self.g and self.p:
            self.public_key = pow(self.g, self.private_key, self.p)
            return self.public_key
        else:
            raise ValueError("私钥、p 和 g 必须可用")

    def calculate_shared_secret(self, other_public_key):
        # 计算共享密钥
        if self.private_key and self.p and other_public_key:
            self.shared_secret = pow(other_public_key, self.private_key, self.p)
            self.derive_encryption_key()
            return self.shared_secret
        else:
            raise ValueError("私钥、p 和对方的公钥必须可用")

    def derive_encryption_key(self):
        # 从共享密钥派生 AES 加密密钥
        if self.shared_secret is not None:
            # 将共享密钥转换为字节并使用 SHA-256 哈希生成 32 字节的 AES-256 密钥
            shared_secret_bytes = self.shared_secret.to_bytes((self.shared_secret.bit_length() + 7) // 8, byteorder='big')
            self.encryption_key = hashlib.sha256(shared_secret_bytes).digest()
        else:
            raise ValueError("共享密钥尚未计算")

    def encrypt(self, plaintext_str):
        # 使用 AES 加密明文
        if not self.encryption_key:
            raise ValueError("加密密钥尚未派生")
        try:
            plaintext_bytes = plaintext_str.encode('utf-8')
            # 生成随机初始化向量 (IV)
            iv = get_random_bytes(AES.block_size)
            cipher = AES.new(self.encryption_key, AES.MODE_CBC, iv)
            # 对明文进行填充
            padded_plaintext = pad(plaintext_bytes, AES.block_size)
            ciphertext_bytes = cipher.encrypt(padded_plaintext)
            # 将 IV 和密文拼接并转换为十六进制字符串
            return (iv + ciphertext_bytes).hex()
        except Exception as e:
            messagebox.showerror("加密错误", f"加密过程中发生错误: {e}")
            return None

    def decrypt(self, ciphertext_hex):
        # 使用 AES 解密密文
        if not self.encryption_key:
            raise ValueError("加密密钥尚未派生")
        try:
            ciphertext_full_bytes = bytes.fromhex(ciphertext_hex)
            # 提取初始化向量 (IV)
            iv = ciphertext_full_bytes[:AES.block_size]
            # 提取实际密文
            ciphertext_bytes = ciphertext_full_bytes[AES.block_size:]
            cipher = AES.new(self.encryption_key, AES.MODE_CBC, iv)
            # 解密并去除填充
            decrypted_padded_bytes = cipher.decrypt(ciphertext_bytes)
            decrypted_bytes = unpad(decrypted_padded_bytes, AES.block_size)
            return decrypted_bytes.decode('utf-8')
        except (ValueError, KeyError) as e:
            messagebox.showerror("解密错误", f"解密失败，密钥错误或数据损坏？\n详情: {e}")
            return None
        except Exception as e:
            messagebox.showerror("解密错误", f"解密过程中发生未知错误: {e}")
            return None


# --- GUI 应用程序 ---
class DHApp:
    def __init__(self, root):
        # 初始化主窗口
        self.root = root
        self.root.title("Diffie-Hellman 密钥交换与加解密模拟")
        self.root.geometry("950x750")

        # 配置界面风格
        self.style = ttk.Style()
        available_themes = self.style.theme_names()
        if 'clam' in available_themes:
            self.style.theme_use('clam')
        elif 'vista' in available_themes:
            self.style.theme_use('vista')
        elif 'aqua' in available_themes:
            self.style.theme_use('aqua')
        else:
            self.style.theme_use('default')

        # 配置控件样式
        self.style.configure('TLabel', font=('Helvetica', 11))
        self.style.configure('TButton', font=('Helvetica', 11), padding=5)
        self.style.configure('TEntry', font=('Helvetica', 11), padding=5)
        self.style.configure('TFrame', padding=10)
        self.style.configure('TNotebook.Tab', font=('Helvetica', 11, 'bold'), padding=[10, 5])

        # 定义字体
        self.title_font = font.Font(family='Helvetica', size=14, weight='bold')
        self.label_font = font.Font(family='Helvetica', size=11)
        self.mono_font = font.Font(family='Courier New', size=10)

        # 创建 Diffie-Hellman 参与方实例
        self.alice = DiffieHellmanParty("Alice")
        self.bob = DiffieHellmanParty("Bob")

        # 创建主选项卡控件
        self.notebook = ttk.Notebook(root)
        self.notebook.pack(pady=10, padx=10, expand=True, fill='both')

        # --- 选项卡 1: Diffie-Hellman 密钥交换 ---
        self.dh_frame = ttk.Frame(self.notebook, padding="10")
        self.notebook.add(self.dh_frame, text='密钥交换 (Diffie-Hellman)')

        # 公共参数区域
        param_frame = ttk.LabelFrame(self.dh_frame, text="公共参数", padding="10")
        param_frame.pack(pady=10, padx=10, fill='x')

        ttk.Label(param_frame, text="p (大素数):").grid(row=0, column=0, padx=5, pady=5, sticky='w')
        self.p_var = tk.StringVar(value="23")
        self.p_entry = ttk.Entry(param_frame, textvariable=self.p_var, width=15)
        self.p_entry.grid(row=0, column=1, padx=5, pady=5)

        ttk.Label(param_frame, text="g (生成元):").grid(row=0, column=2, padx=5, pady=5, sticky='w')
        self.g_var = tk.StringVar(value="5")
        self.g_entry = ttk.Entry(param_frame, textvariable=self.g_var, width=15)
        self.g_entry.grid(row=0, column=3, padx=5, pady=5)

        self.set_params_button = ttk.Button(param_frame, text="设置/更新参数", command=self.set_dh_params)
        self.set_params_button.grid(row=0, column=4, padx=10, pady=5)

        # Alice 和 Bob 的布局框架
        parties_frame = ttk.Frame(self.dh_frame)
        parties_frame.pack(pady=10, padx=5, fill='both', expand=True)
        parties_frame.columnconfigure(0, weight=1)
        parties_frame.columnconfigure(1, weight=1)

        # --- Alice 区域 ---
        alice_frame = ttk.LabelFrame(parties_frame, text="Alice", padding="10")
        alice_frame.grid(row=0, column=0, padx=10, pady=5, sticky='nsew')

        ttk.Button(alice_frame, text="1. 生成 Alice 私钥/公钥", command=self.generate_alice_keys).pack(pady=5, fill='x')
        ttk.Label(alice_frame, text="Alice 私钥 (a):").pack(pady=2, anchor='w')
        self.alice_priv_key_var = tk.StringVar(value="未生成")
        ttk.Entry(alice_frame, textvariable=self.alice_priv_key_var, state='readonly', width=40).pack(pady=2, fill='x')

        ttk.Label(alice_frame, text="Alice 公钥 (A = g^a mod p):").pack(pady=2, anchor='w')
        self.alice_pub_key_var = tk.StringVar(value="未生成")
        ttk.Entry(alice_frame, textvariable=self.alice_pub_key_var, state='readonly', width=40).pack(pady=2, fill='x')

        ttk.Button(alice_frame, text="3. 计算 Alice 共享密钥 (s = B^a mod p)", command=self.calculate_alice_secret).pack(pady=(15, 5), fill='x')
        ttk.Label(alice_frame, text="共享密钥 (s):").pack(pady=2, anchor='w')
        self.alice_shared_secret_var = tk.StringVar(value="未计算")
        ttk.Entry(alice_frame, textvariable=self.alice_shared_secret_var, state='readonly', width=40).pack(pady=2, fill='x')

        ttk.Label(alice_frame, text="AES 密钥 (SHA256(s)):").pack(pady=2, anchor='w')
        self.alice_aes_key_var = tk.StringVar(value="未派生")
        ttk.Entry(alice_frame, textvariable=self.alice_aes_key_var, state='readonly', width=40, font=self.mono_font).pack(pady=2, fill='x')

        # --- Bob 区域 ---
        bob_frame = ttk.LabelFrame(parties_frame, text="Bob", padding="10")
        bob_frame.grid(row=0, column=1, padx=10, pady=5, sticky='nsew')

        ttk.Button(bob_frame, text="1. 生成 Bob 私钥/公钥", command=self.generate_bob_keys).pack(pady=5, fill='x')
        ttk.Label(bob_frame, text="Bob 私钥 (b):").pack(pady=2, anchor='w')
        self.bob_priv_key_var = tk.StringVar(value="未生成")
        ttk.Entry(bob_frame, textvariable=self.bob_priv_key_var, state='readonly', width=40).pack(pady=2, fill='x')

        ttk.Label(bob_frame, text="Bob 公钥 (B = g^b mod p):").pack(pady=2, anchor='w')
        self.bob_pub_key_var = tk.StringVar(value="未生成")
        ttk.Entry(bob_frame, textvariable=self.bob_pub_key_var, state='readonly', width=40).pack(pady=2, fill='x')

        ttk.Button(bob_frame, text="3. 计算 Bob 共享密钥 (s = A^b mod p)", command=self.calculate_bob_secret).pack(pady=(15, 5), fill='x')
        ttk.Label(bob_frame, text="共享密钥 (s):").pack(pady=2, anchor='w')
        self.bob_shared_secret_var = tk.StringVar(value="未计算")
        ttk.Entry(bob_frame, textvariable=self.bob_shared_secret_var, state='readonly', width=40).pack(pady=2, fill='x')

        ttk.Label(bob_frame, text="AES 密钥 (SHA256(s)):").pack(pady=2, anchor='w')
        self.bob_aes_key_var = tk.StringVar(value="未派生")
        ttk.Entry(bob_frame, textvariable=self.bob_aes_key_var, state='readonly', width=40, font=self.mono_font).pack(pady=2, fill='x')

        # --- 公共信道/控制区域 ---
        control_frame = ttk.LabelFrame(self.dh_frame, text="公共信道 / 控制", padding="10")
        control_frame.pack(pady=10, padx=10, fill='x')

        self.exchange_button = ttk.Button(control_frame, text="2. 交换公钥 (A <-> B)", command=self.exchange_keys)
        self.exchange_button.pack(pady=5)
        self.exchange_status_var = tk.StringVar(value="公钥未交换")
        ttk.Label(control_frame, textvariable=self.exchange_status_var, foreground="blue").pack(pady=2)

        self.reset_button = ttk.Button(control_frame, text="重置并生成新密钥", command=self.reset_all)
        self.reset_button.pack(pady=10)

        # --- 选项卡 2: 加密和解密 ---
        self.enc_dec_frame = ttk.Frame(self.notebook, padding="10")
        self.notebook.add(self.enc_dec_frame, text='加密与解密 (AES)')

        enc_dec_parties_frame = ttk.Frame(self.enc_dec_frame)
        enc_dec_parties_frame.pack(pady=10, padx=5, fill='both', expand=True)
        enc_dec_parties_frame.columnconfigure(0, weight=1)
        enc_dec_parties_frame.columnconfigure(1, weight=1)

        # --- Alice 加密/解密区域 ---
        alice_crypto_frame = ttk.LabelFrame(enc_dec_parties_frame, text="Alice 加解密区", padding="10")
        alice_crypto_frame.grid(row=0, column=0, padx=10, pady=5, sticky='nsew')

        ttk.Label(alice_crypto_frame, text="要发送给 Bob 的消息:").pack(pady=5, anchor='w')
        self.alice_message_entry = ttk.Entry(alice_crypto_frame, width=50)
        self.alice_message_entry.pack(pady=5, fill='x')
        self.alice_encrypt_button = ttk.Button(alice_crypto_frame, text="Alice 加密 -> Bob", command=self.alice_encrypt)
        self.alice_encrypt_button.pack(pady=5)

        ttk.Label(alice_crypto_frame, text="加密后的消息 (Hex, 含IV):").pack(pady=5, anchor='w')
        self.alice_ciphertext_text = scrolledtext.ScrolledText(alice_crypto_frame, height=5, width=50, wrap=tk.WORD, font=self.mono_font)
        self.alice_ciphertext_text.pack(pady=5, fill='x')
        self.alice_ciphertext_text.configure(state='disabled')

        ttk.Label(alice_crypto_frame, text="从 Bob 收到的密文 (Hex, 含IV):").pack(pady=(15, 5), anchor='w')
        self.alice_received_ciphertext_text = scrolledtext.ScrolledText(alice_crypto_frame, height=5, width=50, wrap=tk.WORD, font=self.mono_font)
        self.alice_received_ciphertext_text.pack(pady=5, fill='x')
        self.alice_decrypt_button = ttk.Button(alice_crypto_frame, text="Alice 解密 Bob 的消息", command=self.alice_decrypt)
        self.alice_decrypt_button.pack(pady=5)
        ttk.Label(alice_crypto_frame, text="解密后的消息:").pack(pady=5, anchor='w')
        self.alice_decrypted_text = scrolledtext.ScrolledText(alice_crypto_frame, height=3, width=50, wrap=tk.WORD)
        self.alice_decrypted_text.pack(pady=5, fill='x')
        self.alice_decrypted_text.configure(state='disabled')

        # --- Bob 加密/解密区域 ---
        bob_crypto_frame = ttk.LabelFrame(enc_dec_parties_frame, text="Bob 加解密区", padding="10")
        bob_crypto_frame.grid(row=0, column=1, padx=10, pady=5, sticky='nsew')

        ttk.Label(bob_crypto_frame, text="要发送给 Alice 的消息:").pack(pady=5, anchor='w')
        self.bob_message_entry = ttk.Entry(bob_crypto_frame, width=50)
        self.bob_message_entry.pack(pady=5, fill='x')
        self.bob_encrypt_button = ttk.Button(bob_crypto_frame, text="Bob 加密 -> Alice", command=self.bob_encrypt)
        self.bob_encrypt_button.pack(pady=5)

        ttk.Label(bob_crypto_frame, text="加密后的消息 (Hex, 含IV):").pack(pady=5, anchor='w')
        self.bob_ciphertext_text = scrolledtext.ScrolledText(bob_crypto_frame, height=5, width=50, wrap=tk.WORD, font=self.mono_font)
        self.bob_ciphertext_text.pack(pady=5, fill='x')
        self.bob_ciphertext_text.configure(state='disabled')

        ttk.Label(bob_crypto_frame, text="从 Alice 收到的密文 (Hex, 含IV):").pack(pady=(15, 5), anchor='w')
        self.bob_received_ciphertext_text = scrolledtext.ScrolledText(bob_crypto_frame, height=5, width=50, wrap=tk.WORD, font=self.mono_font)
        self.bob_received_ciphertext_text.pack(pady=5, fill='x')
        self.bob_decrypt_button = ttk.Button(bob_crypto_frame, text="Bob 解密 Alice 的消息", command=self.bob_decrypt)
        self.bob_decrypt_button.pack(pady=5)
        ttk.Label(bob_crypto_frame, text="解密后的消息:").pack(pady=5, anchor='w')
        self.bob_decrypted_text = scrolledtext.ScrolledText(bob_crypto_frame, height=3, width=50, wrap=tk.WORD)
        self.bob_decrypted_text.pack(pady=5, fill='x')
        self.bob_decrypted_text.configure(state='disabled')

        # 初始化状态
        self.set_dh_params()
        self.keys_exchanged = False

    def set_dh_params(self):
        # 设置 Diffie-Hellman 公共参数
        try:
            p = int(self.p_var.get())
            g = int(self.g_var.get())
            if p <= 3 or g <= 1 or g >= p:
                raise ValueError("p 必须是大于3的素数, g 必须在 [2, p-2] 范围内")
            self.alice.set_params(p, g)
            self.bob.set_params(p, g)
            messagebox.showinfo("参数设置", f"公共参数已更新: p={p}, g={g}")
            self.reset_keys_secrets()
        except ValueError as e:
            messagebox.showerror("参数错误", f"无效的输入: {e}")

    def reset_keys_secrets(self):
        # 重置所有密钥和相关状态
        self.alice.private_key = None
        self.alice.public_key = None
        self.alice.shared_secret = None
        self.alice.encryption_key = None
        self.bob.private_key = None
        self.bob.public_key = None
        self.bob.shared_secret = None
        self.bob.encryption_key = None

        self.alice_priv_key_var.set("未生成")
        self.alice_pub_key_var.set("未生成")
        self.alice_shared_secret_var.set("未计算")
        self.alice_aes_key_var.set("未派生")
        self.bob_priv_key_var.set("未生成")
        self.bob_pub_key_var.set("未生成")
        self.bob_shared_secret_var.set("未计算")
        self.bob_aes_key_var.set("未派生")
        self.exchange_status_var.set("公钥未交换")
        self.keys_exchanged = False
        self._clear_scrolled_text(self.alice_ciphertext_text)
        self._clear_scrolled_text(self.alice_received_ciphertext_text)
        self._clear_scrolled_text(self.alice_decrypted_text)
        self._clear_scrolled_text(self.bob_ciphertext_text)
        self._clear_scrolled_text(self.bob_received_ciphertext_text)
        self._clear_scrolled_text(self.bob_decrypted_text)

    def reset_all(self):
        # 重置应用程序状态
        self.reset_keys_secrets()
        messagebox.showinfo("重置", "所有密钥和状态已重置。请重新生成密钥。")

    def generate_alice_keys(self):
        # 生成 Alice 的私钥和公钥
        if not self.alice.p or not self.alice.g:
            messagebox.showwarning("警告", "请先设置公共参数 p 和 g")
            return
        try:
            priv_key = self.alice.generate_private_key()
            pub_key = self.alice.generate_public_key()
            self.alice_priv_key_var.set(str(priv_key))
            self.alice_pub_key_var.set(str(pub_key))
            self.keys_exchanged = False
            self.exchange_status_var.set("公钥未交换 (Alice已更新)")
            self.alice_shared_secret_var.set("未计算")
            self.alice_aes_key_var.set("未派生")
            self.bob_shared_secret_var.set("未计算")
            self.bob_aes_key_var.set("未派生")
        except Exception as e:
            messagebox.showerror("错误", f"生成Alice密钥时出错: {e}")

    def generate_bob_keys(self):
        # 生成 Bob 的私钥和公钥
        if not self.bob.p or not self.bob.g:
            messagebox.showwarning("警告", "请先设置公共参数 p 和 g")
            return
        try:
            priv_key = self.bob.generate_private_key()
            pub_key = self.bob.generate_public_key()
            self.bob_priv_key_var.set(str(priv_key))
            self.bob_pub_key_var.set(str(pub_key))
            self.keys_exchanged = False
            self.exchange_status_var.set("公钥未交换 (Bob已更新)")
            self.bob_shared_secret_var.set("未计算")
            self.bob_aes_key_var.set("未派生")
            self.alice_shared_secret_var.set("未计算")
            self.alice_aes_key_var.set("未派生")
        except Exception as e:
            messagebox.showerror("错误", f"生成Bob密钥时出错: {e}")

    def exchange_keys(self):
        # 模拟公钥交换
        if self.alice.public_key is not None and self.bob.public_key is not None:
            self.keys_exchanged = True
            self.exchange_status_var.set(f"公钥已交换: A={self.alice.public_key}, B={self.bob.public_key}")
            messagebox.showinfo("密钥交换", "Alice 和 Bob 的公钥已成功模拟交换")
        else:
            messagebox.showwarning("警告", "必须先为 Alice 和 Bob 都生成公钥才能交换")

    def calculate_alice_secret(self):
        # 计算 Alice 的共享密钥
        if not self.keys_exchanged:
            messagebox.showwarning("警告", "请先交换公钥")
            return
        if self.alice.private_key is None or self.bob.public_key is None:
            messagebox.showerror("错误", "Alice 的私钥或 Bob 的公钥不可用")
            return
        try:
            shared_secret = self.alice.calculate_shared_secret(self.bob.public_key)
            self.alice_shared_secret_var.set(str(shared_secret))
            if self.alice.encryption_key:
                self.alice_aes_key_var.set(self.alice.encryption_key.hex())
            else:
                self.alice_aes_key_var.set("派生失败")
        except Exception as e:
            messagebox.showerror("错误", f"计算 Alice 共享密钥时出错: {e}")
            self.alice_shared_secret_var.set("计算失败")
            self.alice_aes_key_var.set("派生失败")

    def calculate_bob_secret(self):
        # 计算 Bob 的共享密钥
        if not self.keys_exchanged:
            messagebox.showwarning("警告", "请先交换公钥")
            return
        if self.bob.private_key is None or self.alice.public_key is None:
            messagebox.showerror("错误", "Bob 的私钥或 Alice 的公钥不可用")
            return
        try:
            shared_secret = self.bob.calculate_shared_secret(self.alice.public_key)
            self.bob_shared_secret_var.set(str(shared_secret))
            if self.bob.encryption_key:
                self.bob_aes_key_var.set(self.bob.encryption_key.hex())
            else:
                self.bob_aes_key_var.set("派生失败")
            if self.alice.shared_secret is not None and self.alice.shared_secret == self.bob.shared_secret:
                messagebox.showinfo("验证成功", "Alice 和 Bob 计算出的共享密钥相同！")
            elif self.alice.shared_secret is not None:
                messagebox.showerror("验证失败", "Alice 和 Bob 计算出的共享密钥不相同！请检查过程")
        except Exception as e:
            messagebox.showerror("错误", f"计算 Bob 共享密钥时出错: {e}")
            self.bob_shared_secret_var.set("计算失败")
            self.bob_aes_key_var.set("派生失败")

    def _clear_scrolled_text(self, text_widget):
        # 清空滚动文本控件内容
        text_widget.configure(state='normal')
        text_widget.delete('1.0', tk.END)
        text_widget.configure(state='disabled')

    def _update_scrolled_text(self, text_widget, content):
        # 更新滚动文本控件内容
        text_widget.configure(state='normal')
        text_widget.delete('1.0', tk.END)
        text_widget.insert('1.0', content)
        text_widget.configure(state='disabled')

    def alice_encrypt(self):
        # Alice 加密消息并发送给 Bob
        message = self.alice_message_entry.get()
        if not message:
            messagebox.showwarning("输入错误", "请输入要加密的消息")
            return
        if not self.alice.encryption_key:
            messagebox.showerror("错误", "Alice 的加密密钥尚未生成。请先完成密钥交换和计算")
            return
        try:
            ciphertext_hex = self.alice.encrypt(message)
            if ciphertext_hex:
                self._update_scrolled_text(self.alice_ciphertext_text, ciphertext_hex)
                self.bob_received_ciphertext_text.configure(state='normal')
                self.bob_received_ciphertext_text.delete('1.0', tk.END)
                self.bob_received_ciphertext_text.insert('1.0', ciphertext_hex)
                self.bob_received_ciphertext_text.configure(state='disabled')
                messagebox.showinfo("加密成功", "消息已由 Alice 加密，并已“发送”给 Bob")
            else:
                self._clear_scrolled_text(self.alice_ciphertext_text)
        except Exception as e:
            messagebox.showerror("加密错误", f"Alice 加密时发生错误: {e}")
            self._clear_scrolled_text(self.alice_ciphertext_text)

    def bob_decrypt(self):
        # Bob 解密从 Alice 接收的密文
        self.bob_received_ciphertext_text.configure(state='normal')
        ciphertext_hex = self.bob_received_ciphertext_text.get("1.0", tk.END).strip()
        self.bob_received_ciphertext_text.configure(state='disabled')

        if not ciphertext_hex:
            messagebox.showwarning("输入错误", "Bob 的接收框中没有密文")
            return
        if not self.bob.encryption_key:
            messagebox.showerror("错误", "Bob 的解密密钥尚未生成。请先完成密钥交换和计算")
            return
        try:
            decrypted_message = self.bob.decrypt(ciphertext_hex)
            if decrypted_message is not None:
                self._update_scrolled_text(self.bob_decrypted_text, decrypted_message)
                messagebox.showinfo("解密成功", "Bob 成功解密了来自 Alice 的消息")
            else:
                self._clear_scrolled_text(self.bob_decrypted_text)
        except Exception as e:
            messagebox.showerror("解密错误", f"Bob 解密时发生错误: {e}")
            self._clear_scrolled_text(self.bob_decrypted_text)

    def bob_encrypt(self):
        # Bob 加密消息并发送给 Alice
        message = self.bob_message_entry.get()
        if not message:
            messagebox.showwarning("输入错误", "请输入要加密的消息")
            return
        if not self.bob.encryption_key:
            messagebox.showerror("错误", "Bob 的加密密钥尚未生成。请先完成密钥交换和计算")
            return
        try:
            ciphertext_hex = self.bob.encrypt(message)
            if ciphertext_hex:
                self._update_scrolled_text(self.bob_ciphertext_text, ciphertext_hex)
                self.alice_received_ciphertext_text.configure(state='normal')
                self.alice_received_ciphertext_text.delete('1.0', tk.END)
                self.alice_received_ciphertext_text.insert('1.0', ciphertext_hex)
                self.alice_received_ciphertext_text.configure(state='disabled')
                messagebox.showinfo("加密成功", "消息已由 Bob 加密，并已“发送”给 Alice")
            else:
                self._clear_scrolled_text(self.bob_ciphertext_text)
        except Exception as e:
            messagebox.showerror("加密错误", f"Bob 加密时发生错误: {e}")
            self._clear_scrolled_text(self.bob_ciphertext_text)

    def alice_decrypt(self):
        # Alice 解密从 Bob 接收的密文
        self.alice_received_ciphertext_text.configure(state='normal')
        ciphertext_hex = self.alice_received_ciphertext_text.get("1.0", tk.END).strip()
        self.alice_received_ciphertext_text.configure(state='disabled')

        if not ciphertext_hex:
            messagebox.showwarning("输入错误", "Alice 的接收框中没有密文")
            return
        if not self.alice.encryption_key:
            messagebox.showerror("错误", "Alice 的解密密钥尚未生成。请先完成密钥交换和计算")
            return
        try:
            decrypted_message = self.alice.decrypt(ciphertext_hex)
            if decrypted_message is not None:
                self._update_scrolled_text(self.alice_decrypted_text, decrypted_message)
                messagebox.showinfo("解密成功", "Alice 成功解密了来自 Bob 的消息")
            else:
                self._clear_scrolled_text(self.alice_decrypted_text)
        except Exception as e:
            messagebox.showerror("解密错误", f"Alice 解密时发生错误: {e}")
            self._clear_scrolled_text(self.alice_decrypted_text)


# --- 主程序入口 ---
if __name__ == "__main__":
    root = tk.Tk()
    app = DHApp(root)
    root.mainloop()