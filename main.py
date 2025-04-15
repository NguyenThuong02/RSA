import tkinter as tk
from tkinter import filedialog, messagebox, ttk
import os
import base64
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
import xml.etree.ElementTree as ET
import hashlib
import math  # Add this import


class RSACryptosystem:
    def __init__(self, root):
        self.root = root
        self.root.title("RSA Cryptosystem")
        self.root.geometry("1200x600")

        # Variables
        self.key_length = tk.StringVar(value="1024 bits")
        self.key_file_path = tk.StringVar()
        self.input_path = tk.StringVar()
        self.output_path = tk.StringVar()
        self.n_value = tk.StringVar()
        self.e_value = tk.StringVar()
        self.d_value = tk.StringVar()
        self.check_file_path = tk.StringVar()
        self.md5_value = tk.StringVar()
        self.sha1_value = tk.StringVar()
        self.sha256_value = tk.StringVar()
        self.progress_var = tk.DoubleVar()
        self.progress_text = tk.StringVar()

        # Set theme and styling
        self.style = ttk.Style()
        self.style.configure("TFrame", background="#f0f0f0")
        self.style.configure("TLabelframe", background="#f0f0f0")
        self.style.configure("TLabelframe.Label", font=("Arial", 12, "bold"), background="#f0f0f0")
        self.style.configure("TLabel", background="#f0f0f0", font=("Arial", 10))
        self.style.configure("TButton", font=("Arial", 10))
        self.style.configure("Blue.TButton", foreground="white", background="#4287f5")

        # Create header with image
        self.create_header()

        # Create UI
        self.create_ui()

    def create_header(self):
        # Create a header frame
        header_frame = ttk.Frame(self.root)
        header_frame.pack(fill=tk.X, pady=(0, 10))

        # Create blue background
        header_bg = tk.Canvas(header_frame, height=120, bg="#1e3799", highlightthickness=0)
        header_bg.pack(fill=tk.X)

        # Create white banner in the middle
        banner_height = 50
        banner_y = (120 - banner_height) // 2
        banner = tk.Canvas(header_bg, height=banner_height, bg="white", highlightthickness=0)
        banner.place(relx=0.5, y=banner_y, relwidth=0.8, height=banner_height, anchor=tk.N)
        banner.update()
        banner.create_text(banner.winfo_width() // 2, banner_height // 2,
                           text="RSA CRYPTOSYSTEM", font=("Arial", 20, "bold"))

        # Add network-like decoration
        self.draw_network(header_bg)

    def draw_network(self, canvas):
        # Draw some network-like lines and nodes for decoration
        width = self.root.winfo_screenwidth()
        height = 150
        nodes = [(50, 30), (150, 80), (250, 40), (350, 90), (450, 30),
                 (width - 50, 30), (width - 150, 80), (width - 250, 40), (width - 350, 90), (width - 450, 30)]

        # Draw lines
        for i in range(len(nodes)):
            for j in range(i + 1, len(nodes)):
                if abs(nodes[i][0] - nodes[j][0]) < 300:  # Only connect nearby nodes
                    canvas.create_line(nodes[i][0], nodes[i][1], nodes[j][0], nodes[j][1], fill="#4287f5", width=1)

        # Draw nodes
        for x, y in nodes:
            canvas.create_oval(x - 5, y - 5, x + 5, y + 5, fill="#6eb6ff", outline="")

    def create_ui(self):
        # Main container
        main_frame = ttk.Frame(self.root)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=10)

        # Create left column
        left_column = ttk.Frame(main_frame)
        left_column.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0, 10))

        # Create right column
        right_column = ttk.Frame(main_frame)
        right_column.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True, padx=(10, 0))

        # Create sections
        self.create_key_generation_section(left_column)
        self.create_encryption_section(left_column)
        self.create_key_info_section(right_column)
        self.create_file_check_section(right_column)

        # Reset button at bottom
        reset_btn = ttk.Button(self.root, text="RESET FORM", command=self.reset_form, width=20)
        reset_btn.pack(pady=10)

    def create_key_generation_section(self, parent):
        # Key Generation Section
        key_frame = ttk.LabelFrame(parent, text="Tạo Key", padding=10)
        key_frame.pack(fill=tk.X, pady=5)

        # Key Length
        ttk.Label(key_frame, text="Độ dài Key:").grid(row=0, column=0, sticky=tk.W, pady=5, padx=5)
        key_length_combo = ttk.Combobox(key_frame, textvariable=self.key_length, width=15)
        key_length_combo['values'] = ('512 bits', '1024 bits', '2048 bits', '4096 bits')
        key_length_combo.grid(row=0, column=1, sticky=tk.W, pady=5, padx=5)

        generate_btn = ttk.Button(key_frame, text="Tạo Key Tự Động", command=self.generate_keys)
        generate_btn.grid(row=0, column=2, padx=5, pady=5, sticky=tk.E)

        # Key File Path
        ttk.Label(key_frame, text="File Key (Xml):").grid(row=1, column=0, sticky=tk.W, pady=5, padx=5)
        key_path_entry = ttk.Entry(key_frame, textvariable=self.key_file_path, width=50)
        key_path_entry.grid(row=1, column=1, columnspan=2, sticky=tk.W, pady=5, padx=5)

        browse_key_btn = ttk.Button(key_frame, text="Open", command=self.browse_key_file)
        browse_key_btn.grid(row=1, column=3, padx=5, pady=5)

    def create_encryption_section(self, parent):
        # Encryption/Decryption Section
        crypt_frame = ttk.LabelFrame(parent, text="Mã Hoá Và Giải Mã", padding=10)
        crypt_frame.pack(fill=tk.BOTH, expand=True, pady=5)

        # Input
        ttk.Label(crypt_frame, text="Input:").grid(row=0, column=0, sticky=tk.W, pady=5, padx=5)
        input_entry = ttk.Entry(crypt_frame, textvariable=self.input_path, width=50)
        input_entry.grid(row=0, column=1, columnspan=2, sticky=tk.W, pady=5, padx=5)

        select_file_btn = ttk.Button(crypt_frame, text="Select File", command=self.browse_input_file)
        select_file_btn.grid(row=0, column=3, padx=5, pady=5)

        select_input_folder_btn = ttk.Button(crypt_frame, text="Select Folder", command=self.browse_input_folder)
        select_input_folder_btn.grid(row=0, column=4, padx=5, pady=5)

        # Output
        ttk.Label(crypt_frame, text="Output:").grid(row=1, column=0, sticky=tk.W, pady=5, padx=5)
        output_entry = ttk.Entry(crypt_frame, textvariable=self.output_path, width=50)
        output_entry.grid(row=1, column=1, columnspan=2, sticky=tk.W, pady=5, padx=5)

        select_output_folder_btn = ttk.Button(crypt_frame, text="Select Folder", command=self.browse_output_folder)
        select_output_folder_btn.grid(row=1, column=3, padx=5, pady=5)

        open_output_folder_btn = ttk.Button(crypt_frame, text="Open Folder", command=self.open_output_folder)
        open_output_folder_btn.grid(row=1, column=4, padx=5, pady=5)

        # Action buttons
        button_frame = ttk.Frame(crypt_frame)
        button_frame.grid(row=2, column=0, columnspan=5, pady=10)

        encrypt_btn = ttk.Button(button_frame, text="Mã Hoá", command=self.encrypt_file, width=15)
        encrypt_btn.pack(side=tk.LEFT, padx=10)

        decrypt_btn = ttk.Button(button_frame, text="Giải Mã", command=self.decrypt_file, width=15)
        decrypt_btn.pack(side=tk.LEFT, padx=10)

        # Progress bar
        self.progress_bar = ttk.Progressbar(crypt_frame, orient=tk.HORIZONTAL, length=600,
                                            mode='determinate', variable=self.progress_var)
        self.progress_bar.grid(row=3, column=0, columnspan=5, pady=10, sticky=tk.EW)

        # Progress text
        self.progress_label = ttk.Label(crypt_frame, textvariable=self.progress_text)
        self.progress_label.grid(row=4, column=0, columnspan=5, pady=5, sticky=tk.W)

    def create_key_info_section(self, parent):
        # Key Information Section
        info_frame = ttk.LabelFrame(parent, text="Thông tin Key", padding=10)
        info_frame.pack(fill=tk.X, pady=5)

        # Modulus (N)
        ttk.Label(info_frame, text="Module (N):").grid(row=0, column=0, sticky=tk.W, pady=5, padx=5)
        n_entry = ttk.Entry(info_frame, textvariable=self.n_value, width=50)
        n_entry.grid(row=0, column=1, sticky=tk.W, pady=5, padx=5)

        # Public Exponent (E)
        ttk.Label(info_frame, text="Mã Mã Hoá (E):").grid(row=1, column=0, sticky=tk.W, pady=5, padx=5)
        e_entry = ttk.Entry(info_frame, textvariable=self.e_value, width=50)
        e_entry.grid(row=1, column=1, sticky=tk.W, pady=5, padx=5)

        # Private Exponent (D)
        ttk.Label(info_frame, text="Mã Giải Mã (D):").grid(row=2, column=0, sticky=tk.W, pady=5, padx=5)
        d_entry = ttk.Entry(info_frame, textvariable=self.d_value, width=50)
        d_entry.grid(row=2, column=1, sticky=tk.W, pady=5, padx=5)

    def create_file_check_section(self, parent):
        # File Check Section
        check_frame = ttk.LabelFrame(parent, text="Kiểm Tra File", padding=10)
        check_frame.pack(fill=tk.BOTH, expand=True, pady=5)

        # File Path
        ttk.Label(check_frame, text="File:").grid(row=0, column=0, sticky=tk.W, pady=5, padx=5)
        check_file_entry = ttk.Entry(check_frame, textvariable=self.check_file_path, width=50)
        check_file_entry.grid(row=0, column=1, sticky=tk.W, pady=5, padx=5)

        browse_check_file_btn = ttk.Button(check_frame, text="Open File", command=self.browse_check_file)
        browse_check_file_btn.grid(row=0, column=2, padx=5, pady=5)

        # Check button
        check_btn = ttk.Button(check_frame, text="Kiểm Tra", command=self.check_file)
        check_btn.grid(row=1, column=1, pady=10)

        # Hash values
        ttk.Label(check_frame, text="MD5:").grid(row=2, column=0, sticky=tk.W, pady=5, padx=5)
        md5_entry = ttk.Entry(check_frame, textvariable=self.md5_value, width=50)
        md5_entry.grid(row=2, column=1, sticky=tk.W, pady=5, padx=5)

        ttk.Label(check_frame, text="SHA1:").grid(row=3, column=0, sticky=tk.W, pady=5, padx=5)
        sha1_entry = ttk.Entry(check_frame, textvariable=self.sha1_value, width=50)
        sha1_entry.grid(row=3, column=1, sticky=tk.W, pady=5, padx=5)

        ttk.Label(check_frame, text="SHA256:").grid(row=4, column=0, sticky=tk.W, pady=5, padx=5)
        sha256_entry = ttk.Entry(check_frame, textvariable=self.sha256_value, width=50)
        sha256_entry.grid(row=4, column=1, sticky=tk.W, pady=5, padx=5)

    def generate_keys(self):
        try:
            # Get key size
            key_size = int(self.key_length.get().split()[0])

            # Generate private key
            private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=key_size
            )

            # Get public key
            public_key = private_key.public_key()

            # Extract parameters
            private_numbers = private_key.private_numbers()
            public_numbers = public_key.public_numbers()

            # Set values in UI
            self.n_value.set(str(public_numbers.n))
            self.e_value.set(str(public_numbers.e))
            self.d_value.set(str(private_numbers.d))

            # Save keys to XML file
            file_path = filedialog.asksaveasfilename(
                title="Save Keys",
                defaultextension=".xml",
                filetypes=[("XML Files", "*.xml"), ("All Files", "*.*")]
            )

            if file_path:
                self.key_file_path.set(file_path)
                self.save_keys_to_file(file_path, public_numbers.n, public_numbers.e, private_numbers.d)
                messagebox.showinfo("Success", "Keys generated and saved successfully")
        except Exception as ex:
            messagebox.showerror("Error", f"Failed to generate keys: {str(ex)}")

    def save_keys_to_file(self, file_path, n, e, d):
        try:
            # Get the private key components
            private_key = rsa.generate_private_key(
                public_exponent=e,
                key_size=int(self.key_length.get().split()[0])
            )
            private_numbers = private_key.private_numbers()

            # Create XML structure
            root = ET.Element("RSAKeyInfo")
            key_value = ET.SubElement(root, "RSAKeyValue")

            modulus = ET.SubElement(key_value, "Modulus")
            modulus.text = str(n)

            exponent = ET.SubElement(key_value, "Exponent")
            exponent.text = str(e)

            d_elem = ET.SubElement(key_value, "D")
            d_elem.text = str(d)

            # Add p and q to the XML
            p_elem = ET.SubElement(key_value, "P")
            p_elem.text = str(private_numbers.p)

            q_elem = ET.SubElement(key_value, "Q")
            q_elem.text = str(private_numbers.q)

            # Write to file
            tree = ET.ElementTree(root)
            tree.write(file_path, encoding="utf-8", xml_declaration=True)
        except Exception as ex:
            messagebox.showerror("Error", f"Failed to save keys: {str(ex)}")

    def browse_key_file(self):
        file_path = filedialog.askopenfilename(
            title="Select Keys File",
            filetypes=[("XML Files", "*.xml"), ("All Files", "*.*")]
        )
        if file_path:
            self.key_file_path.set(file_path)
            self.load_keys_from_file(file_path)

    def load_keys_from_file(self, file_path):
        try:
            tree = ET.parse(file_path)
            root = tree.getroot()

            # Extract RSA parameters from XML
            p_value = None
            q_value = None

            for param in root.findall('./RSAKeyValue/*'):
                if param.tag == 'Modulus':
                    self.n_value.set(param.text)
                elif param.tag == 'Exponent':
                    self.e_value.set(param.text)
                elif param.tag == 'D':
                    self.d_value.set(param.text)
                elif param.tag == 'P':
                    p_value = param.text
                elif param.tag == 'Q':
                    q_value = param.text

            # Store p and q as instance variables if they exist
            if p_value and q_value:
                self.p_value = int(p_value)
                self.q_value = int(q_value)

            messagebox.showinfo("Success", "Keys loaded successfully")
        except Exception as ex:
            messagebox.showerror("Error", f"Failed to load keys: {str(ex)}")

    def browse_input_file(self):
        file_path = filedialog.askopenfilename(
            title="Select Input File",
            filetypes=[("All Files", "*.*")]
        )
        if file_path:
            self.input_path.set(file_path)

    def browse_input_folder(self):
        folder_path = filedialog.askdirectory(title="Select Input Folder")
        if folder_path:
            self.input_path.set(folder_path)

    def browse_output_folder(self):
        folder_path = filedialog.askdirectory(title="Select Output Folder")
        if folder_path:
            self.output_path.set(folder_path)

    def open_output_folder(self):
        if self.output_path.get():
            os.startfile(self.output_path.get())
        else:
            messagebox.showwarning("Warning", "No output folder selected")

    def browse_check_file(self):
        file_path = filedialog.askopenfilename(
            title="Select File to Check",
            filetypes=[("All Files", "*.*")]
        )
        if file_path:
            self.check_file_path.set(file_path)
            # self.check_file()

    def check_file(self):
        if not self.check_file_path.get():
            messagebox.showwarning("Warning", "Vui lòng chọn file để kiểm tra")
            return

        try:
            file_path = self.check_file_path.get()

            # Calculate hash values
            with open(file_path, 'rb') as f:
                data = f.read()
                self.md5_value.set(hashlib.md5(data).hexdigest())
                self.sha1_value.set(hashlib.sha1(data).hexdigest())
                self.sha256_value.set(hashlib.sha256(data).hexdigest())

            messagebox.showinfo("Success", "File check completed")
        except Exception as ex:
            messagebox.showerror("Error", f"Failed to check file: {str(ex)}")

    def encrypt_file(self):
        if not self.input_path.get() or not self.output_path.get() or not self.n_value.get():
            messagebox.showwarning("Warning", "Vui lòng cung cấp đủ thông tin!")
            return

        try:
            input_path = self.input_path.get()
            output_path = self.output_path.get()

            # Create public key from parameters
            n = int(self.n_value.get())
            e = int(self.e_value.get())

            public_numbers = rsa.RSAPublicNumbers(e=e, n=n)
            public_key = public_numbers.public_key()

            # Check if input is file or directory
            if os.path.isfile(input_path):
                # Process single file
                self.encrypt_single_file(input_path, output_path, public_key)
            elif os.path.isdir(input_path):
                # Process all files in directory
                files = [f for f in os.listdir(input_path) if os.path.isfile(os.path.join(input_path, f))]
                for i, file in enumerate(files):
                    file_path = os.path.join(input_path, file)
                    progress = (i / len(files)) * 100
                    self.progress_var.set(progress)
                    self.progress_text.set(f"Đang xử lý: {file}")
                    self.root.update()
                    self.encrypt_single_file(file_path, output_path, public_key)

                self.progress_var.set(100)
                self.progress_text.set(f"Hoàn thành: {len(files)} files")

            messagebox.showinfo("Success", "Encryption completed successfully")
        except Exception as ex:
            messagebox.showerror("Error", f"Encryption failed: {str(ex)}")
            self.progress_text.set(f"Lỗi: {str(ex)}")

    def encrypt_single_file(self, input_file, output_dir, public_key):
        try:
            # Read file
            with open(input_file, 'rb') as f:
                data = f.read()

            # Calculate maximum chunk size based on key size
            # For OAEP padding with SHA-256, the max data size is:
            # key_size_bytes - 2 * hash_size_bytes - 2
            key_size_bytes = (public_key.key_size + 7) // 8
            hash_size_bytes = 32  # SHA-256 is 32 bytes
            chunk_size = key_size_bytes - 2 * hash_size_bytes - 2

            encrypted_chunks = []

            for i in range(0, len(data), chunk_size):
                chunk = data[i:i + chunk_size]
                encrypted_chunk = public_key.encrypt(
                    chunk,
                    padding.OAEP(
                        mgf=padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None
                    )
                )
                encrypted_chunks.append(encrypted_chunk)

            # Save encrypted file with .lhde extension instead of .enc
            file_name = os.path.basename(input_file)
            encrypted_file_path = os.path.join(output_dir, file_name + ".lhde")

            with open(encrypted_file_path, 'wb') as f:
                for chunk in encrypted_chunks:
                    f.write(chunk)

            self.progress_text.set(f"Tên tệp xử lý: {file_name} Thành công: 100%")
            return True
        except Exception as ex:
            raise Exception(f"Failed to encrypt file {os.path.basename(input_file)}: {str(ex)}")

    def decrypt_file(self):
        if not self.input_path.get() or not self.output_path.get() or not self.n_value.get() or not self.d_value.get():
            messagebox.showwarning("Warning", "Vui lòng cung cấp đủ thông tin!")
            return

        try:
            input_path = self.input_path.get()
            output_path = self.output_path.get()

            # Create private key from parameters
            n = int(self.n_value.get())
            e = int(self.e_value.get())
            d = int(self.d_value.get())

            # Use stored p and q if available, otherwise try to find them
            if hasattr(self, 'p_value') and hasattr(self, 'q_value'):
                p, q = self.p_value, self.q_value
            else:
                p, q = self.find_p_q(n, e, d)

            private_numbers = rsa.RSAPrivateNumbers(
                p=p,
                q=q,
                d=d,
                dmp1=d % (p - 1),
                dmq1=d % (q - 1),
                iqmp=pow(q, -1, p),
                public_numbers=rsa.RSAPublicNumbers(e=e, n=n)
            )

            private_key = private_numbers.private_key()

            # Check if input is file or directory
            if os.path.isfile(input_path):
                # Process single file
                self.decrypt_single_file(input_path, output_path, private_key)
            elif os.path.isdir(input_path):
                # Process all files in directory - look for .lhde files instead of .enc
                files = [f for f in os.listdir(input_path) if
                         os.path.isfile(os.path.join(input_path, f)) and f.endswith('.lhde')]
                for i, file in enumerate(files):
                    file_path = os.path.join(input_path, file)
                    progress = (i / len(files)) * 100
                    self.progress_var.set(progress)
                    self.progress_text.set(f"Đang xử lý: {file}")
                    self.root.update()
                    self.decrypt_single_file(file_path, output_path, private_key)

                self.progress_var.set(100)
                self.progress_text.set(f"Hoàn thành: {len(files)} files")

            messagebox.showinfo("Success", "Decryption completed successfully")
        except Exception as ex:
            messagebox.showerror("Error", f"Decryption failed: {str(ex)}")
            self.progress_text.set(f"Lỗi: {str(ex)}")

    def decrypt_single_file(self, input_file, output_dir, private_key):
        try:
            # Read encrypted file
            with open(input_file, 'rb') as f:
                encrypted_data = f.read()

            # Determine the key size in bytes (n.bit_length() // 8 + 1)
            key_size_bytes = (private_key.key_size + 7) // 8

            # Decrypt in chunks
            decrypted_data = bytearray()

            for i in range(0, len(encrypted_data), key_size_bytes):
                encrypted_chunk = encrypted_data[i:i + key_size_bytes]
                if len(encrypted_chunk) == key_size_bytes:  # Make sure the chunk is complete
                    try:
                        decrypted_chunk = private_key.decrypt(
                            encrypted_chunk,
                            padding.OAEP(
                                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                                algorithm=hashes.SHA256(),
                                label=None
                            )
                        )
                        decrypted_data.extend(decrypted_chunk)
                    except ValueError as e:
                        # Log the error but continue with other chunks
                        self.progress_text.set(f"Lỗi giải mã khối {i // key_size_bytes}: {str(e)}")
                        self.root.update()
                        continue

            # Save decrypted file - change to check for .lhde extension
            file_name = os.path.basename(input_file)
            if file_name.endswith('.lhde'):
                file_name = file_name[:-5]  # Remove .lhde extension
            decrypted_file_path = os.path.join(output_dir, file_name)

            with open(decrypted_file_path, 'wb') as f:
                f.write(decrypted_data)

            self.progress_text.set(f"Tên tệp xử lý: {file_name} Thành công: 100%")
            return True
        except Exception as ex:
            raise Exception(f"Failed to decrypt file {os.path.basename(input_file)}: {str(ex)}")

    def find_p_q(self, n, e, d):
        """
        Find p and q from n, e, and d using a more robust method.
        Based on the mathematical relationship in RSA.
        """
        # Calculate k = e*d - 1
        k = e * d - 1

        # If k is odd, we can't proceed with this method
        if k % 2 == 1:
            raise ValueError("Cannot find p and q with the given parameters")

        # Find the largest power of 2 that divides k
        r = 0
        t = k
        while t % 2 == 0:
            t //= 2
            r += 1

        # Try different random bases to find p and q
        for _ in range(100):  # Try multiple times with different bases
            # Choose a random base between 2 and n-2
            import random
            g = random.randint(2, n - 2)

            # Calculate y = g^t mod n
            y = pow(g, t, n)

            # If y is 1 or n-1, try another base
            if y == 1 or y == n - 1:
                continue

            # Find a non-trivial square root of 1 modulo n
            for i in range(1, r):
                x = y
                y = pow(y, 2, n)
                if y == 1 and x != 1 and x != n - 1:
                    # Found a non-trivial square root of 1
                    # This gives us a factor of n
                    p = math.gcd(x + 1, n)
                    if p > 1 and n % p == 0:
                        return p, n // p

            if y != 1:
                # Another way to find a factor
                p = math.gcd(y - 1, n)
                if p > 1 and n % p == 0:
                    return p, n // p

        # If we get here, we couldn't find p and q
        raise ValueError("Could not find p and q with the given parameters. Try generating new keys.")

    def reset_form(self):
        # Reset all variables
        self.key_length.set("1024 bits")
        self.key_file_path.set("")
        self.input_path.set("")
        self.output_path.set("")
        self.n_value.set("")
        self.e_value.set("")
        self.d_value.set("")
        self.check_file_path.set("")
        self.md5_value.set("")
        self.sha1_value.set("")
        self.sha256_value.set("")
        self.progress_var.set(0)
        self.progress_text.set("")


if __name__ == "__main__":
    root = tk.Tk()
    app = RSACryptosystem(root)
    root.mainloop()