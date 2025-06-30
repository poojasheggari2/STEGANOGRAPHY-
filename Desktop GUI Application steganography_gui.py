import numpy as np
from PIL import Image
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import binascii
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
import os

class AdvancedSteganography:
    def __init__(self):
        self.HEADER_SIZE = 32  # bytes
        self.CRC_SIZE = 4       # bytes
        
    def encrypt_message(self, key, message):
        cipher = AES.new(key, AES.MODE_CBC)
        ct_bytes = cipher.encrypt(pad(message.encode(), AES.block_size))
        return cipher.iv + ct_bytes
        
    def decrypt_message(self, key, encrypted):
        iv = encrypted[:16]
        ct = encrypted[16:]
        cipher = AES.new(key, AES.MODE_CBC, iv=iv)
        return unpad(cipher.decrypt(ct), AES.block_size).decode()
        
    def embed_data(self, image_path, secret_msg, output_path, key=None):
        img = Image.open(image_path)
        if img.mode != 'RGB':
            img = img.convert('RGB')
            
        pixels = np.array(img)
        if key:
            secret_msg = self.encrypt_message(key, secret_msg)
        else:
            secret_msg = secret_msg.encode()
            
        # Calculate required capacity
        required_bits = (len(secret_msg) + self.HEADER_SIZE + self.CRC_SIZE) * 8
        available_bits = pixels.size * 3  # 3 channels per pixel
        
        if required_bits > available_bits:
            raise ValueError("Image too small for the message")
            
        # Create header with size and checksum
        msg_size = len(secret_msg).to_bytes(4, 'big')
        crc = binascii.crc32(secret_msg).to_bytes(4, 'big')
        full_data = msg_size + crc + secret_msg
        
        # Convert to binary string
        binary_str = ''.join(format(byte, '08b') for byte in full_data)
        
        # Embed data using LSB
        data_index = 0
        for row in pixels:
            for pixel in row:
                for channel in range(3):  # R,G,B
                    if data_index < len(binary_str):
                        pixel[channel] = (pixel[channel] & 0xFC) | \
                                       (int(binary_str[data_index]) << 1) | \
                                       (int(binary_str[data_index+1]) if data_index+1 < len(binary_str) else 0)
                        data_index += 2
                        
        stego_img = Image.fromarray(pixels)
        stego_img.save(output_path)
        return True

    def extract_data(self, image_path, key=None):
        img = Image.open(image_path)
        pixels = np.array(img)
        
        # Extract header information
        extracted_bits = []
        for row in pixels:
            for pixel in row:
                for channel in range(3):
                    lsb1 = pixel[channel] & 1
                    lsb2 = (pixel[channel] >> 1) & 1
                    extracted_bits.extend([str(lsb2), str(lsb1)])
        
        # Convert bits to bytes
        byte_array = []
        for i in range(0, len(extracted_bits), 8):
            byte = ''.join(extracted_bits[i:i+8][:8])
            if len(byte) == 8:
                byte_array.append(int(byte, 2))
        
        full_data = bytes(byte_array)
        
        # Parse header
        msg_size = int.from_bytes(full_data[:4], 'big')
        expected_crc = int.from_bytes(full_data[4:8], 'big')
        encrypted_msg = full_data[8:8+msg_size]
        
        # Verify CRC
        if binascii.crc32(encrypted_msg) != expected_crc:
            raise ValueError("Data corrupted or wrong extraction key")
            
        if key:
            return self.decrypt_message(key, encrypted_msg)
        return encrypted_msg.decode()

class SteganographyGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Advanced Steganography Tool")
        self.root.geometry("800x600")
        self.root.configure(bg='#2b2b2b')
        
        # Initialize steganography engine
        self.steg = AdvancedSteganography()
        
        # Variables
        self.input_image_path = tk.StringVar()
        self.output_image_path = tk.StringVar()
        self.extract_image_path = tk.StringVar()
        
        self.create_widgets()
        
    def create_widgets(self):
        # Create notebook for tabs
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill='both', expand=True, padx=10, pady=10)
        
        # Create embed tab
        self.embed_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.embed_frame, text='Hide Message')
        self.create_embed_widgets()
        
        # Create extract tab
        self.extract_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.extract_frame, text='Reveal Message')
        self.create_extract_widgets()
        
        # Style configuration
        style = ttk.Style()
        style.theme_use('clam')
        style.configure('TLabel', background='#2b2b2b', foreground='white')
        style.configure('TFrame', background='#2b2b2b')
        style.configure('TButton', padding=10)
        
    def create_embed_widgets(self):
        # Title
        title_label = ttk.Label(self.embed_frame, text="Hide Secret Message in Image", 
                               font=('Arial', 16, 'bold'))
        title_label.pack(pady=20)
        
        # Input image selection
        input_frame = ttk.Frame(self.embed_frame)
        input_frame.pack(fill='x', padx=20, pady=10)
        
        ttk.Label(input_frame, text="Select Cover Image:").pack(anchor='w')
        input_path_frame = ttk.Frame(input_frame)
        input_path_frame.pack(fill='x', pady=5)
        
        self.input_entry = ttk.Entry(input_path_frame, textvariable=self.input_image_path, width=60)
        self.input_entry.pack(side='left', fill='x', expand=True)
        
        ttk.Button(input_path_frame, text="Browse", 
                  command=self.browse_input_image).pack(side='right', padx=(5,0))
        
        # Message input
        msg_frame = ttk.Frame(self.embed_frame)
        msg_frame.pack(fill='both', expand=True, padx=20, pady=10)
        
        ttk.Label(msg_frame, text="Secret Message:").pack(anchor='w')
        self.message_text = tk.Text(msg_frame, height=8, width=70, bg='#404040', fg='white',
                                   insertbackground='white', font=('Consolas', 10))
        self.message_text.pack(fill='both', expand=True, pady=5)
        
        # Encryption key
        key_frame = ttk.Frame(self.embed_frame)
        key_frame.pack(fill='x', padx=20, pady=10)
        
        ttk.Label(key_frame, text="Encryption Key (Optional):").pack(anchor='w')
        self.embed_key_entry = ttk.Entry(key_frame, show="*", width=40)
        self.embed_key_entry.pack(fill='x', pady=5)
        
        # Output path
        output_frame = ttk.Frame(self.embed_frame)
        output_frame.pack(fill='x', padx=20, pady=10)
        
        ttk.Label(output_frame, text="Output Image Path:").pack(anchor='w')
        output_path_frame = ttk.Frame(output_frame)
        output_path_frame.pack(fill='x', pady=5)
        
        self.output_entry = ttk.Entry(output_path_frame, textvariable=self.output_image_path, width=60)
        self.output_entry.pack(side='left', fill='x', expand=True)
        
        ttk.Button(output_path_frame, text="Browse", 
                  command=self.browse_output_image).pack(side='right', padx=(5,0))
        
        # Embed button
        ttk.Button(self.embed_frame, text="Hide Message", 
                  command=self.embed_message, style='Accent.TButton').pack(pady=20)
        
    def create_extract_widgets(self):
        # Title
        title_label = ttk.Label(self.extract_frame, text="Extract Hidden Message from Image", 
                               font=('Arial', 16, 'bold'))
        title_label.pack(pady=20)
        
        # Input image selection
        extract_input_frame = ttk.Frame(self.extract_frame)
        extract_input_frame.pack(fill='x', padx=20, pady=10)
        
        ttk.Label(extract_input_frame, text="Select Steganographic Image:").pack(anchor='w')
        extract_path_frame = ttk.Frame(extract_input_frame)
        extract_path_frame.pack(fill='x', pady=5)
        
        self.extract_entry = ttk.Entry(extract_path_frame, textvariable=self.extract_image_path, width=60)
        self.extract_entry.pack(side='left', fill='x', expand=True)
        
        ttk.Button(extract_path_frame, text="Browse", 
                  command=self.browse_extract_image).pack(side='right', padx=(5,0))
        
        # Decryption key
        decrypt_key_frame = ttk.Frame(self.extract_frame)
        decrypt_key_frame.pack(fill='x', padx=20, pady=10)
        
        ttk.Label(decrypt_key_frame, text="Decryption Key (if encrypted):").pack(anchor='w')
        self.extract_key_entry = ttk.Entry(decrypt_key_frame, show="*", width=40)
        self.extract_key_entry.pack(fill='x', pady=5)
        
        # Extract button
        ttk.Button(self.extract_frame, text="Reveal Message", 
                  command=self.extract_message, style='Accent.TButton').pack(pady=20)
        
        # Extracted message display
        result_frame = ttk.Frame(self.extract_frame)
        result_frame.pack(fill='both', expand=True, padx=20, pady=10)
        
        ttk.Label(result_frame, text="Extracted Message:").pack(anchor='w')
        self.result_text = tk.Text(result_frame, height=10, width=70, bg='#404040', fg='white',
                                  insertbackground='white', font=('Consolas', 10), state='disabled')
        self.result_text.pack(fill='both', expand=True, pady=5)
        
        # Scrollbar for result text
        scrollbar = ttk.Scrollbar(result_frame, orient='vertical', command=self.result_text.yview)
        scrollbar.pack(side='right', fill='y')
        self.result_text.configure(yscrollcommand=scrollbar.set)
        
    def browse_input_image(self):
        filename = filedialog.askopenfilename(
            title="Select Cover Image",
            filetypes=[("Image files", "*.png *.jpg *.jpeg *.bmp *.tiff"), ("All files", "*.*")]
        )
        if filename:
            self.input_image_path.set(filename)
            # Auto-generate output filename
            base_name = os.path.splitext(filename)[0]
            self.output_image_path.set(f"{base_name}_stego.png")
            
    def browse_output_image(self):
        filename = filedialog.asksaveasfilename(
            title="Save Steganographic Image As",
            defaultextension=".png",
            filetypes=[("PNG files", "*.png"), ("All files", "*.*")]
        )
        if filename:
            self.output_image_path.set(filename)
            
    def browse_extract_image(self):
        filename = filedialog.askopenfilename(
            title="Select Steganographic Image",
            filetypes=[("Image files", "*.png *.jpg *.jpeg *.bmp *.tiff"), ("All files", "*.*")]
        )
        if filename:
            self.extract_image_path.set(filename)
            
    def embed_message(self):
        try:
            # Validate inputs
            if not self.input_image_path.get():
                messagebox.showerror("Error", "Please select a cover image")
                return
                
            if not self.output_image_path.get():
                messagebox.showerror("Error", "Please specify output image path")
                return
                
            message = self.message_text.get("1.0", tk.END).strip()
            if not message:
                messagebox.showerror("Error", "Please enter a message to hide")
                return
                
            # Get encryption key
            key = self.embed_key_entry.get().strip()
            if key:
                # Pad or truncate key to 32 bytes for AES-256
                key_bytes = key.encode('utf-8')
                if len(key_bytes) < 32:
                    key_bytes = key_bytes.ljust(32, b'\0')
                elif len(key_bytes) > 32:
                    key_bytes = key_bytes[:32]
            else:
                key_bytes = None
                
            # Embed message
            success = self.steg.embed_data(
                self.input_image_path.get(),
                message,
                self.output_image_path.get(),
                key_bytes
            )
            
            if success:
                messagebox.showinfo("Success", 
                    f"Message successfully hidden in image!\nSaved as: {self.output_image_path.get()}")
            else:
                messagebox.showerror("Error", "Failed to embed message")
                
        except Exception as e:
            messagebox.showerror("Error", f"Error embedding message: {str(e)}")
            
    def extract_message(self):
        try:
            # Validate inputs
            if not self.extract_image_path.get():
                messagebox.showerror("Error", "Please select a steganographic image")
                return
                
            # Get decryption key
            key = self.extract_key_entry.get().strip()
            if key:
                # Pad or truncate key to 32 bytes for AES-256
                key_bytes = key.encode('utf-8')
                if len(key_bytes) < 32:
                    key_bytes = key_bytes.ljust(32, b'\0')
                elif len(key_bytes) > 32:
                    key_bytes = key_bytes[:32]
            else:
                key_bytes = None
                
            # Extract message
            extracted_message = self.steg.extract_data(
                self.extract_image_path.get(),
                key_bytes
            )
            
            # Display result
            self.result_text.config(state='normal')
            self.result_text.delete("1.0", tk.END)
            self.result_text.insert("1.0", extracted_message)
            self.result_text.config(state='disabled')
            
            messagebox.showinfo("Success", "Message successfully extracted!")
            
        except Exception as e:
            messagebox.showerror("Error", f"Error extracting message: {str(e)}")
            self.result_text.config(state='normal')
            self.result_text.delete("1.0", tk.END)
            self.result_text.insert("1.0", f"Extraction failed: {str(e)}")
            self.result_text.config(state='disabled')

if __name__ == "__main__":
    root = tk.Tk()
    app = SteganographyGUI(root)
    root.mainloop()
