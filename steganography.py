import numpy as np
from PIL import Image
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import binascii
import logging

class AdvancedSteganography:
    def __init__(self):
        self.HEADER_SIZE = 32  # bytes
        self.CRC_SIZE = 4       # bytes
        
    def encrypt_message(self, key, message):
        """Encrypt message using AES encryption"""
        try:
            cipher = AES.new(key, AES.MODE_CBC)
            ct_bytes = cipher.encrypt(pad(message.encode(), AES.block_size))
            return cipher.iv + ct_bytes
        except Exception as e:
            logging.error(f"Encryption error: {e}")
            raise ValueError("Failed to encrypt message")
        
    def decrypt_message(self, key, encrypted):
        """Decrypt message using AES decryption"""
        try:
            iv = encrypted[:16]
            ct = encrypted[16:]
            cipher = AES.new(key, AES.MODE_CBC, iv=iv)
            return unpad(cipher.decrypt(ct), AES.block_size).decode()
        except Exception as e:
            logging.error(f"Decryption error: {e}")
            raise ValueError("Failed to decrypt message - wrong key or corrupted data")
        
    def embed_data(self, image_path, secret_msg, output_path, key=None):
        """Embed secret message into image using LSB steganography"""
        try:
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
            
        except Exception as e:
            logging.error(f"Embedding error: {e}")
            raise ValueError(f"Failed to embed data: {str(e)}")

    def extract_data(self, image_path, key=None):
        """Extract hidden message from steganographic image"""
        try:
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
            
        except Exception as e:
            logging.error(f"Extraction error: {e}")
            if isinstance(e, ValueError):
                raise
            else:
                raise ValueError(f"Failed to extract data: {str(e)}")
