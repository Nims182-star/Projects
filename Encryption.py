from cryptography.fernet import Fernet
import base64
import os
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

class TextEncryptor:
    def __init__(self):
        """Initialize the encryptor with a new key"""
        self.salt = os.urandom(16)
        
    def generate_key(self, password):
        """Generate a key from a password using PBKDF2"""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=self.salt,
            iterations=100000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
        return key

    def encrypt_text(self, text, password):
        """Encrypt text using the provided password"""
        try:
            key = self.generate_key(password)
            f = Fernet(key)
            encrypted_text = f.encrypt(text.encode())
            # Return both salt and encrypted text
            return base64.urlsafe_b64encode(self.salt).decode() + ":" + encrypted_text.decode()
        except Exception as e:
            return f"Encryption error: {str(e)}"

    def decrypt_text(self, encrypted_data, password):
        """Decrypt text using the provided password"""
        try:
            # Split salt and encrypted text
            salt_str, encrypted_text = encrypted_data.split(":")
            self.salt = base64.urlsafe_b64decode(salt_str.encode())
            
            key = self.generate_key(password)
            f = Fernet(key)
            decrypted_text = f.decrypt(encrypted_text.encode())
            return decrypted_text.decode()
        except Exception as e:
            return f"Decryption error: {str(e)}"

def main():
    encryptor = TextEncryptor()
    
    while True:
        print("\nText Encryption Utility")
        print("1. Encrypt Text")
        print("2. Decrypt Text")
        print("3. Exit")
        
        choice = input("Enter your choice (1-3): ")
        
        if choice == '1':
            text = input("Enter text to encrypt: ")
            password = input("Enter encryption password: ")
            encrypted = encryptor.encrypt_text(text, password)
            print("\nEncrypted text:", encrypted)
            
        elif choice == '2':
            encrypted_text = input("Enter encrypted text: ")
            password = input("Enter decryption password: ")
            decrypted = encryptor.decrypt_text(encrypted_text, password)
            print("\nDecrypted text:", decrypted)
            
        elif choice == '3':
            print("Goodbye!")
            break
            
        else:
            print("Invalid choice. Please try again.")

if __name__ == "__main__":
    main()
