from tkinter import filedialog, messagebox, simpledialog
import tkinter as tk
from cryptography.fernet import Fernet, InvalidToken
import threading
import time
import os
from PyKCS11 import *
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
import base64
import hashlib

class RutokenManager:
    def __init__(self):
        self.pkcs11 = PyKCS11Lib()
        try:
            self.pkcs11.load('C:/../rtPKCS11ECP.dll')
        except Exception as e:
            messagebox.showerror("Ошибка", f"Не удалось загрузить библиотеку Рутокен: {str(e)}")
        self.session = None
        
    def connect(self, pin=None):
        try:
            if self.session:
                self.disconnect()
                
            if pin is None:
                pin = self.request_pin()
                if pin is None:
                    return False
            
            slots = self.pkcs11.getSlotList()
            if not slots:
                raise Exception("Не найдены доступные слоты Рутокен")
            
            self.session = self.pkcs11.openSession(slots[0])
            self.session.login(pin)
            return True
        except Exception as e:
            messagebox.showerror("Ошибка", f"Не удалось подключиться к Рутокен: {str(e)}")
            return False
            
    def disconnect(self):
        try:
            if self.session:
                self.session.logout()
                self.session.closeSession()
                self.session = None
        except Exception:
            pass

    def request_pin(self):
        root = tk.Tk()
        root.withdraw()
        pin = simpledialog.askstring(
            "PIN-код токена", 
            "Введите PIN-код для доступа к USB-токену:",
            show='*'
        )
        root.destroy()
        return pin
    
    def find_gost_keys(self):
        try:
            priv_key = self.session.findObjects([
                (CKA_CLASS, CKO_PRIVATE_KEY),
                (CKA_KEY_TYPE, CKK_GOSTR3410)
            ])
            
            if not priv_key:
                raise Exception("На токене не найден закрытый ключ ГОСТ")
            
            certs = self.session.findObjects([
                (CKA_CLASS, CKO_CERTIFICATE)
            ])
            
            if not certs:
                raise Exception("На токене не найден сертификат")
                
            return priv_key[0], certs[0]
        except Exception as e:
            messagebox.showerror("Ошибка", f"Ошибка поиска ключей ГОСТ: {str(e)}")
            return None, None
            
    def gost_sign(self, data):
        try:
            priv_key, _ = self.find_gost_keys()
            if not priv_key:
                return None
                
            digest = self.session.digest(data, Mechanism(CKM_GOSTR3411, None))
            
            signature = self.session.sign(priv_key, digest, Mechanism(CKM_GOSTR3410, None))
            
            return bytes(signature)
        except Exception as e:
            messagebox.showerror("Ошибка", f"Не удалось подписать: {str(e)}")
            return None
            
    def generate_key_from_token(self, pin=None):
        try:
            if not self.connect(pin):
                return None
            
            slot_list = self.pkcs11.getSlotList()
            if not slot_list:
                raise Exception("Не найдены доступные слоты Рутокен")
            
            token_info = self.pkcs11.getTokenInfo(slot_list[0])
            serial = token_info.serialNumber.strip()
        
            if pin is None:
                pin = self.request_pin()
                if not pin:
                    return None
            
            key_material = f"{serial}{pin}".encode()
            salt = hashlib.sha256(serial.encode()).digest()
        
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA512(),
                length=32,
                salt=salt,
                iterations=1000000,
                backend=default_backend()
            )
            key = base64.urlsafe_b64encode(kdf.derive(key_material))
        
            return key
        except Exception as e:
            messagebox.showerror("Ошибка", f"Не удалось сгенерировать ключ: {str(e)}")
            return None
        finally:
            self.disconnect()

class RutokenEncryptor:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("Лучшая программа в мире")
        self.root.geometry("700x550")
        self.rutoken = RutokenManager()

        self.key = None
        self.fernet = None
        self.target_dir = None
        self.running = False
        self.encrypted_ext = ".encrypted"
        self.token_inserted = False
        
        self.root.configure(bg='#f0f0f0')
        self.create_widgets()
        
    def create_widgets(self):
        header = tk.Label(self.root, text="Мама точно не узнает", 
                         font=('Arial', 16, 'bold'), bg='#f0f0f0') 
        header.pack(pady=10)
        
        sign_frame = tk.Frame(self.root, bg='#f0f0f0')
        sign_frame.pack(pady=5, fill='x', padx=20)
        
        tk.Button(sign_frame, text="Подписать файл", 
                 command=self.sign_file_dialog).pack(side='left', padx=10)
        tk.Button(sign_frame, text="Проверить подпись", 
                 command=self.verify_signature_dialog).pack(side='left', padx=10)
        
        dir_frame = tk.Frame(self.root, bg='#f0f0f0')
        dir_frame.pack(pady=5, fill='x', padx=20)
        
        tk.Label(dir_frame, text="Директория для работы:", bg='#f0f0f0').pack(side='left')
        self.dir_label = tk.Label(dir_frame, text="Не выбрано", 
                                width=40, bg='white', anchor='w')
        self.dir_label.pack(side='left', padx=5)
        tk.Button(dir_frame, text="Выбрать", command=self.select_directory).pack(side='left')

        crypto_frame = tk.Frame(self.root, bg='#f0f0f0')
        crypto_frame.pack(pady=10, fill='x', padx=20)
        
        tk.Button(crypto_frame, text="Зашифровать директорию", 
                command=lambda: self.encrypt_decrypt_directory("encrypt"),
                font=('Arial', 10, 'bold')).pack(side='left', padx=10)
        tk.Button(crypto_frame, text="Расшифровать директорию", 
                command=lambda: self.encrypt_decrypt_directory("decrypt"),
                font=('Arial', 10, 'bold')).pack(side='left', padx=10)

        self.token_status = tk.Label(self.root, text="Рутокен: не подключен", 
                                   font=('Arial', 10), fg='red', bg='#f0f0f0')
        self.token_status.pack(pady=5)

        log_frame = tk.Frame(self.root, bg='white', bd=2, relief='sunken')
        log_frame.pack(pady=10, padx=20, fill='both', expand=True)
        
        scrollbar = tk.Scrollbar(log_frame)
        scrollbar.pack(side='right', fill='y')
        
        self.log_text = tk.Text(log_frame, height=10, width=70, yscrollcommand=scrollbar.set,
                              bg='black', fg='lime', font=('Consolas', 9))
        self.log_text.pack(fill='both', expand=True)
        scrollbar.config(command=self.log_text.yview)
        
        

    def sign_file(self, file_path):
        try:
            pin = self.rutoken.request_pin()
            if pin is None:
                return False
                
            if not self.rutoken.connect(pin):
                return False
            
            with open(file_path, "rb") as f:
                data = f.read()
            
            signature = self.rutoken.gost_sign(data)
            
            self.rutoken.disconnect()
            
            if not signature:
                return False
            
            signature_path = file_path + ".sig"
            with open(signature_path, "wb") as f:
                f.write(signature)
            
            self.log(f"Файл подписан: {os.path.basename(file_path)}")
            return True
            
        except Exception as e:
            self.log(f"Ошибка подписи: {str(e)}")
            return False
    
    def verify_signature(self, file_path, signature_path):
        try:
            pin = self.rutoken.request_pin()
            if pin is None:
                return False
                
            if not self.rutoken.connect(pin):
                return False

            _, cert = self.rutoken.find_gost_keys()
            if not cert:
                self.rutoken.disconnect()
                return False
            
            with open(file_path, "rb") as f:
                data = f.read()
            
            with open(signature_path, "rb") as f:
                signature = f.read()
        
            digest = self.rutoken.session.digest(data, Mechanism(CKM_GOSTR3411, None))
        
            pub_key = self.rutoken.session.findObjects([(CKA_CLASS, CKO_PUBLIC_KEY)])[0]
            result = self.rutoken.session.verify(
                pub_key,
                digest,
                signature,
                Mechanism(CKM_GOSTR3410, None)
            )
            
            self.rutoken.disconnect()
        
            return bool(result)
        except Exception as e:
            self.log(f"Ошибка проверки: {str(e)}")
            return False
    
    def sign_file_dialog(self):
        file_path = filedialog.askopenfilename()
        if file_path:
            if self.sign_file(file_path):
                messagebox.showinfo("Успех", "Файл успешно подписан!")
            else:
                messagebox.showerror("Ошибка", "Не удалось подписать файл!")
    
    def verify_signature_dialog(self):
        file_path = filedialog.askopenfilename(title="Выберите файл для проверки")
        if file_path:
            signature_path = filedialog.askopenfilename(
                title="Выберите файл с подписью (.sig)",
                filetypes=[("Подписи ГОСТ", "*.sig"), ("Все файлы", "*.*")]
            )
            if signature_path:
                if self.verify_signature(file_path, signature_path):
                    messagebox.showinfo("Успех", "Подпись верна!")
                else:
                    messagebox.showerror("Ошибка", "Подпись недействительна или файл изменен!")

    def encrypt_decrypt_directory(self, action):
        if not self.target_dir:
            messagebox.showerror("Ошибка", "Сначала выберите директорию!")
            return
            
        if action == "encrypt":
            if not messagebox.askyesno("Подтверждение", 
                                     "Вы уверены, что хотите зашифровать ВСЕ файлы в выбранной директории?\n"
                                     "Без токена вы не сможете восстановить данные!"):
                return
                
        pin = self.rutoken.request_pin()
        if pin is None:
            return
            
        if not self.initialize_encryption(pin):
            messagebox.showerror("Ошибка", "Не удалось инициализировать ключ шифрования с Рутокен!")
            return
                
        self.process_directory(action)
        messagebox.showinfo("Готово", f"Директория успешно {'зашифрована' if action == 'encrypt' else 'расшифрована'}!")
    
    def select_directory(self):
        selected_dir = filedialog.askdirectory()
        if selected_dir:
            self.target_dir = selected_dir
            self.dir_label.config(text=self.target_dir)
            self.log(f"Выбрана директория: {self.target_dir}")
    
    def initialize_encryption(self, pin=None):
        try:
            self.key = self.rutoken.generate_key_from_token(pin)
            if self.key:
                self.fernet = Fernet(self.key)
                self.token_status.config(text="Рутокен: подключен", fg='green')
                self.log("Ключ успешно загружен с Рутокен")
                self.token_inserted = True
                return True
            return False
        except Exception as e:
            messagebox.showerror("Ошибка", f"Ошибка инициализации ключа: {str(e)}")
            self.log(f"Ошибка инициализации ключа: {str(e)}")
            return False
    
    def log(self, message):
        """Логирование сообщений"""
        timestamp = time.strftime("%H:%M:%S", time.localtime())
        self.log_text.insert("end", f"[{timestamp}] {message}\n")
        self.log_text.see("end")
        self.root.update()
    
    def encrypt_file(self, file_path):
        if file_path.endswith(self.encrypted_ext):
            return False
            
        try:
            with open(file_path, "rb") as f:
                data = f.read()
            
            encrypted = self.fernet.encrypt(data)
            
            encrypted_path = file_path + self.encrypted_ext
            with open(encrypted_path, "wb") as f:
                f.write(encrypted)
            
            os.remove(file_path)
            self.log(f"Зашифровано: {os.path.basename(file_path)}")
            return True
        except Exception as e:
            self.log(f"Ошибка шифрования {os.path.basename(file_path)}: {str(e)}")
            return False
    
    def decrypt_file(self, file_path):
        if not file_path.endswith(self.encrypted_ext):
            return False
            
        try:
            with open(file_path, "rb") as f:
                encrypted = f.read()
            
            decrypted = self.fernet.decrypt(encrypted)
            
            original_path = file_path[:-len(self.encrypted_ext)]
            with open(original_path, "wb") as f:
                f.write(decrypted)
            
            os.remove(file_path)
            self.log(f"Расшифровано: {os.path.basename(original_path)}")
            return True
        except InvalidToken:
            self.log(f"Ошибка: неверный ключ для файла {os.path.basename(file_path)}")
            messagebox.showerror("Ошибка", "Неверный ключ дешифрования! Убедитесь, что используется тот же Рутокен и PIN-код.")
            return False
        except Exception as e:
            self.log(f"Ошибка дешифрования {os.path.basename(file_path)}: {str(e)}")
            return False
    
    def process_directory(self, action):
        if not self.target_dir or not os.path.exists(self.target_dir):
            self.log("Директория не существует!")
            return
        
        processed_files = 0
        start_time = time.time()
        
        for root, _, files in os.walk(self.target_dir):
            for file in files:
                full_path = os.path.join(root, file)
                
                try:
                    if action == "encrypt":
                        if not file.endswith(self.encrypted_ext):
                            if self.encrypt_file(full_path):
                                processed_files += 1
                    elif action == "decrypt":
                        if file.endswith(self.encrypted_ext):
                            if self.decrypt_file(full_path):
                                processed_files += 1
                except Exception as e:
                    self.log(f"Ошибка обработки файла {file}: {str(e)}")
        
        elapsed = time.time() - start_time
        self.log(f"Обработано файлов: {processed_files}, время: {elapsed:.2f} сек.")
    
    def run(self):
        try:
            self.root.protocol("WM_DELETE_WINDOW", self.on_close)
            self.root.mainloop()
        except Exception as e:
            self.log(f"[КРИТИЧЕСКАЯ ОШИБКА] {str(e)}")
    
    def on_close(self):
        if messagebox.askokcancel("Выход", "Вы уверены, что хотите выйти?"):
            self.root.destroy()

if __name__ == "__main__":
    app = RutokenEncryptor()
    app.run()