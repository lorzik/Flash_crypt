import os
import tkinter as tk
from tkinter import filedialog, messagebox
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives import serialization
import threading
import time
import psutil
import ctypes
import sys
import base64

class USBEncryptorPro:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("Мама не узнает")
        self.root.geometry("650x450")
        
        self.key_path = None
        self.key = None
        self.fernet = None
        self.target_dir = None
        self.running = False
        self.encrypted_ext = ".encrypted"
        self.signed_ext = ".signed"
        self.usb_inserted = False
        
        self.private_key = None
        self.public_key = None
        self.private_key_path = None
        self.public_key_path = None
        
        self.root.configure(bg='#f0f0f0')
        self.button_style = {'bg': '#4CAF50', 'fg': 'white', 'activebackground': '#45a049'}
        self.stop_button_style = {'bg': '#f44336', 'fg': 'white', 'activebackground': '#d32f2f'}
        
        self.create_widgets()
        self.load_or_generate_keys()
    
    def load_or_generate_keys(self):
        """Загружает или генерирует ключи на подключенной флешке"""
        usb_drives = self.get_usb_drives()
        key_found = False
        
        for drive in usb_drives:
            private_path = os.path.join(drive, "private_key.pem")
            public_path = os.path.join(drive, "public_key.pem")
            
            if os.path.exists(private_path) and os.path.exists(public_path):
                try:
                    with open(private_path, "rb") as f:
                        self.private_key = serialization.load_pem_private_key(
                            f.read(),
                            password=None
                        )
                    with open(public_path, "rb") as f:
                        self.public_key = serialization.load_pem_public_key(
                            f.read()
                        )
                    self.private_key_path = private_path
                    self.public_key_path = public_path
                    key_found = True
                    self.log("Ключи успешно загружены с флешки")
                    break
                except Exception as e:
                    self.log(f"Ошибка загрузки ключей: {str(e)}")
        
        if not key_found and usb_drives:
            # Генерируем новые ключи на первой доступной флешке
            drive = usb_drives[0]
            self.private_key_path = os.path.join(drive, "private_key.pem")
            self.public_key_path = os.path.join(drive, "public_key.pem")
            
            try:
                self.private_key = rsa.generate_private_key(
                    public_exponent=65537,
                    key_size=2048
                )
                self.public_key = self.private_key.public_key()
                
                # Сохраняем ключи на флешку
                with open(self.private_key_path, "wb") as f:
                    f.write(self.private_key.private_bytes(
                        encoding=serialization.Encoding.PEM,
                        format=serialization.PrivateFormat.PKCS8,
                        encryption_algorithm=serialization.NoEncryption()
                    ))
                
                with open(self.public_key_path, "wb") as f:
                    f.write(self.public_key.public_bytes(
                        encoding=serialization.Encoding.PEM,
                        format=serialization.PublicFormat.SubjectPublicKeyInfo
                    ))
                
                self.log("Новые ключи сгенерированы и сохранены на флешку")
            except Exception as e:
                messagebox.showerror("Ошибка", f"Не удалось сохранить ключи на флешку: {str(e)}")
                self.private_key = None
                self.public_key = None
    
    def check_keys_available(self):
        """Проверяет доступность ключей на флешке"""
        if not self.private_key or not self.public_key:
            usb_drives = self.get_usb_drives()
            for drive in usb_drives:
                private_path = os.path.join(drive, "private_key.pem")
                if os.path.exists(private_path):
                    self.load_or_generate_keys()
                    return True
            return False
        return True
    
    def sign_file(self, file_path):
        """Подписывает файл с использованием ключа с флешки"""
        if not self.check_keys_available():
            messagebox.showerror("Ошибка", "Не найден ключ для подписи на подключенных флешках!")
            return False
            
        try:
            with open(file_path, "rb") as f:
                data = f.read()
            
            signature = self.private_key.sign(
                data,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            
            # Сохраняем подпись в отдельный файл
            signature_path = file_path + self.signed_ext
            with open(signature_path, "wb") as f:
                f.write(base64.b64encode(signature))
            
            self.log(f"Файл подписан: {os.path.basename(file_path)}")
            return True
        except Exception as e:
            self.log(f"Ошибка при подписании файла: {str(e)}")
            return False
    
    def verify_signature(self, file_path, signature_path):
        """Проверяет подпись с использованием ключа с флешки"""
        if not self.check_keys_available():
            messagebox.showerror("Ошибка", "Не найден ключ для проверки на подключенных флешках!")
            return False
            
        try:
            with open(file_path, "rb") as f:
                data = f.read()
            
            with open(signature_path, "rb") as f:
                signature = base64.b64decode(f.read())
            
            self.public_key.verify(
                signature,
                data,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            
            self.log(f"Подпись верна: {os.path.basename(file_path)}")
            return True
        except Exception as e:
            self.log(f"Ошибка проверки подписи: {str(e)}")
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
                title="Выберите файл с подписью",
                filetypes=[("Signature files", f"*{self.signed_ext}")]
            )
            if signature_path:
                if self.verify_signature(file_path, signature_path):
                    messagebox.showinfo("Успех", "Подпись верна!")
                else:
                    messagebox.showerror("Ошибка", "Подпись недействительна или файл изменен!")
    def create_widgets(self):
        header = tk.Label(self.root, text="Мама не узнает PRO+ 512GB", font=('Arial', 16, 'bold'), bg='#f0f0f0') 
        header.pack(pady=10)
        sign_frame = tk.Frame(self.root, bg='#f0f0f0')
        sign_frame.pack(pady=5, fill='x', padx=20)
        
        tk.Button(sign_frame, text="Подписать файл", 
                 command=self.sign_file_dialog).pack(side='top', padx=125)
        tk.Button(sign_frame, text="Проверить подпись", 
                 command=self.verify_signature_dialog).pack(side='top', padx=35,pady=5)
        
        dir_frame = tk.Frame(self.root, bg='#f0f0f0')
        dir_frame.pack(pady=5, fill='x', padx=20)
        
        tk.Label(dir_frame, text="Директория для мониторинга:", bg='#f0f0f0').pack(side='left')
        self.dir_label = tk.Label(dir_frame, text="Не выбрано", 
                                width=40, bg='white', anchor='w')
        self.dir_label.pack(side='left', padx=5)
        
        tk.Button(dir_frame, text="Выбрать", command=self.select_directory).pack(side='left')

        self.usb_status = tk.Label(self.root, text="Флешка с ключом: не обнаружена", 
                                 font=('Arial', 10), fg='red', bg='#f0f0f0')
        self.usb_status.pack(pady=5)

        btn_frame = tk.Frame(self.root, bg='#f0f0f0')
        btn_frame.pack(pady=10)
        
        self.start_button = tk.Button(btn_frame, text="АКТИВИРОВАТЬ ЗАЩИТУ", 
                                    command=self.start_monitoring, 
                                    font=('Arial', 10, 'bold'))
        self.start_button.pack(side='left', padx=5)
        
        self.stop_button = tk.Button(btn_frame, text="ОСТАНОВИТЬ", 
                                   command=self.stop_monitoring, state='disabled',
                                   font=('Arial', 10, 'bold'))
        self.stop_button.pack(side='left', padx=5)
        
        log_frame = tk.Frame(self.root, bg='white', bd=2, relief='sunken')
        log_frame.pack(pady=10, padx=20, fill='both', expand=True)
        
        scrollbar = tk.Scrollbar(log_frame)
        scrollbar.pack(side='right', fill='y')
        
        self.log_text = tk.Text(log_frame, height=10, width=70, yscrollcommand=scrollbar.set,
                              bg='black', fg='lime', font=('Consolas', 9))
        self.log_text.pack(fill='both', expand=True)
        
        scrollbar.config(command=self.log_text.yview)
        
        self.protection_status = tk.Label(self.root, text="ЗАЩИТА НЕ АКТИВНА", 
                                        font=('Arial', 12, 'bold'), fg='red', bg='#f0f0f0')
        self.protection_status.pack(pady=5)
    def select_directory(self):
        selected_dir = filedialog.askdirectory()
        if selected_dir:
            self.target_dir = selected_dir
            self.dir_label.config(text=self.target_dir)
            self.log(f"Выбрана директория: {self.target_dir}")
            
            if self.initialize_encryption():
                self.start_button.config(state='normal')
    
    def initialize_encryption(self):
        self.key_path = self.find_usb_key()
        
        if self.key_path:
            try:
                with open(self.key_path, "rb") as f:
                    self.key = f.read()
                self.fernet = Fernet(self.key)
                self.usb_status.config(text=f"Флешка с ключом: ОБНАРУЖЕНА ({self.key_path})", fg='green')
                self.log(f"Ключ загружен с {self.key_path}")
                self.usb_inserted = True
                return True
            except Exception as e:
                self.log(f"Не удалось загрузить ключ: {str(e)}")
                return False
        else:
            self.key = Fernet.generate_key()
            usb_drives = self.get_usb_drives()
            
            if usb_drives:
                for drive in usb_drives:
                    try:
                        key_file = os.path.join(drive, "secret.key")
                        with open(key_file, "wb") as f:
                            f.write(self.key)
                        self.key_path = key_file
                        self.fernet = Fernet(self.key)
                        self.usb_status.config(text=f"Флешка с ключом: ОБНАРУЖЕНА ({self.key_path})", fg='green')
                        self.log(f"Новый ключ создан и сохранен на {self.key_path}")
                        self.usb_inserted = True
                        return True
                    except Exception as e:
                        self.log(f"Не удалось сохранить ключ на {drive}: {str(e)}")
                        continue
            
            messagebox.showwarning("Внимание", "Не найдена флешка для сохранения ключа!")
            self.log("Не найдена флешка для сохранения ключа!")
            return False
    
    def find_usb_key(self):
        usb_drives = self.get_usb_drives()
        for drive in usb_drives:
            key_file = os.path.join(drive, "secret.key")
            if os.path.exists(key_file):
                return key_file
        return None
    
    def get_usb_drives(self):
        usb_drives = []
        if sys.platform == 'win32':
            drives = psutil.disk_partitions()
            for drive in drives:
                if 'removable' in drive.opts:
                    usb_drives.append(drive.mountpoint)
        else:
            drives = ["/media/" + d for d in os.listdir("/media/") if os.path.ismount("/media/" + d)]
            usb_drives.extend(drives)
        
 
        if not usb_drives and sys.platform == 'win32':
            for letter in "EFGHIJKLMNOPQRSTUVWXYZ":
                if os.path.exists(letter + ":\\"):
                    usb_drives.append(letter + ":\\")
        
        return usb_drives
    
    def log(self, message):
        timestamp = time.strftime("%H:%M:%S", time.localtime())
        self.log_text.insert("end", f"[{timestamp}] {message}\n")
        self.log_text.see("end")
        self.root.update()
    
    def encrypt_file(self, file_path):
        if file_path.endswith(self.encrypted_ext):
            return
        
        try:
            with open(file_path, "rb") as f:
                data = f.read()
            
            encrypted = self.fernet.encrypt(data)
            
            encrypted_path = file_path + self.encrypted_ext
            with open(encrypted_path, "wb") as f:
                f.write(encrypted)
            
            os.remove(file_path)
            self.log(f"Шифрование прошло успешно: {os.path.basename(file_path)}")
            return True
        except Exception as e:
            self.log(f"Ошибка при шифровании {os.path.basename(file_path)}: {str(e)}")
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
            self.log(f"Дешифрование прошло успешно: {os.path.basename(original_path)}")
            return True
        except Exception as e:
            self.log(f"Ошибка при дешифровании {os.path.basename(file_path)}: {str(e)}")
            return False
    
    def process_directory(self, action):

        if not self.target_dir or not os.path.exists(self.target_dir):
            self.log("Целевая директория не существует!")
            return
        
        processed_files = 0
        start_time = time.time()
        
        for root, _, files in os.walk(self.target_dir):
            for file in files:
                full_path = os.path.join(root, file)
                
                if action == "encrypt":
                    if not file.endswith(self.encrypted_ext):
                        if self.encrypt_file(full_path):
                            processed_files += 1
                elif action == "decrypt":
                    if file.endswith(self.encrypted_ext):
                        if self.decrypt_file(full_path):
                            processed_files += 1
        
        elapsed = time.time() - start_time
        self.log(f"Обработано {processed_files} файлов за {elapsed:.2f} сек.")
    
    def check_usb_status(self):
        current_status = os.path.exists(self.key_path) if self.key_path else False
        
        if current_status != self.usb_inserted:
            self.usb_inserted = current_status
            if current_status:
                self.usb_status.config(text=f"Флешка с ключом: ОБНАРУЖЕНА ({self.key_path})", fg='green')
                self.log("Флешка с ключом подключена")
                self.process_directory("decrypt")
            else:
                self.usb_status.config(text="Флешка с ключом: НЕ ОБНАРУЖЕНА", fg='red')
                self.log("Флешка с ключом извлечена!")
                self.process_directory("encrypt")
        
        return current_status
    
    def monitoring_loop(self):
        while self.running:
            self.check_usb_status()
            
            if self.usb_inserted:
                self.protection_status.config(text="ЗАЩИТА АКТИВНА", fg='green')
            else:
                self.protection_status.config(text="ФАЙЛЫ ЗАШИФРОВАНЫ", fg='red')
            
            time.sleep(1)
    
    def start_monitoring(self):
        if not self.target_dir:
            messagebox.showerror("Ошибка", "Сначала выберите директорию для защиты!")
            return
        
        if not self.fernet:
            messagebox.showerror("Ошибка", "Ключ шифрования не инициализирован!")
            return
        
        self.running = True
        self.start_button.config(state='disabled')
        self.stop_button.config(state='normal')
        
        self.check_usb_status()
        
        self.monitor_thread = threading.Thread(target=self.monitoring_loop, daemon=True)
        self.monitor_thread.start()
        
        self.log("Система защиты активирована")
    
    def stop_monitoring(self):
        self.running = False
        self.start_button.config(state='normal')
        self.stop_button.config(state='disabled')
        self.protection_status.config(text="ЗАЩИТА НЕ АКТИВНА", fg='red')
        self.log("Система защиты остановлена")
    
    def run(self):
        try:
            self.root.protocol("WM_DELETE_WINDOW", self.on_close)
            self.root.mainloop()
        except Exception as e:
            self.log(f"[КРИТИЧЕСКАЯ ОШИБКА] {str(e)}")
    
    def on_close(self):
        if messagebox.askokcancel("Ливнуть", "Вы знаете что это кнопка выхода?\nФайлы останутся в текущем состоянии защиты."):
            self.stop_monitoring()
            self.root.destroy()

if __name__ == "__main__":
    app = USBEncryptorPro()
    app.run()