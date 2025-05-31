from tkinter import filedialog, messagebox, simpledialog
import tkinter as tk
from cryptography.fernet import Fernet
import threading
import time
import psutil
import sys
import os
from PyKCS11 import *

class RutokenManager:
    def __init__(self):
        self.pkcs11 = PyKCS11Lib()
        self.pkcs11.load('C:/Windows/System32/rtPKCS11ECP.dll')
        self.session = None
        
    def connect(self, pin=None):
        """Подключение к токену с запросом PIN-кода через GUI"""
        try:
            # Если сессия уже открыта, сначала закроем ее
            if self.session:
                self.disconnect()
                
            # Запрашиваем PIN-код, если он не передан
            if pin is None:
                pin = self.request_pin()
                if pin is None:  # Пользователь отменил ввод
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
        """Закрытие сессии с токеном"""
        try:
            if self.session:
                self.session.logout()
                self.session.closeSession()
                self.session = None
        except Exception:
            pass  # Игнорируем ошибки при закрытии сессии

    def request_pin(self):
        """Отображает диалоговое окно для ввода PIN-кода токена"""
        root = tk.Tk()
        root.withdraw()  # Скрываем основное окно
        pin = simpledialog.askstring(
            "PIN-код токена", 
            "Введите PIN-код для доступа к USB-токену:",
            show='*'
        )
        root.destroy()
        return pin
    
    def find_gost_keys(self):
        try:
            # Ищем закрытый ключ ГОСТ
            priv_key = self.session.findObjects([
                (CKA_CLASS, CKO_PRIVATE_KEY),
                (CKA_KEY_TYPE, CKK_GOSTR3410)
            ])
            
            if not priv_key:
                raise Exception("На токене не найден закрытый ключ ГОСТ")
            
            # Ищем сертификат
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
                
            # Хеширование по ГОСТ
            digest = self.session.digest(data, Mechanism(CKM_GOSTR3411, None))
            
            # Подпись по ГОСТ
            signature = self.session.sign(priv_key, digest, Mechanism(CKM_GOSTR3410, None))
            
            return bytes(signature)
        except Exception as e:
            messagebox.showerror("Ошибка", f"Не удалось подписать: {str(e)}")
            return None
        
class USBEncryptorPro:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("Мама не узнает")
        self.root.geometry("650x450")
        self.rutoken = RutokenManager()

        self.key_path = None
        self.key = None
        self.fernet = None
        self.target_dir = None
        self.running = False
        self.encrypted_ext = ".encrypted"
        self.usb_inserted = False
        
        self.root.configure(bg='#f0f0f0')
        self.create_widgets()
        
    def create_widgets(self):
        header = tk.Label(self.root, text="Мама не узнает PRO+ 512GB", 
                         font=('Arial', 16, 'bold'), bg='#f0f0f0') 
        header.pack(pady=10)
        
        sign_frame = tk.Frame(self.root, bg='#f0f0f0')
        sign_frame.pack(pady=5, fill='x', padx=20)
        
        tk.Button(sign_frame, text="Подписать файл", 
                 command=self.sign_file_dialog).pack(side='top', padx=125)
        tk.Button(sign_frame, text="Проверить подпись", 
                 command=self.verify_signature_dialog).pack(side='top', padx=35, pady=5)
        
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
    
    def sign_file(self, file_path):
        """Подписание файла через Рутокен с запросом PIN-кода"""
        try:
            # Запрашиваем подключение (вызовет диалог ввода PIN)
            if not self.rutoken.connect():
                return False
            
            with open(file_path, "rb") as f:
                data = f.read()
            
            # Создаем подпись по ГОСТ
            signature = self.rutoken.gost_sign(data)
            
            # Закрываем сессию после операции
            self.rutoken.disconnect()
            
            if not signature:
                return False
            
            # Сохраняем подпись в файл
            signature_path = file_path + ".sig"
            with open(signature_path, "wb") as f:
                f.write(signature)
            
            self.log(f"Файл подписан: {os.path.basename(file_path)}")
            return True
            
        except Exception as e:
            self.log(f"Ошибка подписи: {str(e)}")
            return False
    
    def verify_gost_signature(self, file_path, signature_path):
        try:
            # Запрашиваем подключение (вызовет диалог ввода PIN)
            if not self.rutoken.connect():
                return False

            # Получаем публичный ключ с токена
            _, cert = self.rutoken.find_gost_keys()
            if not cert:
                self.rutoken.disconnect()
                return False
            
            # Загружаем данные
            with open(file_path, "rb") as f:
                data = f.read()
            
            with open(signature_path, "rb") as f:
                signature = f.read()
        
            # Хешируем данные через токен
            digest = self.rutoken.session.digest(data, Mechanism(CKM_GOSTR3411, None))
        
            # Проверяем подпись
            pub_key = self.rutoken.session.findObjects([(CKA_CLASS, CKO_PUBLIC_KEY)])[0]
            result = self.rutoken.session.verify(
                pub_key,
                digest,
                signature,
                Mechanism(CKM_GOSTR3410, None)
            )
            
            # Закрываем сессию после операции
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
        file_path = filedialog.askopenfilename(
            title="Выберите файл для проверки"
        )
        if file_path:
            signature_path = filedialog.askopenfilename(
            title="Выберите файл с подписью (.sig)",
            filetypes=[("Подписи ГОСТ", "*.sig"), ("Все файлы", "*.*")]
            )
            if signature_path:
                if self.verify_gost_signature(file_path, signature_path):
                    messagebox.showinfo("Успех", "Подпись верна!")
                else:
                    messagebox.showerror("Ошибка", "Подпись недействительна или файл изменен!")

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
                
                if action == "encrypt":
                    if not file.endswith(self.encrypted_ext):
                        if self.encrypt_file(full_path):
                            processed_files += 1
                elif action == "decrypt":
                    if file.endswith(self.encrypted_ext):
                        if self.decrypt_file(full_path):
                            processed_files += 1
        
        elapsed = time.time() - start_time
        self.log(f"Обработано файлов: {processed_files}, время: {elapsed:.2f} сек.")
    
    def check_usb_status(self):
        current_status = os.path.exists(self.key_path) if self.key_path else False
        
        if current_status != self.usb_inserted:
            self.usb_inserted = current_status
            if current_status:
                self.usb_status.config(text=f"Флешка с ключом: ОБНАРУЖЕНА ({self.key_path})", fg='green')
                self.log("Флешка подключена")
                self.process_directory("decrypt")
            else:
                self.usb_status.config(text="Флешка с ключом: НЕ ОБНАРУЖЕНА", fg='red')
                self.log("Флешка извлечена!")
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
            messagebox.showerror("Ошибка", "Выберите директорию для защиты!")
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
        if messagebox.askokcancel("Выход", "Вы уверены, что хотите выйти?\nФайлы останутся в текущем состоянии защиты."):
            self.stop_monitoring()
            self.root.destroy()

if __name__ == "__main__":
    app = USBEncryptorPro()
    app.run()