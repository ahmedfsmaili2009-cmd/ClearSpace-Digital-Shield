import os
import re
import urllib.parse
import hashlib
import base64
import difflib
import customtkinter as ctk
from tkinter import filedialog
from PIL import Image
from cryptography.fernet import Fernet

ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")

class ClearSpaceApp(ctk.CTk):
    def __init__(self):
        super().__init__()

        self.title("ClearSpace: Digital Shield")
        self.geometry("750x550")
        self.resizable(False, False)

        self.tabview = ctk.CTkTabview(self, width=700, height=500)
        self.tabview.pack(pady=15)

        self.tabview.add("Photo Scrubber")
        self.tabview.add("URL Unmasker")
        self.tabview.add("Secure Vault")

        self.setup_photo_scrubber_tab()
        self.setup_url_unmasker_tab()
        self.setup_secure_vault_tab()

    # ==========================================
    # TAB 1: Photo Scrubber UI & LOGIC
    # ==========================================
    def setup_photo_scrubber_tab(self):
        tab = self.tabview.tab("Photo Scrubber")
        ctk.CTkLabel(tab, text="Photo Privacy Scrubber", font=("Arial", 22, "bold")).pack(pady=(20, 5))
        ctk.CTkLabel(tab, text="Deep scan and purge EXIF metadata (GPS, Device Info) before sharing.", text_color="gray", font=("Arial", 13)).pack(pady=(0, 20))

        self.file_path_label = ctk.CTkLabel(tab, text="[ No image selected ]", text_color="#007bff", font=("Arial", 12))
        self.file_path_label.pack(pady=(0, 20))

        ctk.CTkButton(tab, text="1. Select Image", command=self.select_image, width=220, font=("Arial", 14)).pack(pady=10)
        self.scrub_btn = ctk.CTkButton(tab, text="2. Scrub Metadata & Secure", command=self.scrub_image, 
                                       fg_color="#28a745", hover_color="#218838", state="disabled", width=220, font=("Arial", 14, "bold"))
        self.scrub_btn.pack(pady=10)

        self.status_label = ctk.CTkLabel(tab, text="", font=("Courier New", 14))
        self.status_label.pack(pady=20)
        self.selected_image_path = None

    def select_image(self):
        file_path = filedialog.askopenfilename(title="Select an Image", filetypes=[("Image Files", "*.jpg *.jpeg *.png")])
        if file_path:
            self.selected_image_path = file_path
            self.file_path_label.configure(text=f"Target: {os.path.basename(file_path)}")
            self.scrub_btn.configure(state="normal")
            self.status_label.configure(text="Ready for deep scrub...", text_color="yellow")

    def scrub_image(self):
        if not self.selected_image_path: return
        try:
            img = Image.open(self.selected_image_path)
            orig_format = img.format or "PNG" 
            
            directory, filename = os.path.split(self.selected_image_path)
            
            if filename.startswith(".") and filename.count(".") == 1:
                name, ext = "image", filename
            else:
                name, ext = os.path.splitext(filename)
                
            secure_filename = f"{name}_secured{ext}"
            secure_path = os.path.join(directory, secure_filename)
            
            pixel_data = list(img.getdata())
            clean_image = Image.new(img.mode, img.size)
            clean_image.putdata(pixel_data)
            
            clean_image.save(secure_path, format=orig_format)
            
            success_msg = f"[-] EXIF Data Purged\n[-] GPS Location Removed\n[+] Saved as: {secure_filename}"
            self.status_label.configure(text=success_msg, text_color="#28a745")
        except Exception as e:
            self.status_label.configure(text=f"Error: {str(e)}", text_color="#dc3545")

    # ==========================================
    # TAB 2: URL Unmasker UI & LOGIC
    # ==========================================
    def setup_url_unmasker_tab(self):
        tab = self.tabview.tab("URL Unmasker")
        ctk.CTkLabel(tab, text="Heuristic URL Analyzer", font=("Arial", 22, "bold")).pack(pady=(20, 5))
        ctk.CTkLabel(tab, text="Offline engine to detect phishing and unmask suspicious links.", text_color="gray", font=("Arial", 13)).pack(pady=(0, 20))

        self.url_entry = ctk.CTkEntry(tab, placeholder_text="Paste suspicious URL here...", width=550, height=40, font=("Arial", 14))
        self.url_entry.pack(pady=10)

        ctk.CTkButton(tab, text="Scan Link", command=self.analyze_url, width=200, fg_color="#007bff", font=("Arial", 14, "bold")).pack(pady=10)

        ctk.CTkLabel(tab, text="Threat Level:", font=("Arial", 12)).pack(pady=(10, 0))
        self.risk_meter = ctk.CTkProgressBar(tab, width=400, height=15)
        self.risk_meter.set(0)
        self.risk_meter.pack(pady=5)

        self.result_textbox = ctk.CTkTextbox(tab, width=550, height=130, font=("Courier New", 13), state="disabled", fg_color="#1e1e1e")
        self.result_textbox.pack(pady=10)

    def analyze_url(self):
        raw_url = self.url_entry.get().strip().lower()
        if not raw_url:
            self.update_result_box("Error: Empty URL provided.", "#dc3545", 0)
            return

        if not raw_url.startswith("http://") and not raw_url.startswith("https://"):
            url_to_parse = "http://" + raw_url
        else:
            url_to_parse = raw_url

        risk_score = 0
        findings = []
        parsed_url = urllib.parse.urlparse(url_to_parse)
        domain = parsed_url.netloc
        path = parsed_url.path

        if parsed_url.scheme != "https":
            risk_score += 40
            findings.append("[!] No SSL/TLS encryption (HTTP used).")
            
        if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", domain):
            risk_score += 50
            findings.append("[!] Domain hidden behind raw IP address.")
        
        suspicious_keywords = ['login', 'verify', 'update', 'secure', 'bank', 'free', 'account', 'auth']
        found_keywords = [kw for kw in suspicious_keywords if kw in domain or kw in path]
        if found_keywords:
            risk_score += (30 * len(found_keywords))
            findings.append(f"[!] Phishing keywords detected: {', '.join(found_keywords)}")

        popular_brands = ['instagram', 'facebook', 'paypal', 'google', 'microsoft', 'apple', 'netflix', 'amazon', 'devpost']
        domain_main = domain.split('.')[0] if '.' in domain else domain
        
        for brand in popular_brands:
            similarity = difflib.SequenceMatcher(None, domain_main, brand).ratio()
            if 0.70 <= similarity < 1.0:
                risk_score += 60
                findings.append(f"[!] Brand Impersonation: Domain resembles '{brand}' (Typosquatting).")

        final_score = min(risk_score, 100)
        
        if final_score >= 70:
            status, color = "CRITICAL RISK: Phishing/Malware likely.", "#dc3545"
        elif final_score >= 40:
            status, color = "WARNING: Suspicious indicators found.", "#ffc107"
        else:
            status, color = "SAFE: No offline heuristic threats detected.", "#28a745"

        report = f"Engine Status: {status}\nScore: {final_score}/100\n\nLog:\n"
        report += "- Clean structure.\n" if not findings else "\n".join(findings)
        
        self.update_result_box(report, color, final_score)

    def update_result_box(self, text, color, score):
        self.risk_meter.set(score / 100.0)
        self.risk_meter.configure(progress_color=color)
        self.result_textbox.configure(state="normal", text_color=color)
        self.result_textbox.delete("1.0", "end")
        self.result_textbox.insert("1.0", text)
        self.result_textbox.configure(state="disabled")

    # ==========================================
    # TAB 3: Secure Vault UI & LOGIC
    # ==========================================
    def setup_secure_vault_tab(self):
        tab = self.tabview.tab("Secure Vault")
        ctk.CTkLabel(tab, text="Military-Grade Local Vault", font=("Arial", 22, "bold")).pack(pady=(20, 5))
        ctk.CTkLabel(tab, text="Encrypt and decrypt files locally using AES (Fernet) cryptography.", text_color="gray", font=("Arial", 13)).pack(pady=(0, 15))

        self.vault_file_label = ctk.CTkLabel(tab, text="[ No file selected ]", text_color="#007bff", font=("Arial", 12))
        self.vault_file_label.pack(pady=(0, 10))

        ctk.CTkButton(tab, text="Browse Target File", command=self.select_vault_file, width=200).pack(pady=5)

        self.password_entry = ctk.CTkEntry(tab, placeholder_text="Enter Encryption Key (Password)", show="*", width=350, font=("Arial", 14))
        self.password_entry.pack(pady=15)

        btn_frame = ctk.CTkFrame(tab, fg_color="transparent")
        btn_frame.pack(pady=10)

        self.encrypt_btn = ctk.CTkButton(btn_frame, text="🔒 Encrypt", command=self.encrypt_file, 
                                         fg_color="#dc3545", hover_color="#c82333", state="disabled", width=150, font=("Arial", 14, "bold"))
        self.encrypt_btn.grid(row=0, column=0, padx=15)

        self.decrypt_btn = ctk.CTkButton(btn_frame, text="🔓 Decrypt", command=self.decrypt_file, 
                                         fg_color="#28a745", hover_color="#218838", state="disabled", width=150, font=("Arial", 14, "bold"))
        self.decrypt_btn.grid(row=0, column=1, padx=15)

        self.vault_status_label = ctk.CTkLabel(tab, text="", font=("Courier New", 13, "bold"))
        self.vault_status_label.pack(pady=15)
        
        self.selected_vault_path = None

    def select_vault_file(self):
        file_path = filedialog.askopenfilename(title="Select a File to Secure")
        if file_path:
            self.selected_vault_path = file_path
            self.vault_file_label.configure(text=f"Target: {os.path.basename(file_path)}")
            self.encrypt_btn.configure(state="normal")
            self.decrypt_btn.configure(state="normal")
            self.vault_status_label.configure(text="")

    def get_fernet_key(self):
        password = self.password_entry.get()
        if not password:
            raise ValueError("Encryption Key cannot be empty.")
        hasher = hashlib.sha256(password.encode('utf-8'))
        return base64.urlsafe_b64encode(hasher.digest())

    def get_robust_filename(self, path):
        directory, filename = os.path.split(path)
        if filename.startswith(".") and filename.count(".") == 1:
            return directory, f"file{filename}"
        return directory, filename

    def encrypt_file(self):
        if not self.selected_vault_path: return
        try:
            key = self.get_fernet_key()
            fernet = Fernet(key)
            
            with open(self.selected_vault_path, "rb") as file:
                original_data = file.read()
                
            encrypted_data = fernet.encrypt(original_data)
            directory, filename = self.get_robust_filename(self.selected_vault_path)
            
            # منع التشفير المزدوج عبر التحقق من الامتداد الجديد
            if filename.endswith(".locked"):
                self.vault_status_label.configure(text="File is already encrypted!", text_color="#ffc107")
                return

            # إضافة امتداد .locked للملف
            secure_filename = f"{filename}.locked"
            secure_path = os.path.join(directory, secure_filename)
            
            with open(secure_path, "wb") as file:
                file.write(encrypted_data)
                
            self.selected_vault_path = secure_path
            self.vault_file_label.configure(text=f"Target updated: {secure_filename}")
            self.vault_status_label.configure(text=f"[+] Secured successfully: {secure_filename}", text_color="#dc3545")
        except ValueError as ve:
            self.vault_status_label.configure(text=str(ve), text_color="#ffc107")
        except Exception as e:
            self.vault_status_label.configure(text="Error: Could not encrypt file.", text_color="#dc3545")

    def decrypt_file(self):
        if not self.selected_vault_path: return
        try:
            key = self.get_fernet_key()
            fernet = Fernet(key)
            
            with open(self.selected_vault_path, "rb") as file:
                encrypted_data = file.read()
                
            decrypted_data = fernet.decrypt(encrypted_data)
            directory, filename = self.get_robust_filename(self.selected_vault_path)
            
            # إزالة الامتداد .locked عند فك التشفير
            if filename.endswith(".locked"):
                new_name = filename[:-7]  # يحذف آخر 7 أحرف (.locked)
            elif filename.startswith("locked_"): # دعم للنسخة القديمة احتياطياً
                new_name = filename.replace("locked_", "", 1)
            else:
                new_name = f"unlocked_{filename}"
                
            secure_path = os.path.join(directory, new_name)
            
            with open(secure_path, "wb") as file:
                file.write(decrypted_data)
                
            self.selected_vault_path = secure_path
            self.vault_file_label.configure(text=f"Target updated: {new_name}")
            self.vault_status_label.configure(text=f"[+] Unlocked successfully: {new_name}", text_color="#28a745")
        except ValueError as ve:
            self.vault_status_label.configure(text=str(ve), text_color="#ffc107")
        except Exception:
            self.vault_status_label.configure(text="[!] Access Denied: Incorrect Password or unencrypted file.", text_color="#dc3545")

if __name__ == "__main__":
    app = ClearSpaceApp()
    app.mainloop()