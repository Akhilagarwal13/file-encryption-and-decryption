import hashlib
import os
import sys
import threading
import tkinter as tk
from pathlib import Path
from tkinter import *
from tkinter import filedialog, messagebox  # used to access GUI with our file explorer and  messages
from Cryptodome.Cipher import AES
class EncryptionTool:

    def __init__(self, user_file, user_key, user_salt, ):
        # get the path to input file
        self.user_file = user_file

        self.input_file_size = os.path.getsize(self.user_file)
        self.chunk_size = 1024
        self.total_chunks = self.input_file_size // self.chunk_size + 1

        # convert the key and salt to bytes
        self.user_key = bytes(user_key, "utf-8")
        self.user_salt = bytes(user_key[::-1], "utf-8")

        # get the file extension
        self.file_extension = self.user_file.split(".")[-1]

        # hash type for hashing key and salt
        self.hash_type = "SHA256"

        # encrypted file name
        self.encrypt_output_file = (".".join(self.user_file.split(".")[:-1]) + "." + self.file_extension + ".encr")

        # decrypted file name
        self.decrypt_output_file = self.user_file[:-5].split(".")
        self.decrypt_output_file = (
                    ".".join(self.decrypt_output_file[:-1]) + "_decrypted." + self.decrypt_output_file[-1])

        # dictionary to store hashed key and salt
        self.hashed_key_salt = dict()

        # hash key and salt into 16 bit hashes
        self.hash_key_salt()

    def read_in_chunks(self, file_object, chunk_size=1024):
        while True:
            data = file_object.read(chunk_size)
            if not data:
                break
            yield data

    def encrypt(self):
        # create a cipher object
        cipher_object = AES.new(self.hashed_key_salt["key"], AES.MODE_CFB, self.hashed_key_salt["salt"])
        self.abort()  # if the output file already exists, remove it first
        input_file = open(self.user_file, "rb")
        output_file = open(self.encrypt_output_file, "ab")
        done_chunks = 0
        for piece in self.read_in_chunks(input_file, self.chunk_size):
            encrypted_content = cipher_object.encrypt(piece)
            output_file.write(encrypted_content)
            done_chunks += 1
            yield done_chunks / self.total_chunks * 100
        input_file.close()
        output_file.close()

        # clean up the cipher object
        del cipher_object
    def decrypt(self):
        #  exact same as above function except in reverse
        cipher_object = AES.new(
            self.hashed_key_salt["key"], AES.MODE_CFB, self.hashed_key_salt["salt"])
        self.abort()  # if the output file already exists, remove it first
        input_file = open(self.user_file, "rb")
        output_file = open(self.decrypt_output_file, "xb")
        done_chunks = 0
        for piece in self.read_in_chunks(input_file):
            decrypted_content = cipher_object.decrypt(piece)
            output_file.write(decrypted_content)
            done_chunks += 1
            yield done_chunks / self.total_chunks * 100
        input_file.close()
        output_file.close()

        # clean up the cipher object
        del cipher_object

    def abort(self):
        if os.path.isfile(self.encrypt_output_file):
            os.remove(self.encrypt_output_file)
        if os.path.isfile(self.decrypt_output_file):
            os.remove(self.decrypt_output_file)
    def hash_key_salt(self):
        # --- convert key to hash and  create a new hash object
        hasher = hashlib.new(self.hash_type)
        hasher.update(self.user_key)
        # turn the output key hash into 32 bytes (256 bits)
        self.hashed_key_salt["key"] = bytes(hasher.hexdigest()[:32], "utf-8")
        # clean up hash object
        del hasher
        # --- convert salt to hash and create a new hash object
        hasher = hashlib.new(self.hash_type)
        hasher.update(self.user_salt)
        # turn the output salt hash into 16 bytes (128 bits)
        self.hashed_key_salt["salt"] = bytes(hasher.hexdigest()[:16], "utf-8")
        # clean up hash object
        del hasher


class MainWindow:
    """GUI Wrapper"""
    # configure root directory path relative to this file
    THIS_FOLDER_G = ""
    if getattr(sys, "frozen", False):
        # frozen
        THIS_FOLDER_G = os.path.dirname(sys.executable)
    else:
        # unfrozen
        THIS_FOLDER_G = os.path.dirname(os.path.realpath(__file__))

    def __init__(self, root):
        self.root = root
        self._cipher = None
        self._file_url = tk.StringVar()
        self._secret_key = tk.StringVar()
        self._secret_key_check = tk.StringVar()
        self._salt = tk.StringVar()
        self._status = tk.StringVar()
        self._status.set("---")
        self.should_cancel = False
        root.title("Encryption and Decryption")
        root.configure(bg="#030303")
        root.geometry("700x600")
        try:
            icon_img = tk.Image("photo", file=self.THIS_FOLDER_G + "./files/Encryption and Decryption.ico")
            root.call("wm", "iconphoto", root._w, icon_img)
        except Exception:
            pass
        self.menu_bar = tk.Menu(root, bg="#eeeeee", relief=tk.FLAT)
        self.menu_bar.add_command(label="Help!", command=self.show_help_callback)
        self.menu_bar.add_command(label="About", command=self.show_about)
        root.configure(menu=self.menu_bar)

        self.file_entry = tk.Entry(root, textvariable=self._file_url, font=("Helvetica", 15), bg="#CDC8B1", exportselection=0, relief=tk.FLAT, justify=tk.CENTER,)
        self.file_entry.grid(
            padx=10,
            pady=20,
            ipadx=6,
            ipady=10,
            row=0,
            column=0,
            columnspan=4,
            sticky=tk.W + tk.E + tk.N + tk.S,
        )
        self.select_btn = tk.Button(root, text="SELECT FILE", font=("Helvetica", 15), command=self.selectfile_callback,
                                    width=1, bg="#008B8B", fg="#ffffff", bd=2, relief=tk.FLAT, )
        self.select_btn.grid(
            padx=150,
            pady=10,
            ipadx=20,
            ipady=8,
            row=2,
            column=0,
            columnspan=4,
            sticky=tk.W + tk.E + tk.N + tk.S,
        )
        self.root.columnconfigure(0, weight=1)

        self.key_entry_label1 = tk.Label(root, text="Enter Key (To be Remembered while Decryption)",font=("Helvetica", 15,"bold"),bg="#6495ED", fg="black", anchor=tk.W, width=40, bd=2, relief=tk.FLAT, )
        self.key_entry_label1.grid(
            padx=12,
            pady=10,
            ipadx=0,
            ipady=8,
            row=3,
            column=0,
            columnspan=4,
            sticky=tk.W + tk.E + tk.N + tk.S,
        )

        self.key_entry_label2 = tk.Label(root, text="Re-enter Key (Validation)", font=("Helvetica", 15,"bold"), bg="#6495ED",
                                         anchor=tk.W, fg="black",)
        self.key_entry_label2.grid(
            padx=11,
            pady=10,
            ipadx=4,
            ipady=8,
            row=5,
            column=0,
            columnspan=4,
            sticky=tk.W + tk.E + tk.N + tk.S,
        )

        self.key_entry1 = tk.Entry(root, textvariable=self._secret_key, bg="#CDC8B1", font=("Helvetica", 15),
                                   exportselection=0, relief=tk.FLAT, justify=CENTER)
        self.key_entry1.grid(
            padx=11,
            pady=10,
            ipadx=8,
            ipady=8,
            row=4,
            column=0,
            columnspan=4,
            sticky=tk.W + tk.E + tk.N + tk.S,
        )

        self.key_entry2 = tk.Entry(root, textvariable=self._secret_key_check, font=("Helvetica", 15), bg="#CDC8B1",
                                   exportselection=0, relief=tk.FLAT,justify=CENTER )
        self.key_entry2.grid(
            padx=11,
            pady=10,
            ipadx=8,
            ipady=8,
            row=6,
            column=0,
            columnspan=4,
            sticky=tk.W + tk.E + tk.N + tk.S,
        )

        self.encrypt_btn = tk.Button(root,text="ENCRYPT", font=("Helvetica", 15),command=self.e_check_callback,bg="#008B8B",fg="#ffffff",bd=2,relief=tk.FLAT,
        )
        self.encrypt_btn.grid(
            padx=12,
            pady=10,
            ipadx=95,
            ipady=6,
            row=7,
            column=0,
            columnspan=3,
            sticky=tk.W + tk.E + tk.N + tk.S,
        )

        self.decrypt_btn = tk.Button(root,text="DECRYPT", font=("Helvetica", 15),command=self.d_check_callback,
                                     bg="#008B8B",fg="#ffffff",bd=2,relief=tk.FLAT,
        )
        self.decrypt_btn.grid(
            padx=12,
            pady=10,
            ipadx=108,
            ipady=6,
            row=7,
            column=3,
            columnspan=1,
            sticky=tk.W + tk.E + tk.N + tk.S,
        )
        self.reset_btn = tk.Button(root,text="CLEAR", font=("Helvetica", 15),command=self.reset_callback,
                                   bg="#717d7e",fg="#ffffff",bd=2,relief=tk.FLAT,)
        self.reset_btn.grid(
            padx=12,
            pady=10,
            ipadx=95,
            ipady=6,
            row=8,
            column=0,
            columnspan=2,
            sticky=tk.W + tk.E + tk.N + tk.S,
        )
        self.stop_btn = tk.Button(root, text="STOP", font=("Helvetica", 15), command=self.cancel_callback, bg="#717d7e",
                                  fg="#ffffff", bd=2    , relief=tk.FLAT, )
        self.stop_btn.grid(
            padx=12,
            pady=10,
            ipadx=108,
            ipady=6,
            row=8,
            column=3,
            columnspan=2,
            sticky=tk.W + tk.E + tk.N + tk.S,
        )

        self.status_label = tk.Label(root,textvariable=self._status,bg="#CDC8B1",anchor=tk.W,justify=tk.LEFT,relief=tk.FLAT,wraplength=500,
        )
        self.status_label.grid(
            padx=12,
            pady=(0, 12),
            ipadx=0,
            ipady=1,
            row=9,
            column=0,
            columnspan=4,
            sticky=tk.W + tk.E + tk.N + tk.S,
        )
    def selectfile_callback(self):
        try:
            name = filedialog.askopenfile()
            self._file_url.set(name.name)

            # Clear the key entries when a new file is selected
            self._secret_key.set("")
            self._secret_key_check.set("")

        except Exception as e:
            self._status.set(e)
            self.status_label.update()

    def freeze_controls(self):
        self.file_entry.configure(state="disabled")
        self.key_entry1.configure(state="disabled")
        self.key_entry2.configure(state="disabled")
        self.select_btn.configure(state="disabled", bg="#aaaaaa")
        self.encrypt_btn.configure(state="disabled", bg="#aaaaaa")
        self.decrypt_btn.configure(state="disabled", bg="#aaaaaa")
        self.reset_btn.configure(state="disabled", bg="#aaaaaa")
        self.stop_btn.configure(state="normal", bg="#e74c3c")
        self.status_label.update()

    def unfreeze_controls(self):
        self.file_entry.configure(state="normal")
        self.key_entry1.configure(state="normal")
        self.key_entry2.configure(state="normal")
        self.select_btn.configure(state="normal", bg="#3498db")
        self.encrypt_btn.configure(state="normal", bg="#27ae60")
        self.decrypt_btn.configure(state="normal", bg="#27ae60")
        self.reset_btn.configure(state="normal", bg="#717d7e")
        self.stop_btn.configure(state="disabled", bg="#aaaaaa")
        self.status_label.update()

    def e_check_callback(self):
        newPath = Path(self._file_url.get())
        if newPath.is_file():
            pass
        else:
            messagebox.showinfo("Encryption and Decryption", "Please Enter a valid File URL !!")
            return

        if len(self._secret_key.get()) == 0:
            messagebox.showinfo("Encryption and Decryption", "Please Enter a valid Secret Key !!")
            return
        elif self._secret_key.get() != self._secret_key_check.get():
            messagebox.showinfo("encryption", "key do not match !!")
            return
        self.encrypt_callback()

    def d_check_callback(self):
        newPath = Path(self._file_url.get())
        if newPath.is_file():
            pass
        else:
            messagebox.showinfo("Encryption and Decryption", "Please Enter a valid File URL !!")
            return

        if self._file_url.get()[-4:] != "encr":
            messagebox.showinfo(
                "Encryption and Decryption",
                """Provided File is not an Encrypted File !!
Please Enter an Encrypted File to Decrypt.""",
            )
            return
        if len(self._secret_key.get()) == 0:
            messagebox.showinfo("Encryption and Decryption", "Please Enter a Secret Key !!")
            return
        elif self._secret_key.get() != self._secret_key_check.get():
            messagebox.showinfo("Encryption and Decryption", "Passwords do not match !!")
            return

        self.decrypt_callback()

    def encrypt_callback(self):
        t1 = threading.Thread(target=self.encrypt_execute)
        t1.start()

    def encrypt_execute(self):
        self.freeze_controls()

        try:
            self._cipher = EncryptionTool(
                self._file_url.get(), self._secret_key.get(), self._salt.get()
            )
            for percentage in self._cipher.encrypt():
                if self.should_cancel:
                    break
                percentage = "{0:.2f}%".format(percentage)
                self._status.set(percentage)
                self.status_label.update()

            if self.should_cancel:
                self._cipher.abort()
                self._status.set("Cancellation Successful !!")
                messagebox.showinfo("Encryption and Decryption", "Cancellation Successful !!")
                self._cipher = None
                self.should_cancel = False
                self.unfreeze_controls()
                return

            self._cipher = None
            self.should_cancel = False
            self._status.set("File Encryption Successful !!")
            messagebox.showinfo("Encryption and Decryption", "File Encryption Successful !!")
        except Exception as e:
            self._status.set(e)
        self.unfreeze_controls()

    def decrypt_callback(self):
        t2 = threading.Thread(target=self.decrypt_execute)
        t2.start()

    def decrypt_execute(self):
        self.freeze_controls()

        try:
            self._cipher = EncryptionTool(
                self._file_url.get(), self._secret_key.get(), self._salt.get()
            )
            for percentage in self._cipher.decrypt():
                if self.should_cancel:
                    break
                percentage = "{0:.2f}%".format(percentage)
                self._status.set(percentage)
                self.status_label.update()

            if self.should_cancel:
                self._cipher.abort()
                self._status.set("Cancellation Successful !!")
                messagebox.showinfo("Encryption and Decryption", "Cancellation Successful !!")
                self._cipher = None
                self.should_cancel = False
                self.unfreeze_controls()
                return

            self._cipher = None
            self.should_cancel = False
            self._status.set("File Decryption Successful !!")
            messagebox.showinfo("Encryption and Decryption", "File Decryption Successful !!")
        except Exception as e:
            self._status.set(e)
        self.unfreeze_controls()

    def reset_callback(self):
        self._cipher = None
        self._file_url.set("")
        self._secret_key.set("")
        self._salt.set("")
        self._status.set("---")

    def cancel_callback(self):
        self.should_cancel = True

    def show_help_callback(self):
        messagebox.showinfo(
            "Tutorial",
            """1. Open the Application and Click SELECT FILE Button to select your file e.g. "hello.pdf" (OR You can add path manually).
2. Enter your Key (This should be alphanumeric letters). Remember this so you can Decrypt the file later. (Else you'll lose your file permanently)
3. Click ENCRYPT Button to encrypt the file. A new encrypted file with ".encr" extention e.g. "hello.pdf.encr" will be created in the same directory where the "hello.pdf" is.
4. When you want to Decrypt a file you, will select the file with the ".encr" extention and Enter your Key which you chose at the time of Encryption. Click DECRYPT Button to decrypt. The decrypted file will be of the same name as before with the suffix "decrypted" for e.g. "hello_decrypted.pdf".
5. Click CLEAR Button to reset the input fields and status bar.""",)
    def show_about(self):
        messagebox.showinfo(
            "Encryption and Decryption v1.2.0",
            """Encryption and Decryption is a File Encryption Tool based on AES Algorithm. """,
        )

if __name__ == "__main__":
    ROOT = tk.Tk()
    MAIN_WINDOW = MainWindow(ROOT)
    bundle_dir = getattr(sys, "_MEIPASS", os.path.abspath(os.path.dirname(__file__)))
    ROOT.resizable(height=False, width=False)
    ROOT.mainloop()