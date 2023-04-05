import hashlib
import pyperclip
import rsa
import resources
from Crypto.Util import Padding
from PyQt5 import uic, QtWidgets
from PyQt5.QtWidgets import *
from Crypto.Cipher import AES


class MyGUI(QMainWindow):
    def __init__(self):
        super(MyGUI, self).__init__()
        uic.loadUi("deCrypt.ui", self)
        self.show()

        # Connect the GUI signals to the corresponding slots
        self.file_button.clicked.connect(self.select_file)
        self.encrypt_button.clicked.connect(self.encrypt_file)
        self.decrypt_button.clicked.connect(self.decrypt_file)
        self.copy_md5_button.clicked.connect(lambda: self.copy_md5())
        self.copy_sha_button.clicked.connect(lambda: self.copy_sha())
        self.close_button.triggered.connect(lambda: self.close_window())

    def select_file(self):
        filepath, _ = QtWidgets.QFileDialog.getOpenFileName(self, "Select a file for encryption")
        self.file_entry.setText(filepath)

    def copy_md5(self):
        md5 = self.md5.text()
        pyperclip.copy(md5)
        self.result_label.setText("MD5 Copied")

    def copy_sha(self):
        sha = self.sha256.text()
        pyperclip.copy(sha)
        self.result_label.setText("SHA256 Copied")

    def close_window(self):
        self.close()

    (public_key, private_key) = rsa.newkeys(4096)

    def encrypt_file(self):
        key = self.key_entry.text()
        filepath = self.file_entry.text()

        # Check that the file has been specified
        if not filepath:
            self.result_label.setText("Please select a file for encryption.")
            return

        # Encrypt the file using the key stream
        with open(filepath, "rb") as f:
            plaintext = f.read()

        # Calculate hash on text using md5
        md = hashlib.md5(plaintext).hexdigest()
        self.md5.setText(md)

        # Calculate hash on text using sha256
        sha = hashlib.sha256(plaintext).hexdigest()
        self.sha256.setText(sha)

        # Encrypt the padded plaintext using the AES cipher
        ciphertext = rsa.encrypt(plaintext, self.public_key)

        # Save the encrypted file
        save_filepath, _ = QtWidgets.QFileDialog.getSaveFileName(self, "Save encrypted file")
        with open(save_filepath, "wb") as f:
            f.write(ciphertext)

        # Update the result label
        self.result_label.setText("Encryption successful.")

    def decrypt_file(self):
        key = self.key_entry.text()
        filepath = self.file_entry.text()

        # Check that the file has been specified
        if not filepath:
            self.result_label.setText("Please select an encrypted file for decryption.")
            return

        # Encrypt the file using the key stream
        with open(filepath, "rb") as f:
            ciphertext = f.read()

        # Pad the plaintext to be a multiple of 16 bytes (the block size for AES)
        plaintext = rsa.decrypt(ciphertext, self.private_key)

        # Calculate hash on text using md5
        md = hashlib.md5(plaintext).hexdigest()
        self.md5.setText(md)

        # Calculate hash on text using sha256
        sha = hashlib.sha256(plaintext).hexdigest()
        self.sha256.setText(sha)

        # Save the decrypted file
        save_filepath, _ = QtWidgets.QFileDialog.getSaveFileName(self, "Save decrypted file")
        with open(save_filepath, "wb") as f:
            f.write(plaintext)

        # Update the result label
        self.result_label.setText('Decryption Successful')


def main():
    app = QApplication([])
    window = MyGUI()
    app.exec_()


if __name__ == '__main__':
    main()
