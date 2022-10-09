from PyQt5 import QtWidgets
from PyQt5.QtWidgets import *
from PyQt5.QtCore import *
from PyQt5.QtGui import *
# ------------import ui file and S_DES.py------------------
from choose import Ui_MainWindow as choose
from decryption import Ui_Form as decryption
from encryption import Ui_Form as encryption
from key import Ui_Form as KEY
from S_DES_de import Ui_Form as S_DES_de
from S_DES_en import Ui_Form as S_DES_en
from S_DES import *
# ---------------------------------------------------------
# Main windows, which corresponds to the choose.ui
class Main(QMainWindow, choose):
    def __init__(self):
        super().__init__()
        self.setupUi(self)
        self.encrypt = Encryption()
        self.decrypt = Decryption()
        # When the encryption button is clicked, it will lead users to the encryption.ui and execute Encryption() class
        self.encryption.clicked.connect(self.encrypt.show)
        # When the decryption button is clicked, it will lead users to the decryption.ui and execute Decryption() class
        self.decryption.clicked.connect(self.decrypt.show)

# Subwindows of the choose.ui, which corresponds to the encryption.ui
class Encryption(QWidget, encryption):
    def __init__(self):
        super().__init__()
        self.setupUi(self)
        # When the enter button is clicked, it will execute enter_clicked() function
        self.enter.clicked.connect(self.enter_clicked)
    def enter_clicked(self):
        # Enable users to input key
        K = self.input_key.text()
        # Enable users to input plain text
        P = self.input_plaintext.text()
        # check if the input is valid
        if check_binary(K) and check_binary(P):
            self.generate_key = KeyGeneration(K)
            # When the key_generation button is clicked, it will lead users to the key.ui and execute KeyGeneration() class
            self.key_generation.clicked.connect(self.generate_key.show)
            # Execute the encrypt function in S_DES.py and save results in variables described below
            fk_1_inter_results, fk_2_inter_results, encrypt_inter_results, C, key_1, key_2 = encrypt(P, K)
            # When the s_des button is clicked, it will lead users to the S_DES_en.ui and execute SDES_en() class
            self.s_des_en = SDES_en(P, key_1, key_2, fk_1_inter_results, fk_2_inter_results,  encrypt_inter_results)
            self.s_des.clicked.connect(self.s_des_en.show)
            # Show the cipher text
            self.show_ciphertext.setText(C)
        if not check_binary(K):
            self.input_key.setText("Error!")
        if not check_binary(P):
            self.input_plaintext.setText("Error!")

# Subwindows of the choose.ui, which corresponds to the decryption.ui
class Decryption(QWidget, decryption):
    def __init__(self):
        super().__init__()
        self.setupUi(self)
        # When the enter button is clicked, it will execute enter_clicked() function
        self.enter.clicked.connect(self.enter_clicked)
    def enter_clicked(self):
        # Enable users to input cipher text
        C = self.input_ciphertext.text()
        # Enable users to input key
        K = self.input_key.text()
        # check if the input is valid
        if check_binary(K) and check_binary(C):
            self.generate_key = KeyGeneration(K)
            # When the key_generation button is clicked, it will lead users to the key.ui and execute KeyGeneration() class
            self.key_generation.clicked.connect(self.generate_key.show)
            # Execute the decrypt function in S_DES.py and save results in variables described below
            fk_1_inter_results, fk_2_inter_results, decrypt_inter_results, P, key_1, key_2 = decrypt(C, K)
            # When the s_des button is clicked, it will lead users to the S_DES_de.ui and execute SDES_de() class
            self.s_des_de = SDES_de(C, key_1, key_2, fk_1_inter_results, fk_2_inter_results, decrypt_inter_results)
            self.s_des.clicked.connect(self.s_des_de.show)
            # Show the plain text
            self.show_plaintext.setText(P)
        if not check_binary(K):
            self.input_key.setText("Error!")
        if not check_binary(C):
            self.input_ciphertext.setText("Error!")

# Subwindows of the encryption.ui and the decryption.ui, which corresponds to the key.ui
class KeyGeneration(QWidget, KEY):
    def __init__(self, K):
        super().__init__()
        self.setupUi(self)
        # saved_key is the key that passed by the Encryption class
        saved_key = K
        # Execute the key1 function in S_DES.py and save results
        inter_results_1, key_1 = key1(saved_key)
        # Execute the key2 function in S_DES.py and save results
        inter_results_2, key_2 = key2(saved_key)
        # Save the contents that are contained in inter_results_1
        (p10, ls1_left, ls1_right, p8_1) = inter_results_1
        # Save the contents that are contained in inter_results_2
        (ls2_left, ls2_right, p8_2) = inter_results_2
        # Set the text to the corresponding place
        self.key.setText(saved_key)
        self.key.setAlignment(Qt.AlignCenter)
        self.P10.setText(p10)
        self.P10.setAlignment(Qt.AlignCenter)
        self.LS1_left.setText(ls1_left)
        self.LS1_left.setAlignment(Qt.AlignCenter)
        self.LS1_right.setText(ls1_right)
        self.LS1_right.setAlignment(Qt.AlignCenter)
        self.P8_1.setText(p8_1)
        self.P8_1.setAlignment(Qt.AlignCenter)
        self.LS2_left.setText(ls2_left)
        self.LS2_left.setAlignment(Qt.AlignCenter)
        self.LS2_right.setText(ls2_right)
        self.LS2_right.setAlignment(Qt.AlignCenter)
        self.P8_2.setText(p8_2)
        self.P8_2.setAlignment(Qt.AlignCenter)

# Subwindows of the encryption.ui, which corresponds to the S_DES_en.ui
class SDES_en(QWidget, S_DES_en):
    def __init__(self, P, key_1, key_2, fk_1_inter_results, fk_2_inter_results, encrypt_inter_results):
        super().__init__()
        self.setupUi(self)
        # Initialize the variable that are passed by the Encryption class
        saved_plain_text = P
        saved_key_1 = key_1
        saved_key_2 = key_2
        saved_fk_1_inter_results = fk_1_inter_results
        saved_fk_2_inter_results = fk_2_inter_results
        saved_encrypt_inter_results = encrypt_inter_results
        # Save the contents that are contained in variables described below
        (ep_1, xor_bits_1, s0_1, s1_1, p4_1, fk_1_result) = saved_fk_1_inter_results
        (ep_2, xor_bits_2, s0_2, s1_2, p4_2, fk_2_result) = saved_fk_2_inter_results
        (ip, fk_1, sw, fk_2, cipher_text) = saved_encrypt_inter_results
        # Set the text to the corresponding place
        self.plaintext.setText(saved_plain_text)
        self.plaintext.setAlignment(Qt.AlignCenter)
        self.IP.setText(ip)
        self.IP.setAlignment(Qt.AlignCenter)
        self.EP.setText(ep_1)
        self.EP.setAlignment(Qt.AlignCenter)
        self.key1.setText(saved_key_1)
        self.key1.setAlignment(Qt.AlignCenter)
        self.S0.setText(s0_1)
        self.S0.setAlignment(Qt.AlignCenter)
        self.S1.setText(s1_1)
        self.S1.setAlignment(Qt.AlignCenter)
        self.P4.setText(p4_1)
        self.P4.setAlignment(Qt.AlignCenter)
        self.round1_result.setText(fk_1_result)
        self.round1_result.setAlignment(Qt.AlignCenter)
        self.SW.setText(sw)
        self.SW.setAlignment(Qt.AlignCenter)
        self.EP_2.setText(ep_2)
        self.EP_2.setAlignment(Qt.AlignCenter)
        self.key2.setText(saved_key_2)
        self.key2.setAlignment(Qt.AlignCenter)
        self.S0_2.setText(s0_2)
        self.S0_2.setAlignment(Qt.AlignCenter)
        self.S1_2.setText(s1_2)
        self.S1_2.setAlignment(Qt.AlignCenter)
        self.P4_2.setText(p4_2)
        self.P4_2.setAlignment(Qt.AlignCenter)
        self.round2_result.setText(fk_2_result)
        self.round2_result.setAlignment(Qt.AlignCenter)
        self.ip_inverse.setText(cipher_text)
        self.ip_inverse.setAlignment(Qt.AlignCenter)

# Subwindows of the decryption.ui, which corresponds to the S_DES_de.ui
class SDES_de(QWidget, S_DES_de):
    def __init__(self, C, key_1, key_2, fk_1_inter_results, fk_2_inter_results, decrypt_inter_results):
        super().__init__()
        self.setupUi(self)
        # Initialize the variable that are passed by the Decryption class
        saved_cipher_text = C
        saved_key_1 = key_1
        saved_key_2 = key_2
        saved_fk_1_inter_results = fk_1_inter_results
        saved_fk_2_inter_results = fk_2_inter_results
        saved_decrypt_inter_results = decrypt_inter_results
        # Save the contents that are contained in variables described below
        (ep_1, xor_bits_1, s0_1, s1_1, p4_1, fk_1_result) = saved_fk_1_inter_results
        (ep_2, xor_bits_2, s0_2, s1_2, p4_2, fk_2_result) = saved_fk_2_inter_results
        (ip, fk_2, sw, fk_1, plain_text) = saved_decrypt_inter_results
        # Set the text to the corresponding place
        self.ciphertext.setText(saved_cipher_text)
        self.ciphertext.setAlignment(Qt.AlignCenter)
        self.IP.setText(ip)
        self.IP.setAlignment(Qt.AlignCenter)
        self.EP.setText(ep_2)
        self.EP.setAlignment(Qt.AlignCenter)
        self.key2.setText(saved_key_2)
        self.key2.setAlignment(Qt.AlignCenter)
        self.S0.setText(s0_2)
        self.S0.setAlignment(Qt.AlignCenter)
        self.S1.setText(s1_2)
        self.S1.setAlignment(Qt.AlignCenter)
        self.P4.setText(p4_2)
        self.P4.setAlignment(Qt.AlignCenter)
        self.round1_result.setText(fk_2_result)
        self.round1_result.setAlignment(Qt.AlignCenter)
        self.SW.setText(sw)
        self.SW.setAlignment(Qt.AlignCenter)
        self.EP_2.setText(ep_1)
        self.EP_2.setAlignment(Qt.AlignCenter)
        self.key1.setText(saved_key_1)
        self.key1.setAlignment(Qt.AlignCenter)
        self.S0_2.setText(s0_1)
        self.S0_2.setAlignment(Qt.AlignCenter)
        self.S1_2.setText(s1_1)
        self.S1_2.setAlignment(Qt.AlignCenter)
        self.P4_2.setText(p4_1)
        self.P4_2.setAlignment(Qt.AlignCenter)
        self.round2_result.setText(fk_1_result)
        self.round2_result.setAlignment(Qt.AlignCenter)
        self.ip_inverse.setText(plain_text)
        self.ip_inverse.setAlignment(Qt.AlignCenter)

if __name__ == '__main__':
    import sys
    app = QtWidgets.QApplication(sys.argv)
    main_window = Main()
    main_window.show()
    sys.exit(app.exec_())