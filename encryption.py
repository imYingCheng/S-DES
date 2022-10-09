# -*- coding: utf-8 -*-

# Form implementation generated from reading ui file 'encryption.ui'
#
# Created by: PyQt5 UI code generator 5.15.6
#
# WARNING: Any manual changes made to this file will be lost when pyuic5 is
# run again.  Do not edit this file unless you know what you are doing.


from PyQt5 import QtCore, QtGui, QtWidgets


class Ui_Form(object):
    def setupUi(self, Form):
        Form.setObjectName("Form")
        Form.resize(1111, 764)
        self.show_ciphertext = QtWidgets.QLineEdit(Form)
        self.show_ciphertext.setGeometry(QtCore.QRect(900, 250, 191, 51))
        font = QtGui.QFont()
        font.setFamily("Arial Black")
        font.setPointSize(15)
        font.setBold(True)
        font.setWeight(75)
        self.show_ciphertext.setFont(font)
        self.show_ciphertext.setReadOnly(True)
        self.show_ciphertext.setObjectName("show_ciphertext")
        self.label_68 = QtWidgets.QLabel(Form)
        self.label_68.setGeometry(QtCore.QRect(730, 420, 16, 51))
        font = QtGui.QFont()
        font.setFamily("Arial Black")
        font.setPointSize(18)
        font.setBold(True)
        font.setWeight(75)
        self.label_68.setFont(font)
        self.label_68.setAlignment(QtCore.Qt.AlignLeading|QtCore.Qt.AlignLeft|QtCore.Qt.AlignVCenter)
        self.label_68.setTextInteractionFlags(QtCore.Qt.LinksAccessibleByMouse)
        self.label_68.setObjectName("label_68")
        self.label_62 = QtWidgets.QLabel(Form)
        self.label_62.setGeometry(QtCore.QRect(750, 400, 16, 51))
        font = QtGui.QFont()
        font.setFamily("Arial Black")
        font.setPointSize(18)
        font.setBold(True)
        font.setWeight(75)
        self.label_62.setFont(font)
        self.label_62.setAlignment(QtCore.Qt.AlignLeading|QtCore.Qt.AlignLeft|QtCore.Qt.AlignVCenter)
        self.label_62.setTextInteractionFlags(QtCore.Qt.LinksAccessibleByMouse)
        self.label_62.setObjectName("label_62")
        self.label_35 = QtWidgets.QLabel(Form)
        self.label_35.setGeometry(QtCore.QRect(380, 570, 16, 51))
        font = QtGui.QFont()
        font.setFamily("Arial Black")
        font.setPointSize(18)
        font.setBold(True)
        font.setWeight(75)
        self.label_35.setFont(font)
        self.label_35.setAlignment(QtCore.Qt.AlignLeading|QtCore.Qt.AlignLeft|QtCore.Qt.AlignVCenter)
        self.label_35.setTextInteractionFlags(QtCore.Qt.LinksAccessibleByMouse)
        self.label_35.setObjectName("label_35")
        self.label_32 = QtWidgets.QLabel(Form)
        self.label_32.setGeometry(QtCore.QRect(210, 240, 301, 41))
        font = QtGui.QFont()
        font.setFamily("Arial Black")
        font.setPointSize(18)
        font.setBold(True)
        font.setWeight(75)
        self.label_32.setFont(font)
        self.label_32.setObjectName("label_32")
        self.label_49 = QtWidgets.QLabel(Form)
        self.label_49.setGeometry(QtCore.QRect(560, 430, 16, 51))
        font = QtGui.QFont()
        font.setFamily("Arial Black")
        font.setPointSize(18)
        font.setBold(True)
        font.setWeight(75)
        self.label_49.setFont(font)
        self.label_49.setAlignment(QtCore.Qt.AlignLeading|QtCore.Qt.AlignLeft|QtCore.Qt.AlignVCenter)
        self.label_49.setTextInteractionFlags(QtCore.Qt.LinksAccessibleByMouse)
        self.label_49.setObjectName("label_49")
        self.label_25 = QtWidgets.QLabel(Form)
        self.label_25.setGeometry(QtCore.QRect(560, 540, 16, 51))
        font = QtGui.QFont()
        font.setFamily("Arial Black")
        font.setPointSize(18)
        font.setBold(True)
        font.setWeight(75)
        self.label_25.setFont(font)
        self.label_25.setAlignment(QtCore.Qt.AlignLeading|QtCore.Qt.AlignLeft|QtCore.Qt.AlignVCenter)
        self.label_25.setTextInteractionFlags(QtCore.Qt.LinksAccessibleByMouse)
        self.label_25.setObjectName("label_25")
        self.label_46 = QtWidgets.QLabel(Form)
        self.label_46.setGeometry(QtCore.QRect(560, 440, 16, 51))
        font = QtGui.QFont()
        font.setFamily("Arial Black")
        font.setPointSize(18)
        font.setBold(True)
        font.setWeight(75)
        self.label_46.setFont(font)
        self.label_46.setAlignment(QtCore.Qt.AlignLeading|QtCore.Qt.AlignLeft|QtCore.Qt.AlignVCenter)
        self.label_46.setTextInteractionFlags(QtCore.Qt.LinksAccessibleByMouse)
        self.label_46.setObjectName("label_46")
        self.key_generation = QtWidgets.QPushButton(Form)
        self.key_generation.setGeometry(QtCore.QRect(270, 450, 211, 81))
        font = QtGui.QFont()
        font.setFamily("Arial Black")
        font.setPointSize(13)
        font.setBold(True)
        font.setWeight(75)
        self.key_generation.setFont(font)
        self.key_generation.setObjectName("key_generation")
        self.label_53 = QtWidgets.QLabel(Form)
        self.label_53.setGeometry(QtCore.QRect(560, 509, 16, 51))
        font = QtGui.QFont()
        font.setFamily("Arial Black")
        font.setPointSize(18)
        font.setBold(True)
        font.setWeight(75)
        self.label_53.setFont(font)
        self.label_53.setAlignment(QtCore.Qt.AlignLeading|QtCore.Qt.AlignLeft|QtCore.Qt.AlignVCenter)
        self.label_53.setTextInteractionFlags(QtCore.Qt.LinksAccessibleByMouse)
        self.label_53.setObjectName("label_53")
        self.label_57 = QtWidgets.QLabel(Form)
        self.label_57.setGeometry(QtCore.QRect(770, 420, 16, 51))
        font = QtGui.QFont()
        font.setFamily("Arial Black")
        font.setPointSize(18)
        font.setBold(True)
        font.setWeight(75)
        self.label_57.setFont(font)
        self.label_57.setAlignment(QtCore.Qt.AlignLeading|QtCore.Qt.AlignLeft|QtCore.Qt.AlignVCenter)
        self.label_57.setTextInteractionFlags(QtCore.Qt.LinksAccessibleByMouse)
        self.label_57.setObjectName("label_57")
        self.label_48 = QtWidgets.QLabel(Form)
        self.label_48.setGeometry(QtCore.QRect(560, 450, 16, 51))
        font = QtGui.QFont()
        font.setFamily("Arial Black")
        font.setPointSize(18)
        font.setBold(True)
        font.setWeight(75)
        self.label_48.setFont(font)
        self.label_48.setAlignment(QtCore.Qt.AlignLeading|QtCore.Qt.AlignLeft|QtCore.Qt.AlignVCenter)
        self.label_48.setTextInteractionFlags(QtCore.Qt.LinksAccessibleByMouse)
        self.label_48.setObjectName("label_48")
        self.label_60 = QtWidgets.QLabel(Form)
        self.label_60.setGeometry(QtCore.QRect(750, 450, 16, 51))
        font = QtGui.QFont()
        font.setFamily("Arial Black")
        font.setPointSize(18)
        font.setBold(True)
        font.setWeight(75)
        self.label_60.setFont(font)
        self.label_60.setAlignment(QtCore.Qt.AlignLeading|QtCore.Qt.AlignLeft|QtCore.Qt.AlignVCenter)
        self.label_60.setTextInteractionFlags(QtCore.Qt.LinksAccessibleByMouse)
        self.label_60.setObjectName("label_60")
        self.label_43 = QtWidgets.QLabel(Form)
        self.label_43.setGeometry(QtCore.QRect(560, 499, 16, 51))
        font = QtGui.QFont()
        font.setFamily("Arial Black")
        font.setPointSize(18)
        font.setBold(True)
        font.setWeight(75)
        self.label_43.setFont(font)
        self.label_43.setAlignment(QtCore.Qt.AlignLeading|QtCore.Qt.AlignLeft|QtCore.Qt.AlignVCenter)
        self.label_43.setTextInteractionFlags(QtCore.Qt.LinksAccessibleByMouse)
        self.label_43.setObjectName("label_43")
        self.label_52 = QtWidgets.QLabel(Form)
        self.label_52.setGeometry(QtCore.QRect(560, 460, 16, 51))
        font = QtGui.QFont()
        font.setFamily("Arial Black")
        font.setPointSize(18)
        font.setBold(True)
        font.setWeight(75)
        self.label_52.setFont(font)
        self.label_52.setAlignment(QtCore.Qt.AlignLeading|QtCore.Qt.AlignLeft|QtCore.Qt.AlignVCenter)
        self.label_52.setTextInteractionFlags(QtCore.Qt.LinksAccessibleByMouse)
        self.label_52.setObjectName("label_52")
        self.label_4 = QtWidgets.QLabel(Form)
        self.label_4.setGeometry(QtCore.QRect(380, 510, 16, 51))
        font = QtGui.QFont()
        font.setFamily("Arial Black")
        font.setPointSize(18)
        font.setBold(True)
        font.setWeight(75)
        self.label_4.setFont(font)
        self.label_4.setAlignment(QtCore.Qt.AlignLeading|QtCore.Qt.AlignLeft|QtCore.Qt.AlignVCenter)
        self.label_4.setTextInteractionFlags(QtCore.Qt.LinksAccessibleByMouse)
        self.label_4.setObjectName("label_4")
        self.label_34 = QtWidgets.QLabel(Form)
        self.label_34.setGeometry(QtCore.QRect(820, 240, 81, 41))
        font = QtGui.QFont()
        font.setFamily("Arial Black")
        font.setPointSize(18)
        font.setBold(True)
        font.setWeight(75)
        self.label_34.setFont(font)
        self.label_34.setObjectName("label_34")
        self.label_72 = QtWidgets.QLabel(Form)
        self.label_72.setGeometry(QtCore.QRect(750, 571, 16, 51))
        font = QtGui.QFont()
        font.setFamily("Arial Black")
        font.setPointSize(18)
        font.setBold(True)
        font.setWeight(75)
        self.label_72.setFont(font)
        self.label_72.setAlignment(QtCore.Qt.AlignLeading|QtCore.Qt.AlignLeft|QtCore.Qt.AlignVCenter)
        self.label_72.setTextInteractionFlags(QtCore.Qt.LinksAccessibleByMouse)
        self.label_72.setObjectName("label_72")
        self.label_2 = QtWidgets.QLabel(Form)
        self.label_2.setGeometry(QtCore.QRect(380, 580, 471, 41))
        font = QtGui.QFont()
        font.setFamily("Arial Black")
        font.setPointSize(18)
        font.setBold(True)
        font.setWeight(75)
        self.label_2.setFont(font)
        self.label_2.setObjectName("label_2")
        self.ciphertext = QtWidgets.QLabel(Form)
        self.ciphertext.setGeometry(QtCore.QRect(900, 210, 161, 41))
        font = QtGui.QFont()
        font.setFamily("Arial Black")
        font.setPointSize(15)
        font.setBold(True)
        font.setWeight(75)
        self.ciphertext.setFont(font)
        self.ciphertext.setObjectName("ciphertext")
        self.label_73 = QtWidgets.QLabel(Form)
        self.label_73.setGeometry(QtCore.QRect(750, 551, 16, 51))
        font = QtGui.QFont()
        font.setFamily("Arial Black")
        font.setPointSize(18)
        font.setBold(True)
        font.setWeight(75)
        self.label_73.setFont(font)
        self.label_73.setAlignment(QtCore.Qt.AlignLeading|QtCore.Qt.AlignLeft|QtCore.Qt.AlignVCenter)
        self.label_73.setTextInteractionFlags(QtCore.Qt.LinksAccessibleByMouse)
        self.label_73.setObjectName("label_73")
        self.label_55 = QtWidgets.QLabel(Form)
        self.label_55.setGeometry(QtCore.QRect(560, 560, 16, 51))
        font = QtGui.QFont()
        font.setFamily("Arial Black")
        font.setPointSize(18)
        font.setBold(True)
        font.setWeight(75)
        self.label_55.setFont(font)
        self.label_55.setAlignment(QtCore.Qt.AlignLeading|QtCore.Qt.AlignLeft|QtCore.Qt.AlignVCenter)
        self.label_55.setTextInteractionFlags(QtCore.Qt.LinksAccessibleByMouse)
        self.label_55.setObjectName("label_55")
        self.label_69 = QtWidgets.QLabel(Form)
        self.label_69.setGeometry(QtCore.QRect(750, 561, 16, 51))
        font = QtGui.QFont()
        font.setFamily("Arial Black")
        font.setPointSize(18)
        font.setBold(True)
        font.setWeight(75)
        self.label_69.setFont(font)
        self.label_69.setAlignment(QtCore.Qt.AlignLeading|QtCore.Qt.AlignLeft|QtCore.Qt.AlignVCenter)
        self.label_69.setTextInteractionFlags(QtCore.Qt.LinksAccessibleByMouse)
        self.label_69.setObjectName("label_69")
        self.label_38 = QtWidgets.QLabel(Form)
        self.label_38.setGeometry(QtCore.QRect(380, 540, 16, 51))
        font = QtGui.QFont()
        font.setFamily("Arial Black")
        font.setPointSize(18)
        font.setBold(True)
        font.setWeight(75)
        self.label_38.setFont(font)
        self.label_38.setAlignment(QtCore.Qt.AlignLeading|QtCore.Qt.AlignLeft|QtCore.Qt.AlignVCenter)
        self.label_38.setTextInteractionFlags(QtCore.Qt.LinksAccessibleByMouse)
        self.label_38.setObjectName("label_38")
        self.label_71 = QtWidgets.QLabel(Form)
        self.label_71.setGeometry(QtCore.QRect(750, 530, 16, 51))
        font = QtGui.QFont()
        font.setFamily("Arial Black")
        font.setPointSize(18)
        font.setBold(True)
        font.setWeight(75)
        self.label_71.setFont(font)
        self.label_71.setAlignment(QtCore.Qt.AlignLeading|QtCore.Qt.AlignLeft|QtCore.Qt.AlignVCenter)
        self.label_71.setTextInteractionFlags(QtCore.Qt.LinksAccessibleByMouse)
        self.label_71.setObjectName("label_71")
        self.label_56 = QtWidgets.QLabel(Form)
        self.label_56.setGeometry(QtCore.QRect(560, 570, 16, 51))
        font = QtGui.QFont()
        font.setFamily("Arial Black")
        font.setPointSize(18)
        font.setBold(True)
        font.setWeight(75)
        self.label_56.setFont(font)
        self.label_56.setAlignment(QtCore.Qt.AlignLeading|QtCore.Qt.AlignLeft|QtCore.Qt.AlignVCenter)
        self.label_56.setTextInteractionFlags(QtCore.Qt.LinksAccessibleByMouse)
        self.label_56.setObjectName("label_56")
        self.label_66 = QtWidgets.QLabel(Form)
        self.label_66.setGeometry(QtCore.QRect(750, 440, 16, 51))
        font = QtGui.QFont()
        font.setFamily("Arial Black")
        font.setPointSize(18)
        font.setBold(True)
        font.setWeight(75)
        self.label_66.setFont(font)
        self.label_66.setAlignment(QtCore.Qt.AlignLeading|QtCore.Qt.AlignLeft|QtCore.Qt.AlignVCenter)
        self.label_66.setTextInteractionFlags(QtCore.Qt.LinksAccessibleByMouse)
        self.label_66.setObjectName("label_66")
        self.input_plaintext = QtWidgets.QLineEdit(Form)
        self.input_plaintext.setGeometry(QtCore.QRect(20, 247, 191, 51))
        self.input_plaintext.setMinimumSize(QtCore.QSize(191, 51))
        self.input_plaintext.setMaximumSize(QtCore.QSize(191, 51))
        font = QtGui.QFont()
        font.setFamily("Arial Black")
        font.setPointSize(15)
        font.setBold(True)
        font.setWeight(75)
        self.input_plaintext.setFont(font)
        self.input_plaintext.setLayoutDirection(QtCore.Qt.LeftToRight)
        self.input_plaintext.setInputMask("")
        self.input_plaintext.setText("")
        self.input_plaintext.setMaxLength(8)
        self.input_plaintext.setObjectName("input_plaintext")
        self.label_50 = QtWidgets.QLabel(Form)
        self.label_50.setGeometry(QtCore.QRect(570, 410, 16, 51))
        font = QtGui.QFont()
        font.setFamily("Arial Black")
        font.setPointSize(18)
        font.setBold(True)
        font.setWeight(75)
        self.label_50.setFont(font)
        self.label_50.setAlignment(QtCore.Qt.AlignLeading|QtCore.Qt.AlignLeft|QtCore.Qt.AlignVCenter)
        self.label_50.setTextInteractionFlags(QtCore.Qt.LinksAccessibleByMouse)
        self.label_50.setObjectName("label_50")
        self.plaintext = QtWidgets.QLabel(Form)
        self.plaintext.setGeometry(QtCore.QRect(20, 199, 121, 41))
        self.plaintext.setMinimumSize(QtCore.QSize(121, 41))
        self.plaintext.setMaximumSize(QtCore.QSize(121, 41))
        font = QtGui.QFont()
        font.setFamily("Arial Black")
        font.setPointSize(15)
        font.setBold(True)
        font.setWeight(75)
        self.plaintext.setFont(font)
        self.plaintext.setObjectName("plaintext")
        self.label_40 = QtWidgets.QLabel(Form)
        self.label_40.setGeometry(QtCore.QRect(560, 519, 16, 51))
        font = QtGui.QFont()
        font.setFamily("Arial Black")
        font.setPointSize(18)
        font.setBold(True)
        font.setWeight(75)
        self.label_40.setFont(font)
        self.label_40.setAlignment(QtCore.Qt.AlignLeading|QtCore.Qt.AlignLeft|QtCore.Qt.AlignVCenter)
        self.label_40.setTextInteractionFlags(QtCore.Qt.LinksAccessibleByMouse)
        self.label_40.setObjectName("label_40")
        self.label_74 = QtWidgets.QLabel(Form)
        self.label_74.setGeometry(QtCore.QRect(750, 520, 16, 51))
        font = QtGui.QFont()
        font.setFamily("Arial Black")
        font.setPointSize(18)
        font.setBold(True)
        font.setWeight(75)
        self.label_74.setFont(font)
        self.label_74.setAlignment(QtCore.Qt.AlignLeading|QtCore.Qt.AlignLeft|QtCore.Qt.AlignVCenter)
        self.label_74.setTextInteractionFlags(QtCore.Qt.LinksAccessibleByMouse)
        self.label_74.setObjectName("label_74")
        self.label_5 = QtWidgets.QLabel(Form)
        self.label_5.setGeometry(QtCore.QRect(380, 500, 16, 51))
        font = QtGui.QFont()
        font.setFamily("Arial Black")
        font.setPointSize(18)
        font.setBold(True)
        font.setWeight(75)
        self.label_5.setFont(font)
        self.label_5.setAlignment(QtCore.Qt.AlignLeading|QtCore.Qt.AlignLeft|QtCore.Qt.AlignVCenter)
        self.label_5.setTextInteractionFlags(QtCore.Qt.LinksAccessibleByMouse)
        self.label_5.setObjectName("label_5")
        self.s_des = QtWidgets.QPushButton(Form)
        self.s_des.setGeometry(QtCore.QRect(510, 120, 301, 301))
        font = QtGui.QFont()
        font.setFamily("Arial Black")
        font.setPointSize(15)
        font.setBold(True)
        font.setWeight(75)
        self.s_des.setFont(font)
        self.s_des.setObjectName("s_des")
        self.label_42 = QtWidgets.QLabel(Form)
        self.label_42.setGeometry(QtCore.QRect(560, 410, 16, 51))
        font = QtGui.QFont()
        font.setFamily("Arial Black")
        font.setPointSize(18)
        font.setBold(True)
        font.setWeight(75)
        self.label_42.setFont(font)
        self.label_42.setAlignment(QtCore.Qt.AlignLeading|QtCore.Qt.AlignLeft|QtCore.Qt.AlignVCenter)
        self.label_42.setTextInteractionFlags(QtCore.Qt.LinksAccessibleByMouse)
        self.label_42.setObjectName("label_42")
        self.label_33 = QtWidgets.QLabel(Form)
        self.label_33.setGeometry(QtCore.QRect(560, 529, 16, 51))
        font = QtGui.QFont()
        font.setFamily("Arial Black")
        font.setPointSize(18)
        font.setBold(True)
        font.setWeight(75)
        self.label_33.setFont(font)
        self.label_33.setAlignment(QtCore.Qt.AlignLeading|QtCore.Qt.AlignLeft|QtCore.Qt.AlignVCenter)
        self.label_33.setTextInteractionFlags(QtCore.Qt.LinksAccessibleByMouse)
        self.label_33.setObjectName("label_33")
        self.label_41 = QtWidgets.QLabel(Form)
        self.label_41.setGeometry(QtCore.QRect(580, 420, 16, 51))
        font = QtGui.QFont()
        font.setFamily("Arial Black")
        font.setPointSize(18)
        font.setBold(True)
        font.setWeight(75)
        self.label_41.setFont(font)
        self.label_41.setAlignment(QtCore.Qt.AlignLeading|QtCore.Qt.AlignLeft|QtCore.Qt.AlignVCenter)
        self.label_41.setTextInteractionFlags(QtCore.Qt.LinksAccessibleByMouse)
        self.label_41.setObjectName("label_41")
        self.label_75 = QtWidgets.QLabel(Form)
        self.label_75.setGeometry(QtCore.QRect(750, 510, 16, 51))
        font = QtGui.QFont()
        font.setFamily("Arial Black")
        font.setPointSize(18)
        font.setBold(True)
        font.setWeight(75)
        self.label_75.setFont(font)
        self.label_75.setAlignment(QtCore.Qt.AlignLeading|QtCore.Qt.AlignLeft|QtCore.Qt.AlignVCenter)
        self.label_75.setTextInteractionFlags(QtCore.Qt.LinksAccessibleByMouse)
        self.label_75.setObjectName("label_75")
        self.label_44 = QtWidgets.QLabel(Form)
        self.label_44.setGeometry(QtCore.QRect(550, 410, 16, 51))
        font = QtGui.QFont()
        font.setFamily("Arial Black")
        font.setPointSize(18)
        font.setBold(True)
        font.setWeight(75)
        self.label_44.setFont(font)
        self.label_44.setAlignment(QtCore.Qt.AlignLeading|QtCore.Qt.AlignLeft|QtCore.Qt.AlignVCenter)
        self.label_44.setTextInteractionFlags(QtCore.Qt.LinksAccessibleByMouse)
        self.label_44.setObjectName("label_44")
        self.label_61 = QtWidgets.QLabel(Form)
        self.label_61.setGeometry(QtCore.QRect(760, 410, 16, 51))
        font = QtGui.QFont()
        font.setFamily("Arial Black")
        font.setPointSize(18)
        font.setBold(True)
        font.setWeight(75)
        self.label_61.setFont(font)
        self.label_61.setAlignment(QtCore.Qt.AlignLeading|QtCore.Qt.AlignLeft|QtCore.Qt.AlignVCenter)
        self.label_61.setTextInteractionFlags(QtCore.Qt.LinksAccessibleByMouse)
        self.label_61.setObjectName("label_61")
        self.key = QtWidgets.QLabel(Form)
        self.key.setGeometry(QtCore.QRect(20, 422, 121, 41))
        self.key.setMinimumSize(QtCore.QSize(121, 41))
        self.key.setMaximumSize(QtCore.QSize(121, 41))
        font = QtGui.QFont()
        font.setFamily("Arial Black")
        font.setPointSize(15)
        font.setBold(True)
        font.setWeight(75)
        self.key.setFont(font)
        self.key.setObjectName("key")
        self.label_58 = QtWidgets.QLabel(Form)
        self.label_58.setGeometry(QtCore.QRect(750, 410, 16, 51))
        font = QtGui.QFont()
        font.setFamily("Arial Black")
        font.setPointSize(18)
        font.setBold(True)
        font.setWeight(75)
        self.label_58.setFont(font)
        self.label_58.setAlignment(QtCore.Qt.AlignLeading|QtCore.Qt.AlignLeft|QtCore.Qt.AlignVCenter)
        self.label_58.setTextInteractionFlags(QtCore.Qt.LinksAccessibleByMouse)
        self.label_58.setObjectName("label_58")
        self.label_65 = QtWidgets.QLabel(Form)
        self.label_65.setGeometry(QtCore.QRect(750, 430, 16, 51))
        font = QtGui.QFont()
        font.setFamily("Arial Black")
        font.setPointSize(18)
        font.setBold(True)
        font.setWeight(75)
        self.label_65.setFont(font)
        self.label_65.setAlignment(QtCore.Qt.AlignLeading|QtCore.Qt.AlignLeft|QtCore.Qt.AlignVCenter)
        self.label_65.setTextInteractionFlags(QtCore.Qt.LinksAccessibleByMouse)
        self.label_65.setObjectName("label_65")
        self.label_54 = QtWidgets.QLabel(Form)
        self.label_54.setGeometry(QtCore.QRect(560, 550, 16, 51))
        font = QtGui.QFont()
        font.setFamily("Arial Black")
        font.setPointSize(18)
        font.setBold(True)
        font.setWeight(75)
        self.label_54.setFont(font)
        self.label_54.setAlignment(QtCore.Qt.AlignLeading|QtCore.Qt.AlignLeft|QtCore.Qt.AlignVCenter)
        self.label_54.setTextInteractionFlags(QtCore.Qt.LinksAccessibleByMouse)
        self.label_54.setObjectName("label_54")
        self.label_63 = QtWidgets.QLabel(Form)
        self.label_63.setGeometry(QtCore.QRect(750, 460, 16, 51))
        font = QtGui.QFont()
        font.setFamily("Arial Black")
        font.setPointSize(18)
        font.setBold(True)
        font.setWeight(75)
        self.label_63.setFont(font)
        self.label_63.setAlignment(QtCore.Qt.AlignLeading|QtCore.Qt.AlignLeft|QtCore.Qt.AlignVCenter)
        self.label_63.setTextInteractionFlags(QtCore.Qt.LinksAccessibleByMouse)
        self.label_63.setObjectName("label_63")
        self.label_70 = QtWidgets.QLabel(Form)
        self.label_70.setGeometry(QtCore.QRect(750, 500, 16, 51))
        font = QtGui.QFont()
        font.setFamily("Arial Black")
        font.setPointSize(18)
        font.setBold(True)
        font.setWeight(75)
        self.label_70.setFont(font)
        self.label_70.setAlignment(QtCore.Qt.AlignLeading|QtCore.Qt.AlignLeft|QtCore.Qt.AlignVCenter)
        self.label_70.setTextInteractionFlags(QtCore.Qt.LinksAccessibleByMouse)
        self.label_70.setObjectName("label_70")
        self.label_36 = QtWidgets.QLabel(Form)
        self.label_36.setGeometry(QtCore.QRect(380, 560, 16, 51))
        font = QtGui.QFont()
        font.setFamily("Arial Black")
        font.setPointSize(18)
        font.setBold(True)
        font.setWeight(75)
        self.label_36.setFont(font)
        self.label_36.setAlignment(QtCore.Qt.AlignLeading|QtCore.Qt.AlignLeft|QtCore.Qt.AlignVCenter)
        self.label_36.setTextInteractionFlags(QtCore.Qt.LinksAccessibleByMouse)
        self.label_36.setObjectName("label_36")
        self.label_26 = QtWidgets.QLabel(Form)
        self.label_26.setGeometry(QtCore.QRect(750, 541, 16, 51))
        font = QtGui.QFont()
        font.setFamily("Arial Black")
        font.setPointSize(18)
        font.setBold(True)
        font.setWeight(75)
        self.label_26.setFont(font)
        self.label_26.setAlignment(QtCore.Qt.AlignLeading|QtCore.Qt.AlignLeft|QtCore.Qt.AlignVCenter)
        self.label_26.setTextInteractionFlags(QtCore.Qt.LinksAccessibleByMouse)
        self.label_26.setObjectName("label_26")
        self.K2 = QtWidgets.QLabel(Form)
        self.K2.setGeometry(QtCore.QRect(740, 490, 61, 41))
        font = QtGui.QFont()
        font.setFamily("Arial Black")
        font.setPointSize(15)
        font.setBold(True)
        font.setWeight(75)
        self.K2.setFont(font)
        self.K2.setObjectName("K2")
        self.label_39 = QtWidgets.QLabel(Form)
        self.label_39.setGeometry(QtCore.QRect(380, 530, 16, 51))
        font = QtGui.QFont()
        font.setFamily("Arial Black")
        font.setPointSize(18)
        font.setBold(True)
        font.setWeight(75)
        self.label_39.setFont(font)
        self.label_39.setAlignment(QtCore.Qt.AlignLeading|QtCore.Qt.AlignLeft|QtCore.Qt.AlignVCenter)
        self.label_39.setTextInteractionFlags(QtCore.Qt.LinksAccessibleByMouse)
        self.label_39.setObjectName("label_39")
        self.label_67 = QtWidgets.QLabel(Form)
        self.label_67.setGeometry(QtCore.QRect(750, 420, 16, 51))
        font = QtGui.QFont()
        font.setFamily("Arial Black")
        font.setPointSize(18)
        font.setBold(True)
        font.setWeight(75)
        self.label_67.setFont(font)
        self.label_67.setAlignment(QtCore.Qt.AlignLeading|QtCore.Qt.AlignLeft|QtCore.Qt.AlignVCenter)
        self.label_67.setTextInteractionFlags(QtCore.Qt.LinksAccessibleByMouse)
        self.label_67.setObjectName("label_67")
        self.K1 = QtWidgets.QLabel(Form)
        self.K1.setGeometry(QtCore.QRect(550, 490, 61, 41))
        font = QtGui.QFont()
        font.setFamily("Arial Black")
        font.setPointSize(15)
        font.setBold(True)
        font.setWeight(75)
        self.K1.setFont(font)
        self.K1.setObjectName("K1")
        self.label = QtWidgets.QLabel(Form)
        self.label.setGeometry(QtCore.QRect(210, 470, 61, 41))
        font = QtGui.QFont()
        font.setFamily("Arial Black")
        font.setPointSize(18)
        font.setBold(True)
        font.setWeight(75)
        self.label.setFont(font)
        self.label.setObjectName("label")
        self.label_51 = QtWidgets.QLabel(Form)
        self.label_51.setGeometry(QtCore.QRect(540, 420, 16, 51))
        font = QtGui.QFont()
        font.setFamily("Arial Black")
        font.setPointSize(18)
        font.setBold(True)
        font.setWeight(75)
        self.label_51.setFont(font)
        self.label_51.setAlignment(QtCore.Qt.AlignLeading|QtCore.Qt.AlignLeft|QtCore.Qt.AlignVCenter)
        self.label_51.setTextInteractionFlags(QtCore.Qt.LinksAccessibleByMouse)
        self.label_51.setObjectName("label_51")
        self.label_59 = QtWidgets.QLabel(Form)
        self.label_59.setGeometry(QtCore.QRect(740, 410, 16, 51))
        font = QtGui.QFont()
        font.setFamily("Arial Black")
        font.setPointSize(18)
        font.setBold(True)
        font.setWeight(75)
        self.label_59.setFont(font)
        self.label_59.setAlignment(QtCore.Qt.AlignLeading|QtCore.Qt.AlignLeft|QtCore.Qt.AlignVCenter)
        self.label_59.setTextInteractionFlags(QtCore.Qt.LinksAccessibleByMouse)
        self.label_59.setObjectName("label_59")
        self.label_47 = QtWidgets.QLabel(Form)
        self.label_47.setGeometry(QtCore.QRect(560, 420, 16, 51))
        font = QtGui.QFont()
        font.setFamily("Arial Black")
        font.setPointSize(18)
        font.setBold(True)
        font.setWeight(75)
        self.label_47.setFont(font)
        self.label_47.setAlignment(QtCore.Qt.AlignLeading|QtCore.Qt.AlignLeft|QtCore.Qt.AlignVCenter)
        self.label_47.setTextInteractionFlags(QtCore.Qt.LinksAccessibleByMouse)
        self.label_47.setObjectName("label_47")
        self.label_3 = QtWidgets.QLabel(Form)
        self.label_3.setGeometry(QtCore.QRect(380, 520, 16, 51))
        font = QtGui.QFont()
        font.setFamily("Arial Black")
        font.setPointSize(18)
        font.setBold(True)
        font.setWeight(75)
        self.label_3.setFont(font)
        self.label_3.setAlignment(QtCore.Qt.AlignLeading|QtCore.Qt.AlignLeft|QtCore.Qt.AlignVCenter)
        self.label_3.setTextInteractionFlags(QtCore.Qt.LinksAccessibleByMouse)
        self.label_3.setObjectName("label_3")
        self.input_key = QtWidgets.QLineEdit(Form)
        self.input_key.setGeometry(QtCore.QRect(20, 470, 191, 51))
        self.input_key.setMinimumSize(QtCore.QSize(191, 51))
        self.input_key.setMaximumSize(QtCore.QSize(191, 51))
        font = QtGui.QFont()
        font.setFamily("Arial Black")
        font.setPointSize(15)
        font.setBold(True)
        font.setWeight(75)
        self.input_key.setFont(font)
        self.input_key.setLayoutDirection(QtCore.Qt.LeftToRight)
        self.input_key.setInputMask("")
        self.input_key.setText("")
        self.input_key.setMaxLength(10)
        self.input_key.setObjectName("input_key")
        self.label_37 = QtWidgets.QLabel(Form)
        self.label_37.setGeometry(QtCore.QRect(380, 550, 16, 51))
        font = QtGui.QFont()
        font.setFamily("Arial Black")
        font.setPointSize(18)
        font.setBold(True)
        font.setWeight(75)
        self.label_37.setFont(font)
        self.label_37.setAlignment(QtCore.Qt.AlignLeading|QtCore.Qt.AlignLeft|QtCore.Qt.AlignVCenter)
        self.label_37.setTextInteractionFlags(QtCore.Qt.LinksAccessibleByMouse)
        self.label_37.setObjectName("label_37")
        self.label_45 = QtWidgets.QLabel(Form)
        self.label_45.setGeometry(QtCore.QRect(560, 400, 16, 51))
        font = QtGui.QFont()
        font.setFamily("Arial Black")
        font.setPointSize(18)
        font.setBold(True)
        font.setWeight(75)
        self.label_45.setFont(font)
        self.label_45.setAlignment(QtCore.Qt.AlignLeading|QtCore.Qt.AlignLeft|QtCore.Qt.AlignVCenter)
        self.label_45.setTextInteractionFlags(QtCore.Qt.LinksAccessibleByMouse)
        self.label_45.setObjectName("label_45")
        self.enter = QtWidgets.QPushButton(Form)
        self.enter.setGeometry(QtCore.QRect(20, 560, 141, 51))
        font = QtGui.QFont()
        font.setFamily("Arial Black")
        font.setPointSize(15)
        font.setBold(True)
        font.setWeight(75)
        self.enter.setFont(font)
        self.enter.setObjectName("enter")

        self.retranslateUi(Form)
        QtCore.QMetaObject.connectSlotsByName(Form)

    def retranslateUi(self, Form):
        _translate = QtCore.QCoreApplication.translate
        Form.setWindowTitle(_translate("Form", "Form"))
        self.label_68.setText(_translate("Form", "."))
        self.label_62.setText(_translate("Form", "."))
        self.label_35.setText(_translate("Form", "."))
        self.label_32.setText(_translate("Form", "........................................."))
        self.label_49.setText(_translate("Form", "."))
        self.label_25.setText(_translate("Form", "."))
        self.label_46.setText(_translate("Form", "."))
        self.key_generation.setText(_translate("Form", "key generation"))
        self.label_53.setText(_translate("Form", "."))
        self.label_57.setText(_translate("Form", "."))
        self.label_48.setText(_translate("Form", "."))
        self.label_60.setText(_translate("Form", "."))
        self.label_43.setText(_translate("Form", "."))
        self.label_52.setText(_translate("Form", "."))
        self.label_4.setText(_translate("Form", "."))
        self.label_34.setText(_translate("Form", "........"))
        self.label_72.setText(_translate("Form", "."))
        self.label_2.setText(_translate("Form", "......................................"))
        self.ciphertext.setText(_translate("Form", "ciphertext"))
        self.label_73.setText(_translate("Form", "."))
        self.label_55.setText(_translate("Form", "."))
        self.label_69.setText(_translate("Form", "."))
        self.label_38.setText(_translate("Form", "."))
        self.label_71.setText(_translate("Form", "."))
        self.label_56.setText(_translate("Form", "."))
        self.label_66.setText(_translate("Form", "."))
        self.input_plaintext.setPlaceholderText(_translate("Form", "plaintext(8)"))
        self.label_50.setText(_translate("Form", "."))
        self.plaintext.setText(_translate("Form", "plaintext"))
        self.label_40.setText(_translate("Form", "."))
        self.label_74.setText(_translate("Form", "."))
        self.label_5.setText(_translate("Form", "."))
        self.s_des.setText(_translate("Form", "S-DES"))
        self.label_42.setText(_translate("Form", "."))
        self.label_33.setText(_translate("Form", "."))
        self.label_41.setText(_translate("Form", "."))
        self.label_75.setText(_translate("Form", "."))
        self.label_44.setText(_translate("Form", "."))
        self.label_61.setText(_translate("Form", "."))
        self.key.setText(_translate("Form", "key"))
        self.label_58.setText(_translate("Form", "."))
        self.label_65.setText(_translate("Form", "."))
        self.label_54.setText(_translate("Form", "."))
        self.label_63.setText(_translate("Form", "."))
        self.label_70.setText(_translate("Form", "."))
        self.label_36.setText(_translate("Form", "."))
        self.label_26.setText(_translate("Form", "."))
        self.K2.setText(_translate("Form", "K2"))
        self.label_39.setText(_translate("Form", "."))
        self.label_67.setText(_translate("Form", "."))
        self.K1.setText(_translate("Form", "K1"))
        self.label.setText(_translate("Form", "........"))
        self.label_51.setText(_translate("Form", "."))
        self.label_59.setText(_translate("Form", "."))
        self.label_47.setText(_translate("Form", "."))
        self.label_3.setText(_translate("Form", "."))
        self.input_key.setPlaceholderText(_translate("Form", "key(10)"))
        self.label_37.setText(_translate("Form", "."))
        self.label_45.setText(_translate("Form", "."))
        self.enter.setText(_translate("Form", "enter"))


if __name__ == "__main__":
    import sys
    app = QtWidgets.QApplication(sys.argv)
    Form = QtWidgets.QWidget()
    ui = Ui_Form()
    ui.setupUi(Form)
    Form.show()
    sys.exit(app.exec_())