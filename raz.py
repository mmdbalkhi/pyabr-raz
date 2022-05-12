import shutil
from PyQt5.QtWidgets import *
from PyQt5.QtGui import *
from PyQt5.QtCore import *
import sys,os
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization

class Key:
    # create keys for wallet or bank
    def __init__(self):
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        public_key = private_key.public_key()

        private = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        
        f = open('Private Key.pem', 'wb')
        f.write(private)
        f.close()

        public = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        f = open('Public Key.pem','wb')
        f.write(public)
        f.close()


class Message:
    text = ''
    def __init__(self):
        super(Message, self).__init__()

    def Write (self,text):
        self.text+=text+"\n"

    def Save (self):
        message = self.text.encode()

        with open("External Public Key.pem", "rb") as key_file:
            public_key = serialization.load_pem_public_key(
                key_file.read(),
                backend=default_backend()
            )

        encrypted = public_key.encrypt(
            message,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        f = open("Message.raz", 'wb')
        f.write(encrypted)
        f.close()

    def Read (self):
        with open('Private Key.pem', "rb") as key_file:
            private_key = serialization.load_pem_private_key(
                key_file.read(),
                password=None,
                backend=default_backend()
            )

        f = open("Message.raz", 'rb')
        encrypted = f.read()
        f.close()

        original_message = private_key.decrypt(
            encrypted,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        return original_message.decode('utf-8')

class MainApp (QMainWindow):
    def new_(self):
        self.txtRaz.setText("")

    def newpage_(self):
        self.w = MainApp()

    def changekey_(self):
        self.w = Key()

    def publickeyshow_(self):
        self.w = QMainWindow()
        self.txtPublicKey = QTextEdit()
        self.txtPublicKey.setReadOnly(True)
        f = open("Public Key.pem","r")
        self.txtPublicKey.setText(f.read())
        f.close()
        self.w.setWindowTitle("کلید عمومی شما")
        self.w.setCentralWidget(self.txtPublicKey)
        self.w.resize(600,300)
        self.w.show()

    def privatekeyshow_(self):
        self.w = QMainWindow()
        self.txtPrivateKey = QTextEdit()
        self.txtPrivateKey.setReadOnly(True)
        f = open("Private Key.pem","r")
        self.txtPrivateKey.setText(f.read())
        self.w.resize(600,300)
        f.close()
        self.w.setWindowTitle("کلید خصوصی شما : به کسی ارسال نکنید")
        self.w.setCentralWidget(self.txtPrivateKey)
        self.w.show()

    def save__(self):
        f = open("External Public Key.pem",'wb')
        f.write(self.txtPublicKey.toPlainText().encode())
        f.close()

        self.w.close()

        self.m = Message()
        self.m.Write(self.txtRaz.toPlainText())
        self.m.Save()

        self.name = QFileDialog.getSaveFileName(self, 'ذخیره کردن پیام','','Raz Files (*.raz)')
        if self.name != ('', ''):
            shutil.copyfile("Message.raz",str(self.name[0]))

    def save_(self):
        self.w = QWidget()
        self.w.setWindowTitle("کلید عمومی را وارد کنید")
        self.txtPublicKey = QTextEdit()
        self.txtPublicKey.resize(600,300-40)
        self.txtPublicKey.setPlaceholderText("در این مکان متن کامل کلید عمومی دوست خود را جایگذاری نمایید")
        self.txtPublicKey.setFont(QFont("Vazir",12))

        self.vbox = QVBoxLayout()
        self.btnSave = QPushButton()
        self.btnSave.setText("رمزنگاری کن")
        self.btnSave.setFont(QFont("Vazir",12))
        self.btnSave.clicked.connect (self.save__)
        self.btnSave.resize(600,40)
        self.vbox.addWidget(self.txtPublicKey)
        self.vbox.addWidget(self.btnSave)
        self.w.setLayout(self.vbox)
        
        self.w.resize(600,300)
        self.w.show()

    def open_(self):
        self.name = QFileDialog.getOpenFileName(self, 'بازکردن پیام','','Raz Files (*.raz)')
        if self.name != ('', ''):
            try:
                shutil.copyfile(self.name[0],"Message.raz")
            except:
                pass
            self.m = Message()
            self.txtRaz.setText(self.m.Read())

    def about_(self):
        self.w = QMainWindow()
        self.w.setWindowTitle("درباره")
        self.txtAbout = QTextEdit()
        self.txtAbout.setFont(QFont("Vazir",12))
        self.txtAbout.setReadOnly(True)
        self.txtAbout.setText('''
برنامه (راز)
برنامه راز یک نرم افزاری است برای رمزنگاری پیام های شما به بهترین حالت ممکن؛ این برنامه پیام های شما را با رمزنگاری نامتقارن رمزنگاری می کند و این بدان معناست که بدون داشتن کلید خصوصی شما احدی تا احتمال ۹۹٪ نمی تواند به پیام شما دسترسی پیدا کند.
برنامه راز توسط مانی جمالی (توسعه دهنده سیستم عامل ایرانی پای ابر) توسعه می یابد و نسخه های غیر رسمی آن غیرقابل اعتماد هستند؛ هدف ما از توسعه این برنامه امنیت بالای شما در تمام پیام رسان های داخلی و خارجی می باشد تا شما عزیزان بدون هیچ ترسی از شنود پیام های خود در شبکات اجتماعی آنها را تبادل نمایید.

نسخه راز شما ۱.۰.۰ می باشد.

توجه: از این برنامه به هیچ عنوان برای اهداف مجرمانه استفاده ننمایید! ما هیچ مسئولیتی بابت اهداف مجرمانه نخواهیم داشت؛ همچنین برنامه راز کاملا رایگان است و در صورت مشاهده نسخه های غیررسمی حتما به ما اطلاع دهید.

وب سایت ما:
https://pyabr.ir

کانال تلگرام ما:
https://t.me/appraz
        ''')
        self.w.setCentralWidget(self.txtAbout)
        self.w.resize(500,300)
        self.w.show()

    def __init__(self):
        super().__init__()

        self.setWindowTitle("رمزنگار پیام های شما")
        self.setFont(QFont("Vazir",12))
        self.resize(870,560)
        self.show()

        self.menuBar = QMenuBar()
        self.setMenuBar (self.menuBar)

        self.file = self.menuBar.addMenu("فایل")
        self.file.setFont(QFont("Vazir",12))
        self.new = self.file.addAction("پیام جدید")
        self.newpage = self.file.addAction ("برگه جدید")
        self.open = self.file.addAction("بازکردن پیام")
        self.save = self.file.addAction("رمزنگاری پیام")
        self.exit = self.file.addAction("خروج")
        self.key = self.menuBar.addMenu("کلید ها")
        self.key.setFont(QFont("Vazir",12))
        self.about = self.menuBar.addAction("درباره")
        self.about.triggered.connect (self.about_)
        self.publickeyshow = self.key.addAction("نمایش کلید عمومی")
        self.privatekeyshow = self.key.addAction("نمایش کلید خصوصی")
        self.changekey = self.key.addAction("تغییر کلیدها")

        self.exit.triggered.connect (self.close)
        self.new.triggered.connect (self.new_)
        self.newpage.triggered.connect (self.newpage_)
        self.changekey.triggered.connect (self.changekey_)
        self.publickeyshow.triggered.connect (self.publickeyshow_)
        self.privatekeyshow.triggered.connect (self.privatekeyshow_)
        self.save.triggered.connect (self.save_)
        self.open.triggered.connect (self.open_)
        self.txtRaz = QTextEdit()
        self.txtRaz.setLayoutDirection(Qt.RightToLeft)
        self.setCentralWidget(self.txtRaz)

        if not (os.path.isfile("Public Key.pem") or os.path.isfile("Private Key.pem")):
            self.w = Key()

app = QApplication(sys.argv)
w = MainApp()
app.exec()