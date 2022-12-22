# from urllib.parse import urlparse
# from tkinter.messagebox import askyesno
from tkinter import ttk, messagebox
from tkinter import *
from flask import Flask  # , jsonify
from flask_cors import CORS
import os
# import signal
from asyncio.windows_events import NULL
import PyKCS11 as PK11
import datetime
from endesive import pdf, hsm
import requests
from cryptography import x509
import threading
import sys


class Signer(hsm.HSM):
    def __init__(self):
        [dllpath, self.label] = self.loaddll()
        super(Signer, self).__init__(dllpath)

    def loaddll(self):
        devicelist = ['aetpkss1', 'wdpkcs', 'TRUSTKEYP11', 'beidpkcs11', 'libgtop11dotnet',
                      'eps2003csp11', 'eTPKCS11', 'dkck201', 'aetpkss1', 'SignatureP11']
        for file in os.listdir("C:/Windows/System32"):
            file_name = os.path.splitext(file)
            if file_name[1] == '.dll':
                for dll_file in devicelist:
                    if file_name[0].find(dll_file) != -1:
                        file_path = r'C:/Windows/System32/'+file
                        try:
                            pkcs11 = PK11.PyKCS11Lib()
                            pkcs11.load(file_path)
                            slots = pkcs11.getSlotList(tokenPresent=True)
                            for slot in slots:
                                info = pkcs11.getTokenInfo(slot)
                                return file_path, info.label.split('\0')[0].strip()
                        except:
                            continue
        raise Exception("No USB token avaialble")

    def certificate(self):
        self.login(self.label, self.pin)
        keyid = [0x5e, 0x9a, 0x33, 0x44, 0x8b, 0xc3, 0xa1, 0x35, 0x33,
                 0xc7, 0xc2, 0x02, 0xf6, 0x9b, 0xde, 0x55, 0xfe, 0x83, 0x7b, 0xde]
        keyid = bytes(keyid)
        try:
            pk11objects = self.session.findObjects(
                [(PK11.CKA_CLASS, PK11.CKO_CERTIFICATE)])
            all_attributes = [
                PK11.CKA_SUBJECT,
                PK11.CKA_VALUE,
                PK11.CKA_ISSUER,
                PK11.CKA_CERTIFICATE_CATEGORY,
                PK11.CKA_END_DATE,
                PK11.CKA_ID,
            ]

            for pk11object in pk11objects:
                try:
                    attributes = self.session.getAttributeValue(
                        pk11object, all_attributes)
                except PK11.PyKCS11Error as e:
                    continue

                attrDict = dict(list(zip(all_attributes, attributes)))
                cert = bytes(attrDict[PK11.CKA_VALUE])
                return bytes(attrDict[PK11.CKA_ID]), cert
        finally:
            self.logout()
        return None, None

    def sign(self, keyid, data, mech):
        self.login(self.label, self.pin)
        try:
            privKey = self.session.findObjects(
                [(PK11.CKA_CLASS, PK11.CKO_PRIVATE_KEY)])[0]
            mech = getattr(PK11, 'CKM_%s_RSA_PKCS' % mech.upper())
            sig = self.session.sign(privKey, data, PK11.Mechanism(mech, None))
            return bytes(sig)
        finally:
            self.logout()


path = 'startupkhata'


def signFile(clshsm, fname):
    date = datetime.datetime.utcnow() - datetime.timedelta(hours=12)
    if not os.path.exists(path):
        os.makedirs(path)
    if not os.path.exists(path+'/Helvetica.ttf'):
        url_res = requests.get(
            url="https://github.com/m32/endesive/blob/master/endesive/pdf/PyPDF2_annotate/fonts/Helvetica.ttf?raw=true")
        with open(path+'/Helvetica.ttf', 'wb') as file:
            file.write(url_res.content)
    location = 'India'
    name = 'Startup Khata'
    for attribute in x509.load_der_x509_certificate(clshsm.certificate()[1]).subject:
        if attribute.oid._name == 'streetAddress':
            location = attribute.value
        if attribute.oid._name == 'commonName':
            name = attribute.value
    dct = {
        "aligned": 0,
        "sigflags": 3,
        "sigflagsft": 132,
        "sigpage": 0,
        "auto_sigfield": True,
        # "sigandcertify": False,
        "signaturebox": (72, 396, 360, 468),
        "signform": False,
        "sigfield": "Signature",
        "signature_manual": [
            ['font', 'Helvetica', 18],
            ['text_box', 'Digitally signed by \n'+name+'\nDate: {}'.format(date.strftime('%c')),
                'Helvetica', 10, 0, 288, 72, 13, True, 'left', 'top'],
        ],
        "manual_fonts": {
            "Helvetica": './'+path+'/Helvetica.ttf'
        },

        "contact": 'support@startupkhata.com',
        "location": location,
        "signingdate": date.strftime("D:%Y%m%d%H%M%S+00'00'"),
        "reason": 'Digitally signed by '+name,
    }
    datau = open(path+'/'+fname, 'rb').read()
    datas = pdf.cms.sign(datau, dct,
                         None, None,
                         [],
                         'sha256',
                         clshsm,
                         )
    fname = fname.replace('.pdf', '-signed.pdf')
    with open(path+'/'+fname, 'wb') as fp:
        fp.write(datau)
        fp.write(datas)


app = Flask(__name__)
CORS(app)


@app.route('/')
def index():
    return {'connect': True}


@app.route('/validateDSC/<jwt>/<invoiceid>/<type>')
def validateDSC(jwt, invoiceid, type):
    base_url = 'http://3.111.157.6:8000/'
    response = requests.get(
        url=base_url+"invoiceFile/"+invoiceid+"/"+type, headers={"Authorization": "Bearer " + jwt}).json()
    file_path = response.get('file_path')
    url_res = requests.get(
        url=base_url+file_path)
    filename = os.path.basename(file_path)
    with open(path+'/'+filename, 'wb') as file:
        file.write(url_res.content)
    global clshsm
    signFile(clshsm, filename)
    filename = filename.replace('.pdf', '-signed.pdf')
    files = {'uploaded_file': open(path+'/'+filename, 'rb')}
    requests.post(base_url+"invoiceFile/"+invoiceid + "/" +
                  type, files=files)
    return {'upload': True}


class thread_with_trace(threading.Thread):
    def __init__(self, *args, **keywords):
        threading.Thread.__init__(self, *args, **keywords)
        self.killed = False

    def start(self):
        self.__run_backup = self.run
        self.run = self.__run
        threading.Thread.start(self)

    def __run(self):
        sys.settrace(self.globaltrace)
        self.__run_backup()
        self.run = self.__run_backup

    def globaltrace(self, frame, event, arg):
        if event == 'call':
            return self.localtrace
        else:
            return None

    def localtrace(self, frame, event, arg):
        if self.killed:
            if event == 'line':
                raise SystemExit()
        return self.localtrace

    def kill(self):
        self.killed = True


flask_server = NULL
clshsm = NULL


def connectUSB():
    save['text'] = 'Connected'
    input = input_text.get()
    try:
        global clshsm
        clshsm = Signer()
        clshsm.pin = input
        clshsm.certificate()
        global flask_server
        flask_server = thread_with_trace(target=lambda: app.run(
            host='0.0.0.0', port=9999, debug=False, use_reloader=False))
        flask_server.start()
    except:
        messagebox.showwarning(
            "showwarning", "Pin enter valid pin or usb not installed")


def on_closing():
    if messagebox.askokcancel("Quit", "Do you want to quit?"):
        global flask_server
        if flask_server:
            flask_server.kill()
        root.destroy()

if not os.path.exists(path):
    os.makedirs(path)
if not os.path.exists(path+'/app.ico'):
    url_res = requests.get(
        url="https://www.startupkhata.com/favicon/start.png")
    with open(path+'/app.ico', 'wb') as file:
        file.write(url_res.content)
root = Tk()
root.title("Startupkhata")
root.geometry('200x100')
root.iconbitmap(path+'/app.ico')

input_text = StringVar()
style = ttk.Style()
style.configure('TEntry', foreground='green')

entry1 = ttk.Entry(root, textvariable=input_text, justify=CENTER,
                   font=('courier', 15, 'bold'))
entry1.focus_force()
entry1.pack(side=TOP, ipadx=30, ipady=10)

save = ttk.Button(root, text='Connect',
                  command=lambda: connectUSB())
save.pack(side=TOP, pady=10)

root.protocol("WM_DELETE_WINDOW", on_closing)

root.mainloop()
