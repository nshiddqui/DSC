# from asn1crypto import x509
# from PyKCS11 import *

# pkcs11 = PyKCS11.PyKCS11Lib()
# pkcs11.load()
# pkcs11.load("C:\\Windows\\System32\\drivers\\UMDF\\WUDFUsbccidDriver.dll")
# get slot value via pkcs11.getSlotList(tokenPresent=False). Usually it's 0
# session = pkcs11.openSession(slot, CKF_SERIAL_SESSION | CKF_RW_SESSION)
# session.login('<SMART_CARD_PIN_CODE>')
# result = []
# certs = session.findObjects([(CKA_CLASS, CKO_CERTIFICATE)])
# for cert in certs:
#     cka_value, cka_id = session.getAttributeValue(cert, [CKA_VALUE, CKA_ID])
#     cert_der = bytes(cka_value)
#     cert = x509.Certificate.load(cert_der)
#     result.append(cert)
# print(result)

# Import the required Libraries
# from tkinter import *
# from tkinter import ttk
# Create an instance of tkinter frame
# win = Tk()
# Set the geometry of tkinter frame
# win.geometry("750x250")

# Define a function to show a message


# def myclick():
#     message = "Enter your pin" + entry.get()
#     label = Label(frame, text=message, font=('Times New Roman', 14, 'italic'))
#     entry.delete(0, 'end')
#     label.pack(pady=30)


# Creates a Frame
# frame = LabelFrame(win, width=400, height=180, bd=5)
# frame.pack()
# Stop the frame from propagating the widget to be shrink or fit
# frame.pack_propagate(False)

# Create an Entry widget in the Frame
# entry = ttk.Entry(frame, width=40)
# entry.insert(INSERT, "Enter Your Name")
# entry.pack()
# Create a Button
# ttk.Button(win, text="Click", command=myclick).pack(pady=20)
# win.mainloop()

# import http.server
# import socketserver

# PORT = 8000

# Handler = http.server.SimpleHTTPRequestHandler

# with socketserver.TCPServer(("", PORT), Handler) as httpd:
#     print("serving at port", PORT)
#     httpd.serve_forever()

#!/usr/bin/env vpython3
# *-* coding: utf-8 *-*
# import PyKCS11 as PK11
# import sys
# import datetime
# from endesive import pdf, hsm

# import os
# import sys

# dllpath = r'C:\Windows\System32\eps2003csp11.dll'


# class Signer(hsm.HSM):
#     def certificate(self):
#         # print(self.pkcs11.getSlotList(tokenPresent=True))
#         # print(self.pkcs11.getTokenInfo(1))
#         # print(self.pkcs11.getTokenInfo(2))
#         # print(self.pkcs11.getTokenInfo(3))

#         print(self.pkcs11.getSlotInfo(1))
#         self.login("ePass2003", "12345678")  # WF PROXKey is token name.
#         # keyid = [0x5e, 0x9a, 0x33, 0x44, 0x8b, 0xc3, 0xa1, 0x35, 0x33,
#         #          0xc7, 0xc2, 0x02, 0xf6, 0x9b, 0xde, 0x55, 0xfe, 0x83, 0x7b, 0xde]
#         keyid = [0x3f, 0xa6, 0x63, 0xdb, 0x75, 0x97, 0x5d, 0xa6, 0xb0, 0x32, 0xef, 0x2d, 0xdc, 0xc4, 0x8d, 0xe8]
#         keyid = bytes(keyid)
#         try:
#             pk11objects = self.session.findObjects(
#                 [(PK11.CKA_CLASS, PK11.CKO_CERTIFICATE)])
#             all_attributes = [
#                 # PK11.CKA_SUBJECT,
#                 PK11.CKA_VALUE,
#                 # PK11.CKA_ISSUER,
#                 # PK11.CKA_CERTIFICATE_CATEGORY,
#                 # PK11.CKA_END_DATE,
#                 PK11.CKA_ID,
#             ]

#             for pk11object in pk11objects:
#                 try:
#                     attributes = self.session.getAttributeValue(
#                         pk11object, all_attributes)
#                 except PK11.PyKCS11Error as e:
#                     continue

#                 attrDict = dict(list(zip(all_attributes, attributes)))
#                 cert = bytes(attrDict[PK11.CKA_VALUE])
#                 # if keyid == bytes(attrDict[PK11.CKA_ID]):
#                 return bytes(attrDict[PK11.CKA_ID]), cert
#         finally:
#             self.logout()
#         return None, None

#     def sign(self, keyid, data, mech):
#         self.login("WD PROXKey", "12345678")
#         try:
#             privKey = self.session.findObjects(
#                 [(PK11.CKA_CLASS, PK11.CKO_PRIVATE_KEY)])[0]
#             mech = getattr(PK11, 'CKM_%s_RSA_PKCS' % mech.upper())
#             sig = self.session.sign(privKey, data, PK11.Mechanism(mech, None))
#             return bytes(sig)
#         finally:
#             self.logout()


# def main():
#     date = datetime.datetime.utcnow() - datetime.timedelta(hours=12)
#     date = date.strftime('%Y%m%d%H%M%S+00\'00\'')
#     dct = {
#         "sigflags": 3,
#         "sigpage": 0,
#         "sigbutton": True,
#         "contact": "madhurendra@tikaj.com",
#         "location": 'India',
#         "signingdate": date.encode(),
#         "reason": 'Sample sign',
#         "signature": 'Madhurendra Sachan',
#         "signaturebox": (0, 0, 100, 100),
#     }
#     clshsm = Signer(dllpath)
#     fname = 'sample.pdf'
#     datau = open(fname, 'rb').read()
#     datas = pdf.cms.sign(datau, dct,
#                          None, None,
#                          [],
#                          'sha256',
#                          clshsm,
#                          )
#     fname = fname.replace('.pdf', '-signed.pdf')
#     with open(fname, 'wb') as fp:
#         fp.write(datau)
#         fp.write(datas)


# main()

# import pkcs11

# lib = pkcs11.lib(os.environ['PKCS11_MODULE'])
# token = lib.get_token(token_label='DEMO')

# data = b'INPUT DATA'

# # Open a session on our token
# with token.open(user_pin='1234') as session:
#     # Generate an RSA keypair in this session
#     pub, priv = session.generate_keypair(pkcs11.KeyType.RSA, 2048)

#     # Encrypt as one block
#     crypttext = pub.encrypt(data)

# from PyKCS11 import *

# # the key_id has to be the same for both objects
# key_id = (0x22,)

# pkcs11 = PyKCS11Lib()
# # define environment variable PYKCS11LIB=YourPKCS11Lib
# pkcs11.load(r'C:\Windows\System32\eps2003csp11.dll')

# # get 1st slot
# slot = pkcs11.getSlotList(tokenPresent=True)[0]

# session = pkcs11.openSession(slot, CKF_SERIAL_SESSION | CKF_RW_SESSION)
# session.login("12345678")

# pubTemplate = [
#     (CKA_CLASS, CKO_PUBLIC_KEY),
#     (CKA_TOKEN, CK_TRUE),
#     (CKA_PRIVATE, CK_FALSE),
#     (CKA_MODULUS_BITS, 0x0400),
#     (CKA_PUBLIC_EXPONENT, (0x01, 0x00, 0x01)),
#     (CKA_ENCRYPT, CK_TRUE),
#     (CKA_VERIFY, CK_TRUE),
#     (CKA_VERIFY_RECOVER, CK_TRUE),
#     (CKA_WRAP, CK_TRUE),
#     (CKA_LABEL, "My Public Key"),
#     (CKA_ID, key_id),
# ]

# privTemplate = [
#     (CKA_CLASS, CKO_PRIVATE_KEY),
#     (CKA_TOKEN, CK_TRUE),
#     (CKA_PRIVATE, CK_TRUE),
#     (CKA_DECRYPT, CK_TRUE),
#     (CKA_SIGN, CK_TRUE),
#     (CKA_SIGN_RECOVER, CK_TRUE),
#     (CKA_UNWRAP, CK_TRUE),
#     (CKA_ID, key_id),
# ]

# (pubKey, privKey) = session.generateKeyPair(pubTemplate, privTemplate)

# print(pubKey.exportKey())

# # logout
# session.logout()
# session.closeSession()

# date = datetime.datetime.utcnow() - datetime.timedelta(hours=12)
# date = date.strftime('%Y%m%d%H%M%S+00\'00\'')
# dct = {
#     "sigflags": 3,
#     "sigpage": 0,
#     "sigbutton": True,
#     "contact": "madhurendra@tikaj.com",
#     "location": 'India',
#     "signingdate": date.encode(),
#     "reason": 'Sample sign',
#     "signature": 'Madhurendra Sachan',
#     "signaturebox": (0, 0, 100, 100),
# }
# clshsm = Signer(dllpath)
# fname = 'sample.pdf'
# datau = open(fname, 'rb').read()
# datas = pdf.cms.sign(datau, dct,
#                      None, None,
#                      [],
#                      'sha256',
#                      clshsm,
#                      )
# fname = fname.replace('.pdf', '-signed.pdf')
# with open(fname, 'wb') as fp:
#     fp.write(datau)
#     fp.write(datas)


#!/usr/bin/env vpython3
# *-* coding: utf-8 *-*
import PyKCS11 as PK11
import datetime
from endesive import pdf, hsm
from cryptography import x509

import os
import sys

# if sys.platform == 'win32':
devicelist = {
    'EPass': 'eps2003csp11.dll',
    'Watchdata PROXkey': 'SignatureP11.dll'
}
dllpath = r'C:\Windows\System32\SignatureP11.dll'
# else:
#     dllpath = '/usr/lib/WatchData/ProxKey/lib/libwdpkcs_SignatureP11.so'


class Signer(hsm.HSM):
    def __init__(self, dllpath):
        super(Signer, self).__init__(dllpath)
        if self.pkcs11.getSlotList(tokenPresent=True):
            self.info = self.pkcs11.getTokenInfo(1)
            self.label = self.pkcs11.getTokenInfo(
                1).label.split('\0')[0].strip()

    def certificate(self):
        self.login(self.label, "12345678")
        keyid = [0x5e, 0x9a, 0x33, 0x44, 0x8b, 0xc3, 0xa1, 0x35, 0x33,
                 0xc7, 0xc2, 0x02, 0xf6, 0x9b, 0xde, 0x55, 0xfe, 0x83, 0x7b, 0xde]
        keyid = bytes(keyid)
        try:
            pk11objects = self.session.findObjects(
                [(PK11.CKA_CLASS, PK11.CKO_CERTIFICATE)])
            all_attributes = [
                # PK11.CKA_SUBJECT,
                PK11.CKA_VALUE,
                # PK11.CKA_ISSUER,
                # PK11.CKA_CERTIFICATE_CATEGORY,
                # PK11.CKA_END_DATE,
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
                # if keyid == bytes(attrDict[PK11.CKA_ID]):
                return bytes(attrDict[PK11.CKA_ID]), cert
        finally:
            self.logout()
        return None, None

    def sign(self, keyid, data, mech):
        self.login(self.label, "12345678")
        try:
            privKey = self.session.findObjects(
                [(PK11.CKA_CLASS, PK11.CKO_PRIVATE_KEY)])[0]
            mech = getattr(PK11, 'CKM_%s_RSA_PKCS' % mech.upper())
            sig = self.session.sign(privKey, data, PK11.Mechanism(mech, None))
            return bytes(sig)
        finally:
            self.logout()


def main():
    date = datetime.datetime.utcnow() - datetime.timedelta(hours=12)
    date = date.strftime('%Y%m%d%H%M%S+00\'00\'')
    clshsm = Signer(dllpath)
    print(clshsm)
    for attribute in x509.load_der_x509_certificate(clshsm.certificate()[1]).subject:
        print(attribute.value, attribute.oid._name)
    dct = {
        "sigflags": 3,
        "sigpage": 0,
        "sigbutton": True,
        "contact": "nazim27294@gmail.com",
        "location": 'India',
        "signingdate": date.encode(),
        "reason": 'Satrtupkhata',
        "signature": 'Nazim',
        "signaturebox": (50, 50, 100, 100),
    }
    fname = 'sample.pdf'
    datau = open(fname, 'rb').read()
    datas = pdf.cms.sign(datau, dct,
                         None, None,
                         [],
                         'sha256',
                         clshsm,
                         )
    fname = fname.replace('.pdf', '-signed.pdf')
    with open(fname, 'wb') as fp:
        fp.write(datau)
        fp.write(datas)


main()
