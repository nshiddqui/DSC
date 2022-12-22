# import ssl
# from cryptography import x509

# for cert, encoding, trust in ssl.enum_certificates("MY"):
#     certificate = x509.load_der_x509_certificate(cert, backend=True)
#     for attribute in certificate.subject:
#         if attribute.oid._name == 'commonName':
#             print(attribute.value)
import os
import PyKCS11


def loaddll():
    devicelist = ['aetpkss1', 'wdpkcs', 'TRUSTKEYP11', 'beidpkcs11', 'libgtop11dotnet',
                  'eps2003csp11', 'eTPKCS11', 'dkck201', 'aetpkss1', 'SignatureP11']
    for file in os.listdir("C:/Windows/System32"):
        file_name = os.path.splitext(file)
        if file_name[1] == '.dll':
            for dll_file in devicelist:
                if file_name[0].find(dll_file) != -1:
                    file_path = r'C:/Windows/System32/'+file
                    try:
                        pkcs11 = PyKCS11.PyKCS11Lib()
                        pkcs11.load(file_path)
                        slots = pkcs11.getSlotList(tokenPresent=True)
                        for slot in slots:
                            info = pkcs11.getTokenInfo(slot)
                            return info.label.split('\0')[0].strip(), file_path
                    except:
                        continue


print(loaddll())
