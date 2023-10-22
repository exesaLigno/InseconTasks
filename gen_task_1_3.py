#!/usr/bin/python

from base import Config

from subprocess import run
from os import mkdir, walk
from os.path import isdir, isfile
from shutil import rmtree
from zipfile import ZipFile

if __name__ == "__main__":
    
    user = Config("user.json")
    task = Config("tasks/p1_3.json")
    
    workdir = f"{user.name}-{user.group}-{task.no}"
    file_prefix = f"{user.name}-{user.group}"
    archive_name = f"{workdir}/{file_prefix}-{task.no}.zip"
    email_topic = f"{user.university}-{user.group}-{task.no}"
    
    if isdir(workdir): rmtree(workdir)
    mkdir(workdir)

    #################### CA Certificate ##########################
    # Generating RSA-key with aes256 encryption and specified length
    run(["openssl", "genrsa", "-aes256", "-passout", f"pass:{user.name}", "-out", f"{workdir}/{file_prefix}-ca.key", f"{task.ca_keylen}"])
    # Generating self-signed certificate with specified RSA key
    run(["openssl", "req", "-x509", "-new", 
         "-key", f"{workdir}/{file_prefix}-ca.key", "-passin", f"pass:{user.name}",                                          # Passing encrypted RSA key and password
         "-days", f"{task.ca_time}",                                                                                         # Setting time limit for certificate
         "-subj", f"/C=RU/ST=Moscow/L=Moscow/O={user.name}/OU={user.name} P1_3/CN={user.name} CA/emailAddress={user.email}", # Setting certificate parameters in format /param1=value1/param2=value2/...
         "-addext", "basicConstraints=critical,CA:TRUE",                                                                     # Adding x509v3 extensions
         "-addext", "keyUsage=critical,digitalSignature,keyCertSign,cRLSign",                                                # Adding x509v3 extensions
         "-out", f"{workdir}/{file_prefix}-ca.crt"])                                                                         # Setting up output file

    #################### Intermediate CA Certificate #################
    # Generating RSA-key with aes256 encryption and specified length
    run(["openssl", "genrsa", "-aes256", "-passout", f"pass:{user.name}", "-out", f"{workdir}/{file_prefix}-intr.key", f"{task.intr_keylen}"])
    # Generating certificate signing request
    run(["openssl", "req", "-new", 
         "-key", f"{workdir}/{file_prefix}-intr.key", "-passin", f"pass:{user.name}",                                                      # Passing encrypted RSA key and password
         "-subj", f"/C=RU/ST=Moscow/L=Moscow/O={user.name}/OU={user.name} P1_3/CN={user.name} Intermediate CA/emailAddress={user.email}",  # Setting certificate parameters in format /param1=value1/param2=value2/...
         "-addext", "basicConstraints=critical,pathlen:0,CA:TRUE",                                                                         # Adding x509v3 extensions
         "-addext", "keyUsage=critical,digitalSignature,keyCertSign,cRLSign",                                                              # Adding x509v3 extensions 
         "-out", f"{workdir}/{file_prefix}-intr.csr"])                                                                                     # Setting up output file
    # Generating certificate from request
    run(["openssl", "x509", "-req", "-days", f"{task.intr_time}",
         "-CA", f"{workdir}/{file_prefix}-ca.crt", "-CAkey", f"{workdir}/{file_prefix}-ca.key", "-passin", f"pass:{user.name}", # Passing ca cerificate with key and password
         #"-CAcreateserial", "-CAserial", f"{workdir}/serial",
         "-copy_extensions", "copy",                                                                                            # Copying x509v3 extensions from request to certificate
         "-in", f"{workdir}/{file_prefix}-intr.csr",                                                                            # Passing request
         "-out", f"{workdir}/{file_prefix}-intr.crt"])                                                                          # Specifying output path

    ################ OCSP Responder Certificate #####################
    # Generating RSA-key without encryption and with specified length
    run(["openssl", "genrsa", "-aes256", "-passout", f"pass:{user.name}", "-out", f"{workdir}/{file_prefix}-ocsp-resp.key", f"{task.intr_keylen}"])
    # Generating certificate signing request
    run(["openssl", "req", "-new",
         "-key", f"{workdir}/{file_prefix}-ocsp-resp.key", "-passin", f"pass:{user.name}",                                          # Passing RSA key
         "-subj", f"/C=RU/ST=Moscow/L=Moscow/O={user.name}/OU={user.name} P1_3/CN={user.name} OCSP Responder/emailAddress={user.email}", # Setting certificate parameters in format /param1=value1/param2=value2/...
         "-addext", "basicConstraints=CA:FALSE",                                                                                # Adding x509v3 extensions
         "-addext", "keyUsage=critical,digitalSignature",                                                                       # Adding x509v3 extensions
         "-addext", "extendedKeyUsage=OCSPSigning",                                                                             # Adding x509v3 extensions
         "-out", f"{workdir}/{file_prefix}-ocsp-resp.csr"])                                                                         # Setting up output file
    # Generating certificate from request
    run(["openssl", "x509", "-req", "-days", f"{task.intr_time}",
         "-CA", f"{workdir}/{file_prefix}-intr.crt", "-CAkey", f"{workdir}/{file_prefix}-intr.key", "-passin", f"pass:{user.name}", # Passing intr cerificate with key and password
         #"-CAcreateserial", "-CAserial", f"{workdir}/serial",
         "-copy_extensions", "copy",                                                                                                # Copying x509v3 extensions from request to certificate
         "-in", f"{workdir}/{file_prefix}-ocsp-resp.csr",                                                                               # Passing request
         "-out", f"{workdir}/{file_prefix}-ocsp-resp.crt"])                                                                             # Specifying output path
    
    ######################## Valid Certificate #####################
    # Generating RSA-key without encryption and with specified length
    run(["openssl", "genrsa", "-out", f"{workdir}/{file_prefix}-ocsp-valid.key", f"{task.basic_keylen}"])
    # Generating certificate signing request
    run(["openssl", "req", "-new",
         "-key", f"{workdir}/{file_prefix}-ocsp-valid.key",                                                                          # Passing RSA key
         "-subj", f"/C=RU/ST=Moscow/L=Moscow/O={user.name}/OU={user.name} P1_3/CN={user.name} OCSP Valid/emailAddress={user.email}", # Setting certificate parameters in format /param1=value1/param2=value2/...
         "-addext", "basicConstraints=CA:FALSE",                                                                                    # Adding x509v3 extensions
         "-addext", "keyUsage=critical,digitalSignature",                                                                           # Adding x509v3 extensions
         "-addext", "extendedKeyUsage=critical,serverAuth,clientAuth",                                                              # Adding x509v3 extensions
         "-addext", f"subjectAltName=DNS:ocsp.valid.{user.name}.ru",                                                                 # Adding Alternative Name
         "-addext", f"authorityInfoAccess=OCSP;URI:http://ocsp.{user.name}.ru/",
         "-out", f"{workdir}/{file_prefix}-ocsp-valid.csr"])                                                                         # Setting up output file
    # Generating certificate from request
    run(["openssl", "x509", "-req", "-days", f"{task.basic_time}",
         "-CA", f"{workdir}/{file_prefix}-intr.crt", "-CAkey", f"{workdir}/{file_prefix}-intr.key", "-passin", f"pass:{user.name}", # Passing intr cerificate with key and password
         #"-CAcreateserial", "-CAserial", f"{workdir}/serial",
         "-copy_extensions", "copy",                                                                                                # Copying x509v3 extensions from request to certificate
         "-in", f"{workdir}/{file_prefix}-ocsp-valid.csr",                                                                           # Passing request
         "-out", f"{workdir}/{file_prefix}-ocsp-valid.crt"])                                                                         # Specifying output path

    #################### Revoked Certificate ##########################
    # Generating RSA-key without encryption and with specified length
    run(["openssl", "genrsa", "-out", f"{workdir}/{file_prefix}-ocsp-revoked.key", f"{task.basic_keylen}"])
    # Generating certificate signing request
    run(["openssl", "req", "-new",
         "-key", f"{workdir}/{file_prefix}-ocsp-revoked.key",                                                                          # Passing RSA key
         "-subj", f"/C=RU/ST=Moscow/L=Moscow/O={user.name}/OU={user.name} P1_3/CN={user.name} OCSP Revoked/emailAddress={user.email}", # Setting certificate parameters in format /param1=value1/param2=value2/...
         "-addext", "basicConstraints=CA:FALSE",                                                                                      # Adding x509v3 extensions
         "-addext", "keyUsage=critical,digitalSignature",                                                                             # Adding x509v3 extensions
         "-addext", "extendedKeyUsage=critical,serverAuth,clientAuth",                                                                # Adding x509v3 extensions
         "-addext", f"subjectAltName=DNS:ocsp.revoked.{user.name}.ru",                                                                 # Adding Alternative Name
         "-addext", f"authorityInfoAccess=OCSP;URI:http://ocsp.{user.name}.ru/",
         "-out", f"{workdir}/{file_prefix}-ocsp-revoked.csr"])                                                                         # Setting up output file
    # Generating certificate from request
    run(["openssl", "x509", "-req", "-days", f"{task.basic_time}",
         "-CA", f"{workdir}/{file_prefix}-intr.crt", "-CAkey", f"{workdir}/{file_prefix}-intr.key", "-passin", f"pass:{user.name}", # Passing intr cerificate with key and password
         #"-CAcreateserial", "-CAserial", f"{workdir}/serial",
         "-copy_extensions", "copy",                                                                                                # Copying x509v3 extensions from request to certificate
         "-in", f"{workdir}/{file_prefix}-ocsp-revoked.csr",                                                                           # Passing request
         "-out", f"{workdir}/{file_prefix}-ocsp-revoked.crt"])                                                                         # Specifying output path
    
    
    # # Generating archive with solution
    # with ZipFile(archive_name, "w") as archive:
    #     for directory, _, files in walk(workdir):
    #         for file in files:
    #             if file.endswith(".key") or file.endswith(".crt"):
    #                 archive.write(f"{directory}/{file}", arcname=file)

    # if isfile(archive_name):
    #     print(f"Results saved in \x1b[1;4m{archive_name}\x1b[0m. To pass HW, send this archive to \x1b[1;4minsecon@ispras.ru\x1b[0m with topic \x1b[1;4m{email_topic}\x1b[0m.")
    # else:
    #     print("Something gone wrong!")
          
