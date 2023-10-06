#!/usr/bin/python

from base import Config

from subprocess import run
from os import mkdir, walk
from os.path import isdir, isfile
from shutil import rmtree
from zipfile import ZipFile

if __name__ == "__main__":
    
    user = Config("user.json")
    task = Config("p1_2.json")
    
    workdir = f"{user.name}-{user.group}-{task.no}"
    file_prefix = f"{user.name}-{user.group}"
    archive_name = f"{workdir}/{file_prefix}-p1_1.zip"
    email_topic = f"{user.university}-{user.group}-{task.no}"
    crl_filename = f"{user.name}-{user.group}.crl"
    crl_distrib_point = f"URI:http://crl.{user.name}.ru:8080/{crl_filename}"

    with open("temp.conf", "w") as conf:
        conf.write(f"crlDistributionPoints={crl_distrib_point}\n")
    
    if isdir(workdir): rmtree(workdir)
    mkdir(workdir)

    # Generating RSA-key with aes256 encryption and specified length
    run(["openssl", "genrsa", "-aes256", "-passout", f"pass:{user.name}", "-out", f"{workdir}/{file_prefix}-ca.key", f"{task.ca_keylen}"])
    # Generating self-signed certificate with specified RSA key
    run(["openssl", "req", "-x509", "-new", 
         "-key", f"{workdir}/{file_prefix}-ca.key", "-passin", f"pass:{user.name}",                                          # Passing encrypted RSA key and password
         "-days", f"{task.ca_time}",                                                                                         # Setting time limit for certificate
         "-subj", f"/C=RU/ST=Moscow/L=Moscow/O={user.name}/OU={user.name} P1_2/CN={user.name} CA/emailAddress={user.email}", # Setting certificate parameters in format /param1=value1/param2=value2/...
         "-addext", "basicConstraints=critical,CA:TRUE",                                                                     # Adding x509v3 extensions
         "-addext", "keyUsage=critical,digitalSignature,keyCertSign,cRLSign",                                                # Adding x509v3 extensions
         "-out", f"{workdir}/{file_prefix}-ca.crt"])                                                                         # Setting up output file

    # Generating RSA-key with aes256 encryption and specified length
    run(["openssl", "genrsa", "-aes256", "-passout", f"pass:{user.name}", "-out", f"{workdir}/{file_prefix}-intr.key", f"{task.intr_keylen}"])
    # Generating certificate signing request
    run(["openssl", "req", "-new", 
         "-key", f"{workdir}/{file_prefix}-intr.key", "-passin", f"pass:{user.name}",                                                      # Passing encrypted RSA key and password
         "-subj", f"/C=RU/ST=Moscow/L=Moscow/O={user.name}/OU={user.name} P1_2/CN={user.name} Intermediate CA/emailAddress={user.email}",  # Setting certificate parameters in format /param1=value1/param2=value2/...
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

    # Generating basic valid certificate
    # Generating RSA-key without encryption and with specified length
    run(["openssl", "genrsa", "-out", f"{workdir}/{file_prefix}-crl-valid.key", f"{task.basic_keylen}"])
    # Generating certificate signing request
    run(["openssl", "req", "-new",
         "-key", f"{workdir}/{file_prefix}-crl-valid.key",                                                                          # Passing RSA key
         "-subj", f"/C=RU/ST=Moscow/L=Moscow/O={user.name}/OU={user.name} P1_2/CN={user.name} CRL Valid/emailAddress={user.email}", # Setting certificate parameters in format /param1=value1/param2=value2/...
         "-addext", "basicConstraints=CA:FALSE",                                                                                    # Adding x509v3 extensions
         "-addext", "keyUsage=critical,digitalSignature",                                                                           # Adding x509v3 extensions
         "-addext", "extendedKeyUsage=critical,serverAuth,clientAuth",                                                              # Adding x509v3 extensions
         "-addext", f"subjectAltName=DNS:crl.valid.{user.name}.ru",                                                                 # Adding Alternative Name
         "-addext", f"crlDistributionPoints={crl_distrib_point}",                                                                   # Adding CRL Distribution Points
         "-out", f"{workdir}/{file_prefix}-crl-valid.csr"])                                                                         # Setting up output file
    # Generating certificate from request
    run(["openssl", "x509", "-req", "-days", f"{task.basic_time}",
         "-CA", f"{workdir}/{file_prefix}-intr.crt", "-CAkey", f"{workdir}/{file_prefix}-intr.key", "-passin", f"pass:{user.name}", # Passing intr cerificate with key and password
         #"-CAcreateserial", "-CAserial", f"{workdir}/serial",
         "-copy_extensions", "copy",                                                                                                # Copying x509v3 extensions from request to certificate
         "-in", f"{workdir}/{file_prefix}-crl-valid.csr",                                                                           # Passing request
         "-out", f"{workdir}/{file_prefix}-crl-valid.crt"])                                                                         # Specifying output path

    # Generating basic revoked certificate
    # Generating RSA-key without encryption and with specified length
    run(["openssl", "genrsa", "-out", f"{workdir}/{file_prefix}-crl-revoked.key", f"{task.basic_keylen}"])
    # Generating certificate signing request
    run(["openssl", "req", "-new",
         "-key", f"{workdir}/{file_prefix}-crl-revoked.key",                                                                          # Passing RSA key
         "-subj", f"/C=RU/ST=Moscow/L=Moscow/O={user.name}/OU={user.name} P1_2/CN={user.name} CRL Revoked/emailAddress={user.email}", # Setting certificate parameters in format /param1=value1/param2=value2/...
         "-addext", "basicConstraints=CA:FALSE",                                                                                      # Adding x509v3 extensions
         "-addext", "keyUsage=critical,digitalSignature",                                                                             # Adding x509v3 extensions
         "-addext", "extendedKeyUsage=critical,serverAuth,clientAuth",                                                                # Adding x509v3 extensions
         "-addext", f"subjectAltName=DNS:crl.revoked.{user.name}.ru",                                                                 # Adding Alternative Name
         "-addext", f"crlDistributionPoints={crl_distrib_point}",                                                                     # Adding CRL Distribution Points
         "-out", f"{workdir}/{file_prefix}-crl-revoked.csr"])                                                                         # Setting up output file
    # Generating certificate from request
    run(["openssl", "x509", "-req", "-days", f"{task.basic_time}",
         "-CA", f"{workdir}/{file_prefix}-intr.crt", "-CAkey", f"{workdir}/{file_prefix}-intr.key", "-passin", f"pass:{user.name}", # Passing intr cerificate with key and password
         #"-CAcreateserial", "-CAserial", f"{workdir}/serial",
         "-copy_extensions", "copy",                                                                                                # Copying x509v3 extensions from request to certificate
         "-in", f"{workdir}/{file_prefix}-crl-revoked.csr",                                                                           # Passing request
         "-out", f"{workdir}/{file_prefix}-crl-revoked.crt"])                                                                         # Specifying output path

    # Generating CRL file
    run(["openssl", "ca", 
         "-config", "temp.conf",
         "-gencrl",
         "-out", crl_filename])
