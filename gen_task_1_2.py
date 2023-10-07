#!/usr/bin/python

from base import Config

from subprocess import run
from os import mkdir, walk
from os.path import isdir, isfile
from shutil import rmtree
from zipfile import ZipFile

if __name__ == "__main__":
    
    user = Config("user.json")
    task = Config("tasks/p1_2.json")
    
    workdir = f"{user.name}-{user.group}-{task.no}"
    file_prefix = f"{user.name}-{user.group}"
    archive_name = f"{workdir}/{file_prefix}-{task.no}.zip"
    email_topic = f"{user.university}-{user.group}-{task.no}"
    crl_filename = f"{user.name}-{user.group}.crl"
    crl_distrib_point = f"URI:http://crl.{user.name}.ru:8080/{crl_filename}"

    files_to_save = [f"{user.name}-{user.group}.crl", f"{file_prefix}.crt", 
                     f"{file_prefix}-crl-valid.key", f"{file_prefix}-crl-valid.crt",
                     f"{file_prefix}-crl-revoked.key", f"{file_prefix}-crl-revoked.crt"]
    
    if isdir(workdir): rmtree(workdir)
    mkdir(workdir)

    with open(f"{workdir}/crl.conf", "w") as conf:
        conf.write(f"authorityKeyIdentifier=keyid,issuer\n")
        conf.write(f"[ basic_cert ]\n")
        conf.write(f"crlDistributionPoints={crl_distrib_point}\n")
        conf.write(f"[ ca ]\n")
        conf.write(f"default_ca=CA_default\n")
        conf.write(f"[ CA_default ]\n")
        conf.write(f"database = {workdir}/index.txt\n")
        conf.write(f"default_md = sha256\n")
        conf.write(f"default_crl_days = 30\n")

    with open(f"{workdir}/index.txt", "w"): pass

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
    
    print(f"\n\n-------Revoking one of certificates-------")
    run(["openssl", "ca", 
         "-config", f"{workdir}/crl.conf", 
         "-cert", f"{workdir}/{file_prefix}-intr.crt", "-keyfile", f"{workdir}/{file_prefix}-intr.key", "-passin", f"pass:{user.name}",
         "-revoke", f"{workdir}/{file_prefix}-crl-revoked.crt"])
    
    run(["openssl", "ca", 
         "-config", f"{workdir}/crl.conf",
         "-cert", f"{workdir}/{file_prefix}-intr.crt", "-keyfile", f"{workdir}/{file_prefix}-intr.key", "-passin", f"pass:{user.name}",
         "-gencrl",
         "-out", f"{workdir}/{crl_filename}"])
    
    print(f"\n\n-------Generating certificate chain-------")
    with open(f"{workdir}/{file_prefix}.crt", "w") as chain:
        with open(f"{workdir}/{file_prefix}-intr.crt", "r") as intr:
            chain.write(intr.read())
        with open(f"{workdir}/{file_prefix}-ca.crt", "r") as ca:
            chain.write(ca.read())
    if isfile(f"{workdir}/{file_prefix}.crt"):
        print(f"Generated certificate chain: {workdir}/{file_prefix}.crt")

    print(f"\n\n-------Testing valid and revoked certificates-------")
    run(["openssl", "verify", "-crl_check", "-CRLfile", f"{workdir}/{crl_filename}", 
         "-CAfile", f"{workdir}/{file_prefix}.crt", 
         f"{workdir}/{file_prefix}-crl-valid.crt"])
    run(["openssl", "verify", "-crl_check", "-CRLfile", f"{workdir}/{crl_filename}", 
         "-CAfile", f"{workdir}/{file_prefix}.crt", 
         f"{workdir}/{file_prefix}-crl-revoked.crt"])

    # Generating archive with solution
    with ZipFile(archive_name, "w") as archive:
        for directory, _, files in walk(workdir):
            for file in files:
                if file in files_to_save:
                    archive.write(f"{directory}/{file}", arcname=file)

    if isfile(archive_name):
        print(f"Results saved in \x1b[1;4m{archive_name}\x1b[0m. To pass HW, send this archive to \x1b[1;4minsecon@ispras.ru\x1b[0m with topic \x1b[1;4m{email_topic}\x1b[0m.")
    else:
        print("Something gone wrong!")
