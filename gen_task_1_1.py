#!/usr/bin/python

from base import Config

from subprocess import run
from os import mkdir, walk
from os.path import isdir, isfile
from shutil import rmtree
from zipfile import ZipFile

if __name__ == "__main__":
    
    user = Config("user.json")
    task = Config("p1_1.json")
    
    workdir = f"{user.name}-{user.group}-{task.no}"
    file_prefix = f"{user.name}-{user.group}"
    archive_name = f"{workdir}/{file_prefix}-p1_1.zip"
    email_topic = f"{user.university}-{user.group}-{task.no}"
    
    if isdir(workdir): rmtree(workdir)
    mkdir(workdir)

    run(["openssl", "genrsa", "-aes256", "-passout", f"pass:{user.name}", "-out", f"{workdir}/{file_prefix}-ca.key", f"{task.ca_keylen}"])
    run(["openssl", "req", "-x509", "-new", "-key", 
         f"{workdir}/{file_prefix}-ca.key", "-passin", f"pass:{user.name}", 
         "-days", f"{task.ca_time}", 
         "-subj", f"/C=RU/ST=Moscow/L=Moscow/O={user.name}/OU={user.name} P1_1/CN={user.name} CA/emailAddress={user.email}",
         "-addext", "basicConstraints=critical,CA:TRUE",
         "-addext", "keyUsage=critical,digitalSignature,keyCertSign,cRLSign",
         "-out", f"{workdir}/{file_prefix}-ca.crt"])

    run(["openssl", "genrsa", "-aes256", "-passout", f"pass:{user.name}", "-out", f"{workdir}/{file_prefix}-intr.key", f"{task.intr_keylen}"])
    run(["openssl", "req", "-new", 
         "-key", f"{workdir}/{file_prefix}-intr.key", "-passin", f"pass:{user.name}", 
         "-subj", f"/C=RU/ST=Moscow/L=Moscow/O={user.name}/OU={user.name} P1_1/CN={user.name} Intermediate CA/emailAddress={user.email}",
         "-addext", "basicConstraints=critical,pathlen:0,CA:TRUE",
         "-addext", "keyUsage=critical,digitalSignature,keyCertSign,cRLSign",
         "-out", f"{workdir}/{file_prefix}-intr.csr"])
    run(["openssl", "x509", "-req", "-days", f"{task.intr_time}",
         "-CA", f"{workdir}/{file_prefix}-ca.crt", "-CAkey", f"{workdir}/{file_prefix}-ca.key", "-passin", f"pass:{user.name}",
         #"-CAcreateserial", "-CAserial", f"{workdir}/serial",
         "-copy_extensions", "copy",
         "-in", f"{workdir}/{file_prefix}-intr.csr", 
         "-out", f"{workdir}/{file_prefix}-intr.crt"])

    run(["openssl", "genrsa", "-out", f"{workdir}/{file_prefix}-basic.key", f"{task.basic_keylen}"])
    run(["openssl", "req", "-new",
         "-key", f"{workdir}/{file_prefix}-basic.key",
         "-subj", f"/C=RU/ST=Moscow/L=Moscow/O={user.name}/OU={user.name} P1_1/CN={user.name} Basic/emailAddress={user.email}",
         "-addext", "basicConstraints=CA:FALSE",
         "-addext", "keyUsage=critical,digitalSignature",
         "-addext", "extendedKeyUsage=critical,serverAuth,clientAuth",
         "-addext", f"subjectAltName=DNS:basic.{user.name}.ru,DNS:basic.{user.name}.com",
         "-out", f"{workdir}/{file_prefix}-basic.csr"])
    run(["openssl", "x509", "-req", "-days", f"{task.basic_time}",
         "-CA", f"{workdir}/{file_prefix}-intr.crt", "-CAkey", f"{workdir}/{file_prefix}-intr.key", "-passin", f"pass:{user.name}",
         #"-CAcreateserial", "-CAserial", f"{workdir}/serial",
         "-copy_extensions", "copy",
         "-in", f"{workdir}/{file_prefix}-basic.csr",
         "-out", f"{workdir}/{file_prefix}-basic.crt"])
    
    with ZipFile(archive_name, "w") as archive:
        for directory, _, files in walk(workdir):
            for file in files:
                if file.endswith(".key") or file.endswith(".crt"):
                    archive.write(f"{directory}/{file}", arcname=file)

    if isfile(archive_name):
        print(f"Results saved in \x1b[1;4m{archive_name}\x1b[0m. To pass HW, send this archive to \x1b[1;4minsecon@ispras.ru\x1b[0m with topic \x1b[1;4m{email_topic}\x1b[0m.")
    else:
        print("Something gone wrong!")
          
