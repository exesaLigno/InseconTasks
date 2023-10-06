#!/usr/bin/python

from subprocess import run
from json import load, loads
from os import mkdir
from os.path import isdir
from shutil import rmtree

TASK_NO = "p1_1"

if __name__ == "__main__":
    
    with open("lab_config.json", "r") as config_file:
        config = load(config_file)
    
    workdir = f"{config['name']}-{config['group']}-{TASK_NO}"
    file_prefix = f"{config['name']}-{config['group']}"
    
    if isdir(workdir): rmtree(workdir)

    mkdir(workdir)

    run(["openssl", "genrsa", "-aes256", "-passout", f"pass:{config['name']}", "-out", f"{workdir}/{file_prefix}-ca.key", "4096"])
    run(["openssl", "req", "-x509", "-new", "-key", 
         f"{workdir}/{file_prefix}-ca.key", "-passin", f"pass:{config['name']}", 
         "-days", f"{365 * 3}", 
         "-subj", f"/C=RU/ST=Moscow/L=Moscow/O={config['name']}/OU={config['name']} P1_1/CN={config['name']} CA/emailAddress={config['email']}",
         "-addext", "basicConstraints=critical,CA:TRUE",
         "-addext", "keyUsage=critical,digitalSignature,keyCertSign,cRLSign",
         "-out", f"{workdir}/{file_prefix}-ca.crt"])

    run(["openssl", "genrsa", "-aes256", "-passout", f"pass:{config['name']}", "-out", f"{workdir}/{file_prefix}-intr.key", "4096"])
    run(["openssl", "req", "-new", 
         "-key", f"{workdir}/{file_prefix}-intr.key", "-passin", f"pass:{config['name']}", 
         "-subj", f"/C=RU/ST=Moscow/L=Moscow/O={config['name']}/OU={config['name']} P1_1/CN={config['name']} Intermediate CA/emailAddress={config['email']}",
         "-addext", "basicConstraints=critical,pathlen:0,CA:TRUE",
         "-addext", "keyUsage=critical,digitalSignature,keyCertSign,cRLSign",
         "-out", f"{workdir}/{file_prefix}-intr.csr"])
    run(["openssl", "x509", "-req", "-days", f"{365 * 1}",
         "-CA", f"{workdir}/{file_prefix}-ca.crt", "-CAkey", f"{workdir}/{file_prefix}-ca.key", "-passin", f"pass:{config['name']}",
         #"-CAcreateserial", "-CAserial", f"{workdir}/serial",
         "-copy_extensions", "copy",
         "-in", f"{workdir}/{file_prefix}-intr.csr", 
         "-out", f"{workdir}/{file_prefix}-intr.crt"])

    
