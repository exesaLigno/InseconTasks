#!/usr/bin/python

from subprocess import run
from json import load, loads
from os import mkdir, rmdir
from os.path import isdir

TASK_NO = "p1_1"

if __name__ == "__main__":
    
    with open("lab_config.json", "r") as config_file:
        config = load(config_file)
    
    workdir = f"{config['name']}-{config['group']}-{TASK_NO}"
    
    if isdir(workdir): rmdir(workdir)

    mkdir(workdir)

    run(["openssl", "genrsa", "-aes256", "-passout", f"pass:{config['name']}", "-out", f"{workdir}/root.key", "4096"])
    run(["openssl", "req", "-x509", "-new", "-key", f"{workdir}/root.key", "-days", f"{365 * 3}", "-out", f"{workdir}/root.crt"])
