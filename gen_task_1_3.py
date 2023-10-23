#!/usr/bin/python

from base import Config

from subprocess import run, Popen, DEVNULL, check_call
from os import mkdir, walk, geteuid, remove, listdir, environ
from os.path import isdir, isfile, abspath
from shutil import rmtree, which, copy, move
from zipfile import ZipFile

def reboot_ifaces():
    for iface in listdir('/sys/class/net'):
        run(['ifconfig', iface, 'down'])
        run(['ifconfig', iface, 'up'])
        print(f'{iface} rebooted')

if __name__ == "__main__":
    
    user = Config("user.json")
    task = Config("tasks/p1_3.json")
    
    workdir = f"{user.name}-{user.group}-{task.no}"
    file_prefix = f"{user.name}-{user.group}"
    archive_name = f"{workdir}/{file_prefix}-{task.no}.zip"
    email_topic = f"{user.university}-{user.group}-{task.no}"

    keeplist = [f"{file_prefix}-ocsp-valid.key", f"{file_prefix}-ocsp-valid.crt",
                f"{file_prefix}-ocsp-revoked.key", f"{file_prefix}-ocsp-revoked.crt",
                f"{file_prefix}-ocsp-resp.key", f"{file_prefix}-ocsp-resp.crt", 
                f"{file_prefix}-chain.crt",
                f"{file_prefix}-ocsp-valid.pcapng", f"{file_prefix}-ocsp-valid.log",
                f"{file_prefix}-ocsp-revoked.pcapng", f"{file_prefix}-ocsp-revoked.log"]

    if isdir(workdir): rmtree(workdir)
    mkdir(workdir)

    if which("nginx") == None:
        print(f"NGINX is needed for this task, install it with your packet manager")
        print(f"e.g. \x1b[1mpacman -S nginx\x1b[0m for Arch")
        print(f"e.g. \x1b[1mapt-get install nginx\x1b[0m for Debian")
        exit(1)

    if geteuid() != 0:
        print("You must run this script as sudoer, exiting...")
        exit(1)

    ################## Configuration for Certificate revoking ################
    with open(f"{workdir}/ocsp.conf", "w") as conf:
        conf.write(f"[ basic_cert ]\n")
        conf.write(f"authorityInfoAccess = OCSP;URI:http://ocsp.{user.name}.ru:2560\n")
        conf.write(f"[ req ]\n")
        conf.write(f"database = {workdir}/index.txt\n")
        conf.write(f"[ ca ]\n")
        conf.write(f"default_ca=CA_default\n")
        conf.write(f"[ CA_default ]\n")
        conf.write(f"database = {workdir}/index.txt\n")
        conf.write(f"default_md = sha256\n")
        conf.write(f"default_crl_days = 30\n")
        conf.write(f"crl_extensions = crl_ext\n")
        conf.write(f"[ crl_ext ]\n")
        conf.write(f"authorityKeyIdentifier=keyid:always\n")

    with open(f"{workdir}/index.txt", "w"): pass

    #################### CA Certificate ##########################
    print(f"\n------- Generating CA Certificate -------")
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
    print(f"\n------- Generating Intermediate Certificate -------")
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

    ################### Installing certificate #####################
    if isdir("/etc/ca-certificates/trust-source/anchors"):
        copy(f"{workdir}/{file_prefix}-intr.crt", f"/etc/ca-certificates/trust-source/anchors/{file_prefix}-intr.crt")
        run(["trust", "extract-compat"])
    else:
        _ = input(f"\x1b[1;31mSounds like your OS has no centralized certificate db. Open Firefox, import \x1b[4;31m{file_prefix}-ca.crt\x1b[0m\x1b[1;31m and press Enter to continue...\x1b[0m")

    ################### Generating CA Chain #########################
    print(f"\n------- Generating certificate chain -------")
    with open(f"{workdir}/{file_prefix}-chain.crt", "w") as chain:
        with open(f"{workdir}/{file_prefix}-ca.crt", "r") as ca:
            chain.write(ca.read())
        with open(f"{workdir}/{file_prefix}-intr.crt", "r") as intr:
            chain.write(intr.read())
    if isfile(f"{workdir}/{file_prefix}-chain.crt"):
        print(f"Generated certificate chain: {workdir}/{file_prefix}-chain.crt")

    ################ OCSP Responder Certificate #####################
    print(f"\n------- Generating OCSP Responder Certificate -------")
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
    
    #################### Revoked Certificate ##########################
    print(f"\n------- Generating Revoked Certificate -------")
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
         "-addext", f"authorityInfoAccess=OCSP;URI:http://ocsp.{user.name}.ru:2560/",
         "-out", f"{workdir}/{file_prefix}-ocsp-revoked.csr"])                                                                         # Setting up output file
    # Generating certificate from request
    run(["openssl", "x509", "-req", "-days", f"{task.basic_time}",
         "-CA", f"{workdir}/{file_prefix}-intr.crt", "-CAkey", f"{workdir}/{file_prefix}-intr.key", "-passin", f"pass:{user.name}", # Passing intr cerificate with key and password
         #"-CAcreateserial", "-CAserial", f"{workdir}/serial",
         "-copy_extensions", "copy",                                                                                                # Copying x509v3 extensions from request to certificate
         "-in", f"{workdir}/{file_prefix}-ocsp-revoked.csr",                                                                           # Passing request
         "-out", f"{workdir}/{file_prefix}-ocsp-revoked.crt"])                                                                         # Specifying output path

    ##################### Revoking Certificate ######################
    print(f"\n------- Revoking one of certificates -------")
    run(["openssl", "ca", 
         "-config", f"{workdir}/ocsp.conf", 
         "-cert", f"{workdir}/{file_prefix}-intr.crt", "-keyfile", f"{workdir}/{file_prefix}-intr.key", "-passin", f"pass:{user.name}",
         "-revoke", f"{workdir}/{file_prefix}-ocsp-revoked.crt"])
    
    ######################## Valid Certificate #####################
    print(f"\n------- Generating Valid Certificate -------")
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
         "-addext", f"authorityInfoAccess=OCSP;URI:http://ocsp.{user.name}.ru:2560/",
         "-out", f"{workdir}/{file_prefix}-ocsp-valid.csr"])                                                                         # Setting up output file
    # Generating certificate from request
    run(["openssl", "x509", "-req", "-days", f"{task.basic_time}",
         "-CA", f"{workdir}/{file_prefix}-intr.crt", "-CAkey", f"{workdir}/{file_prefix}-intr.key", "-passin", f"pass:{user.name}", # Passing intr cerificate with key and password
         #"-CAcreateserial", "-CAserial", f"{workdir}/serial",
         "-copy_extensions", "copy",                                                                                                # Copying x509v3 extensions from request to certificate
         "-in", f"{workdir}/{file_prefix}-ocsp-valid.csr",                                                                           # Passing request
         "-out", f"{workdir}/{file_prefix}-ocsp-valid.crt"])                                                                         # Specifying output path

    ##################### Validing Certificate ######################
    print(f"\n------- Validing one of certificates -------")
    run(["openssl", "ca", 
         "-config", f"{workdir}/ocsp.conf", 
         "-cert", f"{workdir}/{file_prefix}-intr.crt", "-keyfile", f"{workdir}/{file_prefix}-intr.key", "-passin", f"pass:{user.name}",
         "-valid", f"{workdir}/{file_prefix}-ocsp-valid.crt"])
    
    ################### Generating Valid Chain #########################
    print(f"\n------- Generating Valid chain -------")
    with open(f"{workdir}/{file_prefix}-ocsp-valid-chain.crt", "w") as valid_chain:
        with open(f"{workdir}/{file_prefix}-ocsp-valid.crt", "r") as ocsp_valid:
            valid_chain.write(ocsp_valid.read())
        with open(f"{workdir}/{file_prefix}-chain.crt", "r") as chain:
            valid_chain.write(chain.read())
    if isfile(f"{workdir}/{file_prefix}-ocsp-valid-chain.crt"):
        print(f"Generated certificate chain: {workdir}/{file_prefix}-ocsp-valid-chain.crt")

    ################### Generating Revoked Chain #########################
    print(f"\n------- Generating Revoked chain -------")
    with open(f"{workdir}/{file_prefix}-ocsp-revoked-chain.crt", "w") as revoked_chain:
        with open(f"{workdir}/{file_prefix}-ocsp-revoked.crt", "r") as ocsp_revoked:
            revoked_chain.write(ocsp_revoked.read())
        with open(f"{workdir}/{file_prefix}-chain.crt", "r") as chain:
            revoked_chain.write(chain.read())
    if isfile(f"{workdir}/{file_prefix}-ocsp-revoked-chain.crt"):
        print(f"Generated certificate chain: {workdir}/{file_prefix}-ocsp-revoked-chain.crt")

    ################# Creating test sites for valid and revoked certs ################
    try: mkdir("/var/www")
    except: pass
    
    try: mkdir(f"/var/www/{file_prefix}-valid")
    except: pass
    with open(f"/var/www/{file_prefix}-valid/index.html", "w") as index:
        index.write(f'<Html><Head><title>Вопрос интимного характера</title></Head><Body><center><h1> Пить пиво </h1><h2> В среду </h2><h3> В 3 часа дня </h3></center>Это лучший способ показать миру свою независимость от предубеждений. <a href="mailto:{user.email}">Присоединяйтесь</a>! <br></Body></Html>')
    
    try: mkdir(f"/var/www/{file_prefix}-revoked")
    except: pass
    with open(f"/var/www/{file_prefix}-revoked/index.html", "w") as index:
        index.write(f'<Html><Head><title>АНТИВОДКА</title></Head><Body><center><h1> Запретим пить водку! </h1></center>Проголосуйте за запрет водки на физтехе по <a href="https://natribu.org/">ссылке</a>! <br></Body></Html>')\
        
    ################## Adding all links to hosts #######################
    print(f"\n------- Adding all links to hosts -------")
    copy('/etc/hosts', '/etc/hosts_backup')
    with open('/etc/hosts', 'a') as hosts:
        hosts.write(f"{task.local_adress} ocsp.{user.name}.ru\n")
        hosts.write(f"{task.local_adress} ocsp.valid.{user.name}.ru\n")
        hosts.write(f"{task.local_adress} ocsp.revoked.{user.name}.ru\n")
    reboot_ifaces()
    
    ################## Configurating NGINX ###################
    print(f"\n------- Adding sites configuration -------")
    copy('/etc/nginx/nginx.conf', '/etc/nginx/nginx.conf.backup')

    chain_path = abspath(f"{workdir}/{file_prefix}-chain.crt")

    valid_site_path = f"/var/www/{file_prefix}-valid"
    valid_key_path = abspath(f"{workdir}/{file_prefix}-ocsp-valid.key")
    valid_cert_path = abspath(f"{workdir}/{file_prefix}-ocsp-valid-chain.crt")

    revoked_site_path = f"/var/www/{file_prefix}-revoked"
    revoked_key_path = abspath(f"{workdir}/{file_prefix}-ocsp-revoked.key")
    revoked_cert_path = abspath(f"{workdir}/{file_prefix}-ocsp-revoked-chain.crt")

    with open(f"/etc/nginx/nginx.conf", "w") as nginx_conf:
        nginx_conf.write(f"""
worker_processes  1;
events {{
    worker_connections  1024;
}}
http {{
    include       mime.types;
    default_type  application/octet-stream;
    sendfile        on;
    keepalive_timeout  65;
    server {{
        listen       80;
        server_name  localhost;
        location / {{
            root   /usr/share/nginx/html;
            index  index.html index.htm;
        }}
        error_page   500 502 503 504  /50x.html;
        location = /50x.html {{
            root   /usr/share/nginx/html;
        }}
    }}
    server {{
        listen       443 ssl;
        server_name  ocsp.valid.{user.name}.ru;
        ssl_certificate      {valid_cert_path};
        ssl_certificate_key  {valid_key_path};
        ssl_session_cache    shared:SSL:1m;
        ssl_session_timeout  5m;
        ssl_ciphers  HIGH:!aNULL:!MD5;
        ssl_prefer_server_ciphers  on;
        # ssl_stapling on;
        # ssl_stapling_verify on;
        # ssl_trusted_certificate {chain_path};
        ssl_ocsp on;
        charset UTF-8;
        location / {{
            root   {valid_site_path};
            index  index.html;
            charset UTF-8;
        }}
    }}
    server {{
        listen       443 ssl;
        server_name  ocsp.revoked.{user.name}.ru;
        ssl_certificate      {revoked_cert_path};
        ssl_certificate_key  {revoked_key_path};
        ssl_session_cache    shared:SSL:1m;
        ssl_session_timeout  5m;
        ssl_ciphers  HIGH:!aNULL:!MD5;
        ssl_prefer_server_ciphers  on;
        # ssl_stapling on;
        # ssl_stapling_verify on;
        # ssl_trusted_certificate {chain_path};
        ssl_ocsp on;
        charset UTF-8;
        location / {{
            root   {revoked_site_path};
            index  index.html;
            charset UTF-8;
        }}
    }}
}}""")
    run(["systemctl", "start", "nginx"])
    run(["nginx", "-s", "reload"])

    ################## Starting OCSP Responder ######################
    print(f"\n------- Starting OCSP Responder -------")
    responder = Popen(["openssl", "ocsp", 
                       "-port", "2560", 
                       "-index", f"{workdir}/index.txt",
                       "-CA", f"{workdir}/{file_prefix}-chain.crt",
                       "-rkey", f"{workdir}/{file_prefix}-ocsp-resp.key", "-passin", f"pass:{user.name}",
                       "-rsigner", f"{workdir}/{file_prefix}-ocsp-resp.crt"], 
                       stdout=DEVNULL, stderr=DEVNULL)

    ################## Testing Valid and Revoked Certificate ######################
    print(f"\n------- Testing valid and revoked certificates -------")
    run(["openssl", "ocsp", "-url", f"http://ocsp.{user.name}.ru:2560/", 
         "-CAfile", f"{workdir}/{file_prefix}-chain.crt",
         "-issuer", f"{workdir}/{file_prefix}-intr.crt", 
         "-cert", f"{workdir}/{file_prefix}-ocsp-valid.crt"])
    run(["openssl", "ocsp", "-url", f"http://ocsp.{user.name}.ru:2560/", 
         "-CAfile", f"{workdir}/{file_prefix}-chain.crt",
         "-issuer", f"{workdir}/{file_prefix}-intr.crt", 
         "-cert", f"{workdir}/{file_prefix}-ocsp-revoked.crt"])
    
    ############### Starting process of verification #################
    _ = input(f"\n\x1b[1;33mPress Enter to stop OCSP Responder, NGINX and restore all settings...\x1b[0m")
    
    print(f"\n------- Killing OCSP Responder -------")
    responder.kill()
    print("OCSP Responder killed")

    print(f"\n------- Removing generated sites -------")
    rmtree(f"/var/www/{file_prefix}-valid")
    rmtree(f"/var/www/{file_prefix}-revoked")
    if len(listdir("/var/www")) == 0:
        rmtree("/var/www")
    print("Sites are removed")

    print(f"\n------- Restoring hosts file -------")
    move('/etc/hosts_backup', '/etc/hosts')
    reboot_ifaces()
    print("Restored hosts file")

    print(f"\n------- Restoring NGINX config file -------")
    move('/etc/nginx/nginx.conf.backup', '/etc/nginx/nginx.conf')
    run(["nginx", "-s", "reload"])
    run(["systemctl", "stop", "nginx"])
    print("Restored NGINX config file")

    if isdir("/etc/ca-certificates/trust-source/anchors"):
        print(f"\n------- Removing certificate -------")
        remove(f"/etc/ca-certificates/trust-source/anchors/{file_prefix}-intr.crt")
        run(["trust", "extract-compat"])
        print(f"Certificate removed")

    # Generating archive with solution
    with ZipFile(archive_name, "w") as archive:
        checklist = keeplist.copy()
        for directory, _, files in walk(workdir):
            for file in files:
                if file in keeplist:
                    checklist.remove(file)
                    archive.write(f"{directory}/{file}", arcname=file)

    print("\n\n------- Exporting results -------")
    if isfile(archive_name) and len(checklist) == 0:
        print(f"Results saved in \x1b[1;4m{archive_name}\x1b[0m. To pass HW, send this archive to \x1b[1;4minsecon@ispras.ru\x1b[0m with topic \x1b[1;4m{email_topic}\x1b[0m.")
    elif len(checklist) != 0:
        print(f"\x1b[1;31mSome files are not found: {', '.join(checklist)}\x1b[0m")
        print(f"Maybe you forgot to save trace from wireshark?")
    else:
        print("\x1b[1;31mSomething gone wrong!\x1b[0m")
          
