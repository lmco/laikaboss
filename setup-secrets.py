#!/usr/bin/env python3
import os
import shutil
import secrets
import socket
import configparser
import getpass
import random
from laikaboss.lbconfigparser import LBConfigParser

from passlib.apache import HtpasswdFile

from jinja2 import Template

_source_path = os.path.dirname(os.path.realpath(__file__))

default_configs = {
  "redis_secret_file":"/etc/laikaboss/secrets/redis_pass",
  "redis_secret_file2":"/etc/laikaboss/secrets/redis/redis_pass",
  "tls_key_file":"/etc/laikaboss/secrets/server.key",
  "tls_cert_file":"/etc/laikaboss/secrets/server.crt",
  "ca_certificate":"/etc/laikaboss/secrets/cacert.crt",
  "redis_tls_key_file":"/etc/laikaboss/secrets/redis/server.key",
  "redis_tls_cert_file":"/etc/laikaboss/secrets/redis/server.crt",
  "redis_ca_certificate":"/etc/laikaboss/secrets/redis/cacert.crt",
  "apache_tls_key_file":"/etc/laikaboss/secrets/apache/server.key",
  "apache_tls_cert_file":"/etc/laikaboss/secrets/apache/server.crt",
  "apache_ca_certificate":"/etc/laikaboss/secrets/apache/cacert.crt",
  "auth_user_password_db":"/etc/laikaboss/secrets/htpasswd.db",
  "db_password_file":"/etc/laikaboss/secrets/db_password",
  "db_password_file2":"/etc/laikaboss/secrets/postgres/db_password",
  "newness_password_file":"/etc/laikaboss/secrets/local_creds",
  "lb_client_secret_file":"/etc/laikaboss/secrets/lb_client_secret_file",
  "storage_s3_creds_file":"/etc/laikaboss/secrets/s3_creds",
  "storage_s3_secret_file":"/etc/laikaboss/secrets/s3_secret_key",
  "storage_s3_access_file":"/etc/laikaboss/secrets/s3_access_key"
}

def _file_exists(path):

    try:
        if os.path.getsize(path):
           return True
    except:
        pass

    return False

def copy(src, dst, overwrite=True):

   if overwrite or not _file_exists(dst):
      shutil.copy(src, dst)

def files_exist(paths, fix):

    if isinstance(paths, str):
        paths = [paths]

    paths_valid(paths, fix)

    for x in paths:
        if _file_exists(x):
           return True

    return False

def paths_valid(path, fix=False):

    paths = path
    if isinstance(path, str):
        paths = [path]

    for x in paths:
        if "{{" in x:
            raise ValueError("path: {} is invalid".format(x))
        if os.path.isdir(x):
            if fix:
                os.rmdir(x)
                return False

            raise ValueError("Path: {} should be a file but is a directory??".format(path))

    return True

def cert_gen(
    commonName,
    emailAddress=None,
    countryName=None,
    localityName=None,
    stateOrProvinceName=None,
    organizationName=None,
    organizationUnitName=None,
    serialNumber=0,
    validityStartInSeconds=0,
    validityEndInSeconds=10*365*24*60*60,
    KEY_FILE = "private.key",
    CERT_FILE="selfsigned.crt",
    CA_FILE=None):

    if files_exist([KEY_FILE, CERT_FILE], fix=True):
      return

    if not serialNumber:
        # max 64 bit (signed int)
        serialNumber = random.getrandbits(63)


    from OpenSSL import crypto
    #can look at generated file using openssl:
    #openssl x509 -inform pem -in selfsigned.crt -noout -text
    # create a key pair
    k = crypto.PKey()
    k.generate_key(crypto.TYPE_RSA, 4096)
    # create a self-signed cert

    san_list = ["DNS:" + commonName]

    cert = crypto.X509()
    if countryName:
       cert.get_subject().C = countryName
    if stateOrProvinceName:
       cert.get_subject().ST = stateOrProvinceName
    if localityName:
       cert.get_subject().L = localityName

    if organizationName:
       cert.get_subject().O = organizationName
    if organizationUnitName:
       cert.get_subject().OU = organizationUnitName

    cert.get_subject().CN = commonName

    if emailAddress:
       cert.get_subject().emailAddress = emailAddress

    cert.set_serial_number(serialNumber)

    # 2 means version 3
    cert.set_version(2)

    cert.gmtime_adj_notBefore(0)

    cert.gmtime_adj_notAfter(validityEndInSeconds)


    cert.set_issuer(cert.get_subject())
    cert.set_pubkey(k)
    cert.add_extensions([
      crypto.X509Extension(
        b"subjectAltName", False, ", ".join(san_list).encode('utf-8'))
    ])
    cert.sign(k, 'sha512')

    with open(CERT_FILE, "wt") as f:
        f.write(crypto.dump_certificate(crypto.FILETYPE_PEM, cert).decode("utf-8"))
    with open(KEY_FILE, "wt") as f:
        f.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, k).decode("utf-8"))

    if CA_FILE and not files_exist(CA_FILE, fix=True):
       shutil.copyfile(CERT_FILE, CA_FILE)

def prompt_and_populate(question, valid_answers=[], validation_function=False, default_value=False):
    if valid_answers:
        print("{} {}".format(question, valid_answers))
    else:
        print(question)
    if default_value:
        print('Default: {}'.format(default_value))

    response = input()
    response = default_value if not response else response

    if not default_value:
        if len(valid_answers) != 0:
            while response not in valid_answers:
                print(question)
                response = input()
        elif validation_function != False:
            while not validation_function(response):
                print(question)
                response = input()
    return response

def main():

    redis_pass = secrets.token_urlsafe(nbytes=12)
    config = LBConfigParser()

    options = {}

    hostname = ''

    if not hostname:
        hostname = socket.getfqdn()

    ok = False

    while not ok:
        options['hostname'] = prompt_and_populate('What is the FQDN for the redis host on this cluster"?', default_value=hostname)
        if not options['hostname'] or options['hostname'] in ['localhost', 'localhost.localdomain'] or '.' not in options['hostname']:
            print("The hostname must be fully qualified with at least one dot, and not contain localhost")
        else:
            ok = True

    orig_options = options.copy()

    file_name = default_configs['newness_password_file']

    newness_passwd = None

    if not files_exist(file_name, fix=True):
       newness_passwd = secrets.token_urlsafe(nbytes=12)
       with open(file_name, 'w') as f:
              f.write('laika_system:' + newness_passwd)

       new = True
       auth_password = default_configs['auth_user_password_db']

       if files_exist(auth_password, fix=True):
          new = False

       ht = HtpasswdFile(auth_password, new=new)
       ht.set_password("laika_system", newness_passwd)

       """
       user_passwd = ''
       user_passwd2 = ''
       first = True

       while not user_passwd or user_passwd2!=user_passwd:
          if not first:
              print('Password mismatch please try again')
              first = False
          user_passwd = getpass.getpass(prompt='Type set default password for local laika_user account: ')
          user_passwd2 = getpass.getpass(prompt='Retype password: ')

       ht.set_password("laika_user", user_passwd)
       """

       ht.save()

    redis_secret_file = default_configs['redis_secret_file']
    redis_secret_file2 = default_configs['redis_secret_file2']

    if not files_exist(redis_secret_file, fix=True):
       redis_pass = secrets.token_urlsafe(nbytes=12)
       with open(redis_secret_file, 'w') as f:
           f.write(redis_pass)
       with open(redis_secret_file2, 'w') as f:
           f.write(redis_pass)

    key = os.path.abspath(default_configs['tls_key_file'])
    crt = os.path.abspath(default_configs['tls_cert_file'])
    ca = os.path.abspath(default_configs['ca_certificate'])
     
    if not files_exist([key, crt], fix=True):
        cert_gen(KEY_FILE = key, CERT_FILE=crt, CA_FILE=ca, commonName = options['hostname'])

    redis_key = os.path.abspath(default_configs['redis_tls_key_file'])
    redis_crt = os.path.abspath(default_configs['redis_tls_cert_file'])
    redis_ca = os.path.abspath(default_configs['redis_ca_certificate'])

    if not files_exist([redis_key, redis_crt], fix=True):
       copy(key, redis_key, overwrite=False)
       copy(crt, redis_crt, overwrite=False)
       copy(ca, redis_ca, overwrite=False)

    apache_key = os.path.abspath(default_configs['apache_tls_key_file'])
    apache_crt = os.path.abspath(default_configs['apache_tls_cert_file'])
    apache_ca = os.path.abspath(default_configs['apache_ca_certificate'])

    if not files_exist([apache_key, apache_crt], fix=True):
       copy(key, apache_key, overwrite=False)
       copy(crt, apache_crt, overwrite=False)
       copy(ca, apache_ca, overwrite=False)

    hostname = options['hostname']

    short_hostname = hostname
    if '.' in hostname:
       short_hostname = hostname[:short_hostname.find('.')]

    options['hostname_short'] = short_hostname

    file_name = default_configs['db_password_file']
    file_name2 = default_configs['db_password_file2']

    if not files_exist([file_name], fix=True):
       secret=secrets.token_urlsafe(nbytes=64)
       with open(file_name, 'w') as f:
            f.write(secret)
       with open(file_name2, 'w') as f:
            f.write(secret)

    file_name = default_configs['lb_client_secret_file']
    if not files_exist([file_name], fix=True):
       with open(file_name, 'w') as f:
            secret=secrets.token_urlsafe(nbytes=64)
            f.write(secret)

    access_file = default_configs['storage_s3_access_file']
    secret_file = default_configs['storage_s3_secret_file']
    s3_creds = default_configs['storage_s3_creds_file']

    if not files_exist([access_file, secret_file], fix=True):

        with open(access_file, 'w') as f:
            access_key=secrets.token_urlsafe(nbytes=64)
            f.write(access_key)

        with open(secret_file, 'w') as f:
            secret_key=secrets.token_urlsafe(nbytes=64)
            f.write(secret_key)

        with open(s3_creds, 'w') as f:
            blob = access_key + ":" + secret_key
            f.write(blob)

    print("Modify the local laika_cluster.conf file including the hostname attribute and copy to /etc/laikaboss/laika_cluster.conf then run the setup-host.sh script again to fix permissions.")

if __name__ == "__main__":
    main()
