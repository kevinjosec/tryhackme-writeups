# OWASP Juice Shop | TryHackMe Write-up

> **TL;DR:** Walked through OWASP's intentionally vulnerable web app, exploiting ten distinct weaknesses across SQL injection, broken authentication, sensitive data exposure, broken access control, and three classes of XSS - all mapped to OWASP Top 10 categories. First structured hands-on run at Burp Suite Intruder, DOM/Stored/Reflected XSS, and IDOR against a real web stack.

|  |  |
|---|---|
| **Platform** | TryHackMe |
| **Room** | [OWASP Juice Shop](https://tryhackme.com/room/owaspjuiceshop) |
| **Difficulty** | Easy |
| **Category** | Web application security · OWASP Top 10 |
| **Date completed** | `<YYYY-MM-DD>` |
| **Author** | Kevin Jose |

**Tools used:** Browser DevTools · Burp Suite (Proxy · Intruder · Repeater) · `SecLists/best1050.txt`
**Vulnerabilities covered:** SQL Injection (CWE-89) · Broken Authentication - brute force (CWE-307) · Broken Authentication - insecure password reset (CWE-640) · Sensitive Data Exposure - open FTP directory (CWE-552) · Sensitive Data Exposure - OSINT credential recovery (CWE-200) · Null Byte file extension bypass (CWE-434) · Security Misconfiguration - exposed admin route (CWE-425) · IDOR / Broken Access Control (CWE-639) · DOM XSS (CWE-79) · Stored XSS via HTTP header (CWE-79) · Reflected XSS (CWE-79)

---

## 1. Overview

OWASP Juice Shop is a deliberately vulnerable Node.js/Express web application designed to demonstrate the OWASP Top 10. This room works through guided tasks covering injection, broken authentication, sensitive data exposure, broken access control, and XSS. Unlike the Linux boot2root boxes in this write-up series, there is no shell or privilege escalation - the objective is to identify and exploit web vulnerabilities in a realistic single-page application, and to understand both the attack and the remediation.

Each section below is structured as a pentest finding: location, OWASP/CWE reference, steps to reproduce, why it works, and how to fix it.

> **Note:** TryHackMe assigns a fresh IP each time the machine is deployed. Commands and URLs below use `$IP` as a placeholder.

---

## 2. Reconnaissance

### JS source review - discovering the admin route

Before attacking anything, browsing the application's JavaScript bundle (loaded with the SPA) reveals the client-side routing configuration. Searching for `admin` in the source surfaces:

```
path: 'administration'
...
path: 'about'
```

This immediately leaks the existence of an admin panel at `/#/administration` - covered in Finding 7 below. Reading JS source is always worth doing before reaching for a scanner.

---

## 3. Findings

### Finding 1 - SQL Injection (Authentication Bypass)

- **Location:** `POST /rest/user/login` - email field
- **OWASP:** A03:2021 – Injection · CWE-89
- **Severity:** Critical

**Steps to reproduce**

1. Navigate to `http://$IP/#/login`.
2. Enter the following in the **Email** field (leave password as anything, e.g. `a`):
   ```
   ' OR 1=1 --
   ```
3. Click **Log in**.

**Result:** Authenticated as `admin@juice-sh.op` - the first account in the database - without knowing the password.

**Why it works:** The login query is built by concatenating user input directly into SQL:

```sql
SELECT * FROM Users WHERE email = '<input>' AND password = '<hash>'
```

The payload closes the email string with `'`, appends `OR 1=1` to make the condition always true, and comments out the rest of the query with `--`. The database returns the first matching row, which is the admin account.

**Remediation:** Use parameterised queries (prepared statements) exclusively. Never build SQL strings through string concatenation of user input. Apply an ORM if available; validate and sanitise email fields server-side.

---

### Finding 2 - Broken Authentication (Admin Password Brute-Force via Burp Intruder)

- **Location:** `POST /rest/user/login` - password field
- **OWASP:** A07:2021 – Identification and Authentication Failures · CWE-307
- **Severity:** High

**Steps to reproduce**

1. Log out and capture a login POST request to `/rest/user/login` in **Burp Proxy**.
2. Send the request to **Intruder**, set the password value as the payload position.
3. Load wordlist: `/usr/share/wordlists/SecLists/Passwords/Common-Credentials/best1050.txt`
4. Start the attack. Filter results by Status Code - failed attempts return `401 Unauthorized`, the correct password returns `200 OK`.
5. **Result:** Request 117 - payload `admin123` - returns `200 OK` with a response length of 1185 bytes.

Log in with `admin@juice-sh.op` / `admin123`.

**Why it works:** The login endpoint does not implement rate-limiting, account lockout, or CAPTCHA. An attacker can submit unlimited password attempts programmatically, reducing a 1000-entry wordlist to seconds.

**Remediation:** Implement account lockout or progressive delay after N failed attempts. Add rate-limiting at the API gateway level. Require strong passwords (rejecting `admin123` at registration). Consider MFA for admin accounts.

---

### Finding 3 - Broken Authentication (Insecure Password Reset - Jim)

- **Location:** `GET /rest/user/reset-password` - security question flow
- **OWASP:** A07:2021 – Identification and Authentication Failures · CWE-640
- **Severity:** High

**Steps to reproduce**

1. Navigate to `http://$IP/#/forgot-password` and enter `jim@juice-sh.op`.
2. The security question asks for Jim's **brother's middle name**.
3. OSINT: Jim's profile hints at Star Trek. A Wikipedia search for James T. Kirk reveals his brother is **George Samuel Kirk** - middle name `Samuel`.
4. Enter `Samuel` as the security question answer. The application accepts it and allows a password reset.

**Why it works:** The security question can be answered using publicly available OSINT - the character's Wikipedia page. Security questions based on findable facts provide no meaningful authentication barrier.

**Remediation:** Eliminate knowledge-based security questions. Use out-of-band password reset flows (email link with a time-limited signed token). If security questions must exist, never use questions answerable from public records.

---

### Finding 4 - Sensitive Data Exposure (Open FTP Directory)

- **Location:** `http://$IP/ftp/`
- **OWASP:** A02:2021 – Cryptographic Failures / Sensitive Data Exposure · CWE-552
- **Severity:** High

**Steps to reproduce**

1. Navigate directly to `http://$IP/ftp/`.
2. The directory listing is publicly accessible and contains:
   - `acquisitions.md` - internal business acquisition plans
   - `legal.md`
   - `announcement_encrypted.md`
   - `coupons_2013.md.bak`
   - `eastere.gg`
   - `encrypt.pyc`
   - `incident-support.kdbx`
   - `package.json.bak`
   - `suspicious_errors.yml`
3. Download `acquisitions.md` - it contains confidential business information.

**Why it works:** The FTP/static file directory has no authentication and no directory listing restriction, making internal documents directly accessible to any visitor.

**Remediation:** Disable directory listing on all web servers. Move sensitive documents behind authentication. Never serve internal files from a public web root. Audit accessible directories periodically.

---

### Finding 5 - Sensitive Data Exposure (OSINT Credential Recovery - MC SafeSearch)

- **Location:** Account `mc.safesearch@juice-sh.op`
- **OWASP:** A02:2021 – Sensitive Data Exposure · CWE-200
- **Severity:** Medium

**Steps to reproduce**

1. Search YouTube for "MC SafeSearch" - a video shows him rapping about his password.
2. He states his password is **"Mr. Noodles"** but says he replaced the vowels with zeros.
3. Derived password: `Mr. N00dles`
4. Log in as `mc.safesearch@juice-sh.op` / `Mr. N00dles`.

**Why it works:** The user publicly disclosed their password transformation rule. Even obfuscated passwords (leet-speak, vowel substitution) are trivially reversible once the rule is known.

**Remediation:** Never reuse or hint at passwords in any public content. Use a password manager to generate and store random, unique credentials per account.

---

### Finding 6 - Null Byte File Extension Bypass (Downloading a Restricted Backup File)

- **Location:** `http://$IP/ftp/package.json.bak`
- **OWASP:** A05:2021 – Security Misconfiguration · CWE-434
- **Severity:** Medium

**Steps to reproduce**

1. Attempt to download `http://$IP/ftp/package.json.bak` directly - returns `403: Only .md and .pdf files are allowed!`.
2. The server validates the file extension using a blocklist. Bypass with a **Poison Null Byte**:
   - The null byte `%00`, URL-encoded for a URL context, becomes `%2500` (percent-encoded percent).
3. Request the file as:
   ```
   http://$IP/ftp/package.json.bak%2500.md
   ```
4. The server sees the extension as `.md` (bypassing the check), then the underlying file system strips everything after the null byte and returns `package.json.bak`.

**Why it works:** A Poison Null Byte (`%00` / `%2500`) acts as a string terminator at the OS/file-system level. The application's extension check operates on the full string (`.md` passes), but the file system resolves up to the null byte and returns the actual `.bak` file.

**Remediation:** Validate file extensions using an allowlist, not a blocklist. Sanitise and reject null bytes in all URL/file path inputs. Serve files through a controller that enforces access rules independently of the filename extension.

---

### Finding 7 - Security Misconfiguration (Exposed Admin Route)

- **Location:** `http://$IP/#/administration`
- **OWASP:** A05:2021 – Security Misconfiguration · CWE-425
- **Severity:** High

**Steps to reproduce**

1. View the application's bundled JavaScript source in the browser.
2. Search for `admin` - the client-side router configuration reveals:
   ```javascript
   path: 'administration'
   ...
   path: 'about'
   ```
3. Navigate to `http://$IP/#/administration` while logged in as admin.

**Result:** Full admin control panel with user management, order management, and review management.

**Why it works:** The admin route is defined in the client-side JavaScript bundle, which is publicly downloadable. Security through obscurity - hiding a page by not linking to it - provides no real protection if the route is discoverable from the source.

**Remediation:** Enforce admin route access server-side. The API endpoints backing the admin panel must verify admin role on every request, regardless of the client-side URL. Never rely on client-side routing alone to protect sensitive functionality.

---

### Finding 8 - Insecure Direct Object Reference / IDOR (Accessing Another User's Basket)

- **Location:** `GET /rest/basket/{id}`
- **OWASP:** A01:2021 – Broken Access Control · CWE-639
- **Severity:** High

**Steps to reproduce**

1. Log in as any user and open your basket. Intercept the request in Burp - it calls:
   ```
   GET /rest/basket/1 HTTP/1.1
   ```
2. Change the basket ID from `1` to `2`:
   ```
   GET /rest/basket/2 HTTP/1.1
   ```
3. Forward the request.

**Result:** The response returns the basket of `admin@juice-sh.op` - UserID 2 - containing "Raspberry Juice (1000ml) × 2, Total: 9.98¤". Any authenticated user can read any other user's basket by incrementing the integer ID.

**Why it works:** The server returns basket data based on the ID in the URL without checking whether the requesting user owns that basket. There is no ownership verification - the object reference (integer ID) is both guessable and unprotected.

**Remediation:** Enforce server-side ownership checks on every object access: the session's user ID must match the resource's owner ID. Never trust client-supplied IDs to imply authorisation. Use non-sequential, unguessable identifiers (UUIDs) as a defence-in-depth measure - but not as the only control.

---

### Finding 9 - Broken Access Control (Deleting All 5-Star Reviews via Admin Panel)

- **Location:** `http://$IP/#/administration` - Customer Feedback section
- **OWASP:** A01:2021 – Broken Access Control · CWE-285
- **Severity:** Medium

**Steps to reproduce**

1. Log in as admin (via Finding 1 or Finding 2).
2. Navigate to `/#/administration`.
3. In the **Customer Feedback** section, click the bin icon next to each review showing 5 stars.

**Result:** All 5-star reviews are deleted. The admin panel exposes destructive data management operations with no additional confirmation.

**Why it works:** The admin panel is accessible once admin credentials are compromised (via SQLi or brute force), and it provides no further authorisation gates for destructive operations.

**Remediation:** Require re-authentication or a confirmation step for destructive admin actions. Audit all admin operations. The primary fix remains the access controls on the admin route itself (Finding 7).

---

### Finding 10 - DOM-Based XSS (Search Bar)

- **Location:** Search bar - reflected in the DOM
- **OWASP:** A03:2021 – Injection · CWE-79
- **Severity:** High

**Steps to reproduce**

1. Navigate to the Juice Shop home page.
2. Enter the following payload in the search bar:
   ```html
   <iframe src="javascript:alert('xss')">
   ```
3. Submit the search.

**Result:** A JavaScript alert box fires immediately with the text `xss`.

**Why it works:** The search bar's input is inserted into the DOM without sanitisation or encoding. The `javascript:` pseudo-protocol in an `<iframe src>` attribute is executed by the browser as soon as the element is rendered. This is **Cross-Frame Scripting (XFS)** - a common DOM XSS variant - and it is detectable in any web application that reflects user input into the HTML without output encoding.

**Remediation:** Sanitise all user input before rendering it in the DOM. Use a Content Security Policy (CSP) that blocks inline scripts and `javascript:` URIs. Libraries like DOMPurify can sanitise HTML before insertion. Never insert raw user input via `.innerHTML` or equivalent.

---

### Finding 11 - Stored XSS (via True-Client-IP HTTP Header)

- **Location:** `GET /rest/saveLoginIp` - `True-Client-IP` request header → Last Login IP page
- **OWASP:** A03:2021 – Injection · CWE-79
- **Severity:** High

**Steps to reproduce**

1. Ensure **Burp Intercept** is on.
2. Log out from the admin account - Burp catches the `GET /rest/saveLoginIp` request.
3. In the **Headers** tab, add a new header:
   ```
   True-Client-IP: <iframe src="javascript:alert('xss')">
   ```
4. Forward the request. The server stores this header value as the last login IP.
5. Log back in as admin and navigate to the **Last Login IP** page.

**Result:** The stored XSS payload fires - an alert pops with `xss` each time the Last Login IP page is loaded.

**Why it works:** The `True-Client-IP` header (similar to `X-Forwarded-For`) is intended to communicate a client's real IP through proxies. The application stores this header value in the database without sanitisation and renders it directly in the Last Login IP page without output encoding. An attacker who can send a crafted request can permanently plant a script that executes for any admin who views that page.

**Remediation:** Validate and sanitise all HTTP request headers before persisting them. Never trust client-controlled headers (X-Forwarded-For, True-Client-IP, etc.) for anything that will be rendered as HTML - they are trivially forgeable. Apply output encoding on all stored values at render time.

---

### Finding 12 - Reflected XSS (Order Tracking `id` Parameter)

- **Location:** `/#/track-result?id=` - order tracking URL parameter
- **OWASP:** A03:2021 – Injection · CWE-79
- **Severity:** High

**Steps to reproduce**

1. Place or locate an order. The tracking URL looks like:
   ```
   http://$IP/#/track-result?id=5267-f73dcd000abcc353
   ```
2. Replace the `id` value with the XSS payload:
   ```
   http://$IP/#/track-result?id=<iframe src="javascript:alert('xss')">
   ```
3. Submit the URL and refresh the page.

**Result:** Alert box fires with `xss`.

**Why it works:** The `id` parameter is reflected into the page without sanitisation. The server performs a lookup using the parameter value and returns it to the DOM unsanitised - the browser executes the embedded script. Unlike stored XSS, the malicious payload travels in the URL rather than the database, making it distributable via phishing links.

**Remediation:** Sanitise and encode all URL parameters before reflecting them in responses. Apply a strict CSP that blocks inline scripts. Validate the `id` parameter against the expected format (UUID/alphanumeric) and reject anything that doesn't match.

---

## 4. Score Board

Accessing `http://$IP/#/score-board` shows the full list of Juice Shop challenges across all OWASP categories. The room covers a guided subset - more advanced challenges (Bonus Payload, XXE, Cryptographic Issues, Insecure Deserialisation) are visible on the board as further practice.

---

## 5. OWASP Top 10 Coverage Summary

| Finding | OWASP Category | CWE |
|---|---|---|
| SQL Injection auth bypass | A03 – Injection | CWE-89 |
| Password brute-force (Burp Intruder) | A07 – Auth Failures | CWE-307 |
| Insecure password reset (Jim) | A07 – Auth Failures | CWE-640 |
| Open FTP directory | A02 – Sensitive Data Exposure | CWE-552 |
| OSINT credential (MC SafeSearch) | A02 – Sensitive Data Exposure | CWE-200 |
| Null byte file extension bypass | A05 – Security Misconfiguration | CWE-434 |
| Exposed admin route (JS source) | A05 – Security Misconfiguration | CWE-425 |
| IDOR - basket access | A01 – Broken Access Control | CWE-639 |
| DOM XSS (search bar) | A03 – Injection | CWE-79 |
| Stored XSS (True-Client-IP header) | A03 – Injection | CWE-79 |
| Reflected XSS (order tracking) | A03 – Injection | CWE-79 |

---

## 6. Lessons Learned

- XSS comes in three distinct classes - DOM, Stored, Reflected - and each requires a different delivery mechanism and carries different impact. Stored XSS is the most severe because the payload persists and fires for every victim who loads the page.
- IDOR is found by watching for sequential integers or predictable IDs in API calls. The fix is always a server-side ownership check - guessable IDs are a symptom, not the root cause.
- Reading the JavaScript bundle before running any scanner found the admin route immediately. Source review takes two minutes and is often more productive than a ten-minute Gobuster scan on an SPA.
- Burp Intruder for password brute-force is the practical equivalent of what Hydra does for SSH - same concept, same wordlist, different protocol layer.
- Null byte bypass is a classic content-validation failure: the application and the file system disagree on where the string ends, and that disagreement is the vulnerability.

---

## 7. References

- Room: https://tryhackme.com/room/owaspjuiceshop
- OWASP Juice Shop (official): https://owasp.org/www-project-juice-shop/
- OWASP Top 10:2021 - https://owasp.org/Top10/
- CWE-89 (SQL Injection) - https://cwe.mitre.org/data/definitions/89.html
- CWE-79 (XSS) - https://cwe.mitre.org/data/definitions/79.html
- CWE-639 (IDOR) - https://cwe.mitre.org/data/definitions/639.html
- Burp Suite Intruder documentation - https://portswigger.net/burp/documentation/desktop/tools/intruder

---

*Lab conducted in an authorised, isolated training environment (TryHackMe). All activity was performed against systems I am explicitly permitted to test.*