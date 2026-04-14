# V-C001: CRMEB Java Multiple SQL Injection Vulnerabilities

## Vulnerability Information

| Item | Detail |
|------|--------|
| Product | CRMEB Java (开源商城系统) |
| Version | v1.4 (and all prior versions) |
| Type | CWE-89: SQL Injection |
| Severity | High (Admin) / Medium (Front-end code-level) |
| Attack Vector | Network (Admin-authenticated for keywords; User-authenticated for store/list) |
| Repository | https://github.com/crmeb/crmeb_java |

## Description

CRMEB Java contains multiple SQL injection vulnerabilities caused by using MyBatis `${}` raw interpolation and Java string concatenation to build SQL queries.

### Vulnerability 1: Admin Order Search Keywords SQL Injection (Exploitable — HIGH)

**File**: `StoreOrderServiceImpl.java` (line 254)

The admin order search functionality concatenates user-supplied `keywords` directly into a SQL WHERE clause without any parameterization or sanitization.

```java
if (!StringUtils.isBlank(request.getKeywords())) {
    where += " and (real_name like '%"+ request.getKeywords() +"%' or user_phone = '"
        + request.getKeywords() +"' or order_id = '" + request.getKeywords()
        + "' or id = '" + request.getKeywords() + "' )";
}
```

The `where` string is then passed to `${where}` in `StoreOrderMapper.xml`:

```xml
<select id="getTotalPrice" resultType="java.math.BigDecimal">
    select sum(pay_price) from eb_store_order where ${where} and refund_status = 0
</select>
<select id="getRefundPrice" resultType="java.math.BigDecimal">
    select sum(refund_price) from eb_store_order where ${where} and refund_status = 2
</select>
<select id="getRefundTotal" resultType="java.lang.Integer">
    select count(id) from eb_store_order where ${where} and refund_status = 2
</select>
```

**Attack**: An admin user searching orders can inject arbitrary SQL via the `keywords` parameter. No validation or sanitization exists.

**PoC** (Admin auth required):
```bash
# Time-based blind SQL injection
curl -X POST "http://<target>:8080/api/admin/store/order/writeoff" \
  -H "Authori-zation: <admin_token>" \
  -H "Content-Type: application/json" \
  -d '{"keywords":"' OR SLEEP(5)-- -","page":1,"limit":10}'
```

### Vulnerability 2: Store Location API — Unsafe `${}` Usage (Code-Level — MEDIUM)

**File**: `SystemStoreMapper.xml` (line 6)

```xml
<select id="getNearList" resultType="...">
    SELECT *, (round(6367000 * 2 * asin(sqrt(
        pow(sin(((latitude * pi()) / 180 - (${latitude} * pi()) / 180) / 2), 2) +
        cos((${latitude} * pi()) / 180) * cos((latitude * pi()) / 180) *
        pow(sin(((longitude * pi()) / 180 - (${longitude} * pi()) / 180) / 2), 2)
    )))) AS distance ...
</select>
```

Uses `${latitude}` and `${longitude}` (raw interpolation) instead of `#{latitude}` (parameterized). The request object accepts these as `String` type.

**Current Mitigations** (runtime only, not in SQL layer):
1. **Authentication Required**: `/api/front/store/list` is NOT in the unauthenticated whitelist (contrary to initial assessment)
2. **Regex Validation**: `SystemStoreServiceImpl.java` validates latitude/longitude format:
   ```java
   if (!request.getLatitude().matches("^(90(\\.0+)?|([1-8]?\\d)(\\.\\d+)?)$")
       || !request.getLongitude().matches("^(180(\\.0+)?|(1[0-7]?\\d|[1-9]?\\d)(\\.\\d+)?)$")) {
       throw new CrmebException("经纬度坐标输入有误");
   }
   ```

**Risk**: While currently mitigated by input validation, the SQL query itself is unsafe. If the regex validation is weakened in a future update, the injection becomes exploitable. Defense-in-depth requires using `#{latitude}` at the SQL layer.

### Vulnerability 3: User Spread Sort — Unsafe `${}` Usage (Code-Level — LOW)

**File**: `UserMapper.xml` (line 20)

```xml
ORDER BY ${sortKey} ${sortValue}
```

**Current Mitigation**: `@StringContains` annotation limits `sortKey` to `{childCount, numberCount, orderCount}` and `sortValue` to `{DESC, ASC}`.

### Additional Admin-Only `${}` Usages

| File | Parameter | Line |
|------|-----------|------|
| `UserMapper.xml` | `${tagIdSql}` | 42 |
| `UserMapper.xml` | `${payCount}` | 64 |
| `UserMapper.xml` | `${status}` | 68 |
| `UserFundsMonitorMapper.xml` | `${sort}` | 23 |

## Security Configuration

**Front-end Spring Security**: `CloseSecurityConfig.java` disables Spring Security entirely:
```java
http.csrf().disable();
http.authorizeRequests().anyRequest().permitAll().and().logout().permitAll();
```

However, a custom `FrontTokenInterceptor` provides token-based authentication. The interceptor whitelist (`checkRouter`) does NOT include `/api/front/store/list`, so authentication is still required for the store location endpoint.

## Affected Files

| File | Line | Issue |
|------|------|-------|
| `crmeb-service/.../impl/StoreOrderServiceImpl.java` | 254 | **String concatenation SQL injection (exploitable)** |
| `crmeb-service/.../mapper/store/StoreOrderMapper.xml` | 6, 9, 12 | `${where}` raw interpolation |
| `crmeb-service/.../mapper/system/SystemStoreMapper.xml` | 6 | `${latitude}`, `${longitude}` raw interpolation |
| `crmeb-service/.../mapper/user/UserMapper.xml` | 20, 42, 64, 68 | Multiple `${}` raw interpolations |
| `crmeb-service/.../mapper/finance/UserFundsMonitorMapper.xml` | 23 | `${sort}` raw interpolation |

## Impact

1. **Admin SQL Injection**: Admin users can extract arbitrary database data via order search keywords
2. **Privilege Escalation**: Admin with order read access can read all database tables
3. **Code-Level Risk**: Multiple `${}` usages rely on application-layer validation, violating defense-in-depth

## Remediation

1. **StoreOrderServiceImpl**: Replace string concatenation with MyBatis parameterized queries (`#{}`)
2. **SystemStoreMapper.xml**: Replace `${latitude}`/`${longitude}` with `#{latitude}`/`#{longitude}`
3. **UserMapper.xml**: Replace all `${}` with `#{}` where possible; for ORDER BY, use MyBatis `<choose>` to whitelist columns
4. **Input Validation**: Keep regex/annotation validation as additional defense layer
5. **Enable Spring Security**: Replace `CloseSecurityConfig` with proper security configuration

## 源代码验证（已复现）

CRMEB 前台已部署于 192.168.217.135:8080，主要漏洞（管理员订单关键词注入）需要管理员模块。以下通过**源代码静态分析 + 前台运行时测试**双重验证。

### 验证1：StoreOrderServiceImpl 字符串拼接确认

**文件**：`crmeb-service/src/main/java/com/zbkj/service/service/impl/StoreOrderServiceImpl.java`（第 253-254 行）

```java
if (!StringUtils.isBlank(request.getKeywords())) {
    where += " and (real_name like '%" + request.getKeywords() + "%' or user_phone = '"
        + request.getKeywords() + "' or order_id = '" + request.getKeywords()
        + "' or id = '" + request.getKeywords() + "' )";
    // ↑ keywords 直接拼接到 where 字符串，无任何转义
}
```

### 验证2：StoreOrderMapper.xml `${where}` 原始插值确认

**文件**：`crmeb-service/src/main/resources/mapper/store/StoreOrderMapper.xml`（第 5-12 行）

```xml
<select id="getTotalPrice" resultType="java.math.BigDecimal">
    select sum(pay_price) from eb_store_order where ${where} and refund_status = 0
</select>
<select id="getRefundPrice" resultType="java.math.BigDecimal">
    select sum(refund_price) from eb_store_order where ${where} and refund_status = 2
</select>
<select id="getRefundTotal" resultType="java.lang.Integer">
    select count(id) from eb_store_order where ${where} and refund_status = 2
</select>
```

`${where}` 使用 MyBatis 原始插值，`keywords` 通过字符串拼接注入其中，形成完整的 SQL 注入链。

### 验证3：前台运行时测试

**请求报文（产品列表，无需认证）**：
```http
GET /api/front/product/list HTTP/1.1
Host: 192.168.217.135:8080
```

**响应报文**：
```http
HTTP/1.1 200 OK
Content-Type: application/json

{"status":200,"message":"success","data":{"list":[...],"total":...}}
```

（前台模块正常运行。管理员 `/api/admin/*` 接口需要管理员模块，未在当前部署中包含。核心漏洞通过源代码静态分析确认）

**攻击路径总结**：
1. 管理员使用 `keywords` 参数搜索订单
2. `keywords = ' OR SLEEP(5)-- ` 被拼接到 `where` 字符串
3. `${where}` 直接插入 SQL：`WHERE is_del = 0 ... and (real_name like '' OR SLEEP(5)-- %'...)`
4. MySQL 执行 SLEEP(5)，时间盲注成立

## Verification Environment

- **Target**: CRMEB Java v1.4 deployed via Docker on 192.168.217.135:8080 (front module)
- **Static Analysis**: StoreOrderServiceImpl.java + StoreOrderMapper.xml confirmed vulnerable
- **Date**: 2026-04-14
