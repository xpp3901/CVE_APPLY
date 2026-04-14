# V-C001: CRMEB Java 多处 SQL 注入漏洞

## 漏洞信息

| 项目 | 详情 |
|------|------|
| 产品 | CRMEB Java（开源商城系统）|
| 版本 | v1.4（及所有之前版本）|
| 类型 | CWE-89: SQL 注入 |
| 严重程度 | 高危（管理端）/ 中危（前端代码级）|
| 攻击向量 | 网络（管理端需认证keywords；用户端需认证store/list）|
| 代码仓库 | https://github.com/crmeb/crmeb_java |

## 漏洞描述

CRMEB Java 存在多处 SQL 注入漏洞，原因是使用 MyBatis `${}` 原始插值和 Java 字符串拼接来构建 SQL 查询。

### 漏洞1：管理端订单搜索 Keywords SQL 注入（可利用 — 高危）

**文件**: `StoreOrderServiceImpl.java`（第 254 行）

管理端订单搜索功能将用户提供的 `keywords` 直接拼接到 SQL WHERE 子句中，没有任何参数化或过滤。

```java
if (!StringUtils.isBlank(request.getKeywords())) {
    where += " and (real_name like '%"+ request.getKeywords() +"%' or user_phone = '"
        + request.getKeywords() +"' or order_id = '" + request.getKeywords()
        + "' or id = '" + request.getKeywords() + "' )";
}
```

然后将 `where` 字符串传递给 `StoreOrderMapper.xml` 中的 `${where}`：

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

**攻击**：管理端用户搜索订单时可通过 `keywords` 参数注入任意 SQL。无任何过滤。

**PoC**（需要管理端认证）:
```bash
# 时间盲注
curl -X POST "http://<target>:8080/api/admin/store/order/writeoff" \
  -H "Authorization: <admin_token>" \
  -H "Content-Type: application/json" \
  -d '{"keywords":"' OR SLEEP(5)-- -","page":1,"limit":10}'
```

### 漏洞2：门店位置 API — 不安全的 `${}` 使用（代码级 — 中危）

**文件**: `SystemStoreMapper.xml`（第 6 行）

```xml
<select id="getNearList" resultType="...">
    SELECT *, (round(6367000 * 2 * asin(sqrt(
        pow(sin(((latitude * pi()) / 180 - (${latitude} * pi()) / 180) / 2), 2) +
        cos((${latitude} * pi()) / 180) * cos((latitude * pi()) / 180) *
        pow(sin(((longitude * pi()) / 180 - (${longitude} * pi()) / 180) / 2), 2)
    )))) AS distance ...
</select>
```

使用 `${latitude}` 和 `${longitude}`（原始插值）而非 `#{latitude}`（参数化）。请求对象将这些作为 `String` 类型接收。

**当前缓解措施**（仅运行时，非 SQL 层）：
1. **需要认证**：`/api/front/store/list` 不在未认证白名单中
2. **正则校验**：`SystemStoreServiceImpl.java` 校验经纬度格式：
   ```java
   if (!request.getLatitude().matches("^(90(\\.0+)?|([1-8]?\\d)(\\.\\d+)?)$")
       || !request.getLongitude().matches("^(180(\\.0+)?|(1[0-7]?\\d|[1-9]?\\d)(\\.\\d+)?)$")) {
       throw new CrmebException("经纬度坐标输入有误");
   }
   ```

**风险**：虽然当前有输入校验保护，但 SQL 查询本身不安全。如果将来正则校验被削弱，注入即可利用。防御纵深需要在 SQL 层使用 `#{latitude}`。

### 漏洞3：用户推广排序 — 不安全的 `${}` 使用（代码级 — 低危）

**文件**: `UserMapper.xml`（第 20 行）

```xml
ORDER BY ${sortKey} ${sortValue}
```

**当前缓解措施**：`@StringContains` 注解将 `sortKey` 限制为 `{childCount, numberCount, orderCount}`，`sortValue` 限制为 `{DESC, ASC}`。

### 其他管理端 `${}` 使用

| 文件 | 参数 | 行号 |
|------|-----------|------|
| `UserMapper.xml` | `${tagIdSql}` | 42 |
| `UserMapper.xml` | `${payCount}` | 64 |
| `UserMapper.xml` | `${status}` | 68 |
| `UserFundsMonitorMapper.xml` | `${sort}` | 23 |

## 安全配置

**前端 Spring Security**：`CloseSecurityConfig.java` 完全禁用 Spring Security：
```java
http.csrf().disable();
http.authorizeRequests().anyRequest().permitAll().and().logout().permitAll();
```

然而，自定义 `FrontTokenInterceptor` 提供基于 token 的认证。拦截器白名单（`checkRouter`）**不包含** `/api/front/store/list`，因此门店位置端点仍需要认证。

## 受影响文件

| 文件 | 行号 | 问题 |
|------|------|-------|
| `crmeb-service/.../impl/StoreOrderServiceImpl.java` | 254 | **字符串拼接 SQL 注入（可利用）** |
| `crmeb-service/.../mapper/store/StoreOrderMapper.xml` | 6, 9, 12 | `${where}` 原始插值 |
| `crmeb-service/.../mapper/system/SystemStoreMapper.xml` | 6 | `${latitude}`、`${longitude}` 原始插值 |
| `crmeb-service/.../mapper/user/UserMapper.xml` | 20, 42, 64, 68 | 多处 `${}` 原始插值 |
| `crmeb-service/.../mapper/finance/UserFundsMonitorMapper.xml` | 23 | `${sort}` 原始插值 |

## 影响

1. **管理端 SQL 注入**：管理端用户可通过订单搜索关键字提取任意数据库数据
2. **权限提升**：有订单读取权限的管理端可读取所有数据库表
3. **代码级风险**：多处 `${}` 使用依赖应用层校验，违反防御纵深原则

## 修复建议

1. **StoreOrderServiceImpl**：将字符串拼接替换为 MyBatis 参数化查询（`#{}`）
2. **SystemStoreMapper.xml**：将 `${latitude}`/`${longitude}` 替换为 `#{latitude}`/`#{longitude}`
3. **UserMapper.xml**：将所有 `${}` 替换为 `#{}`；对于 ORDER BY，使用 MyBatis `<choose>` 白名单列
4. **输入校验**：保留正则/注解校验作为额外防御层
5. **启用 Spring Security**：用 proper security configuration 替换 `CloseSecurityConfig`

## 运行时验证

- **目标**：CRMEB Java v1.4 通过 Docker 部署在 192.168.217.135:8080
- **已确认**：应用启动并响应 API 端点
- **商品列表**（`/api/front/product/list`）：无需认证返回数据（符合预期）
- **门店列表**（`/api/front/store/list`）：无 token 返回 401（需要认证）
- **日期**：2026-04-13