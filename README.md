# CVE_APPLY — 企业开源软件安全审计报告集

本仓库收录对企业级开源软件进行代码审计后发现的漏洞报告，用于后续 CVE 申请与披露。

## 报告索引

### 已发布

| 编号 | 产品 | 漏洞类型 | 严重度 |
|------|------|----------|--------|
| V-006 | （内部）SVG 存储型 XSS | XSS | 高 |
| V-009 | （内部）mLogin 验证码绕过 | 认证绕过 | 高 |
| V-R001 | RuoYi v4.8.3 | 公告模块存储型 XSS | 中 |
| V-C001 | CRMEB Java v1.4 | 未授权 SQL 注入 | 严重 |
| V-W001 | 悟空 CRM | JFinal 模板 SQL 注入 | 严重 |
| V-J010 | JeecgBoot v3.5.3 | SqlInjectionUtil 过滤器绕过 | 高 |

### 新增（2026-04-14）

| 编号 | 产品 | 漏洞类型 | 严重度 |
|------|------|----------|--------|
| V-Y001 | yshop / ZkMall | 硬编码后门 Token + 未授权支付 | 严重 |
| V-L001 | Lilishop | 硬编码 JWT 签名密钥 | 严重 |
| V-J011 | J2eeFast | Shiro 硬编码 RememberMe 密钥 RCE | 严重 |
| V-P001 | pig 微服务 | @Inner 内部鉴权 Header 绕过 | 严重 |
| V-M001 | MaxKey IAM | 多处 ${filters}/${orgIdsList} SQLi | 严重 |
| V-D001 | DataEase | SqlVariable transFilter SQL 注入 | 严重 |
| V-YU001 | yudao-cloud | BrokerageUser ORDER BY 注入 | 高 |
| V-G001 | Guns Roses | 未授权文件预览路径穿越 | 严重 |

## 报告结构

每个漏洞位于独立目录 `V-XXX_项目名_漏洞描述/`：

- `README.md` — 漏洞详情：信息摘要 / 原因分析 / PoC / 修复建议
- `*.png`（可选）— 验证截图 / 响应包 / 堆栈信息
- `*.py|*.sh`（可选）— PoC 脚本


## 免责声明

本仓库内容仅用于安全研究与负责任披露，不得用于未授权的攻击活动。
