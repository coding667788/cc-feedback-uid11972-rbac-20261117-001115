# 多租户文件元数据服务（循环角色继承 + 即时撤权）

仅使用 **Windows 原生 Python 3.12 标准库 + SQLite**（CPU）。没有 Docker、外部身份平台、
第三方权限引擎或任何 pip 依赖。

- 认证：预置用户 + Bearer 令牌（令牌以 SHA-256 存库，密码以 PBKDF2-SHA256 存库）
- 授权：租户内角色继承图（允许自环与任意长度环）、allow/deny、动作 `read`/`write`、
  条件 `any` / `own` / `same_department`，**命中任一 deny 即拒绝，无 allow 也拒绝**
- 数据：`tenant`、`file_id`、`owner`、`department`（+ 内部 `version`/时间戳），
  不涉及真实文件内容
- 并发：4 个以上独立服务进程共享一个 SQLite（WAL）数据库；**没有跨进程的应用级全局锁**
- 即时撤权：每个租户有单调递增的 `authz_version`，写入与管理事务同事务递增；
  进程内缓存按 `(tenant_id, user_id, version)` 校验，撤权返回后新请求立即失效
- 写入：先按“修改前 / 目标”资源各校验一次 `write`，随后在 SQLite 写事务里
  **重新读取并重新鉴权**，再落库，因此不会越过并发撤权

## 目录结构

```
rbac/
  __main__.py     python -m rbac 入口
  cli.py          init / serve / login / state / 管理命令 / dump
  db.py           模式、连接与 WAL、写事务、预置数据
  auth.py         登录、令牌校验、撤销
  authz.py        身份/角色闭包/deny 优先/版本化缓存
  service.py      读取、列表、修改、管理操作
  http.py         ThreadingHTTPServer + JSON 路由
  hooks.py        （仅测试）进程间文件同步点
  errors.py       错误到 HTTP 状态码的映射
tests/
  reference.py    独立的朴素参考实现（递归 DFS + 过滤→排序→分页）
  fixtures.py     随机带环夹具、竞态夹具
  test_authz_unit.py     闭包/deny/缓存/4000 环深度
  test_http_api.py       端到端 HTTP + 数据库最终状态
  test_differential.py   与参考实现逐条/分页比对
  test_races.py          4 进程 + 同步点的撤权/写入竞态
  test_cli.py            init/管理命令/dump
docs/
  DESIGN.md       设计与正确性论证
  WINDOWS.md      Windows 安装与运行说明
  TEST_RESULTS.md 实际测试结果与未完成项
```

## 快速开始（Windows）

```bat
cd 作答工作区_uid11972-identity-20261117-001115-r1

python -m rbac --db data\rbac.db init
python -m rbac --db data\rbac.db serve --host 127.0.0.1 --port 8080
```

另开窗口：

```bat
python -m rbac --db data\rbac.db login alice AlicePass1!
```

用返回的 token 请求：

```bat
curl -H "Authorization: Bearer <TOKEN>" ^
     "http://127.0.0.1:8080/v1/tenants/acme/files?page_size=5"
```

多个进程共享同一数据库（任选 4 个端口）：

```bat
start python -m rbac --db data\rbac.db serve --port 8081
start python -m rbac --db data\rbac.db serve --port 8082
start python -m rbac --db data\rbac.db serve --port 8083
start python -m rbac --db data\rbac.db serve --port 8084
```

## 预置账号与数据

| 用户  | 密码          | 租户 / 直接角色 |
|-------|---------------|-----------------|
| admin | `AdminPass1!` | acme: tenant-admin；globex: tenant-admin；umbrella: tenant-admin（全局管理员）|
| alice | `AlicePass1!` | acme: developer, cycle-a；globex: developer；umbrella: guest |
| bob   | `BobPass1!`   | acme: reader, reviewer；globex: auditor；umbrella: manager |
| carol | `CarolPass1!` | acme: sales-writer |
| dave  | `DavePass1!`  | acme: reader, suspended |

预置角色图里有真实环：`cycle-a ⇄ cycle-b`，且 `cycle-b → reader`。
`acme`/`globex`/`umbrella` 三租户都定义了同名角色 `reader`，但权限不同——
用来证明跨租户同名角色不会互相串用。

预置文件：acme 7 个（`A-100`…`A-106`），globex 3 个（`G-200`…`G-202`），
umbrella 2 个（`U-300`、`U-301`）。

## HTTP API

所有 `/v1` 接口（除登录和健康检查）都需要 `Authorization: Bearer <token>`。

| 方法与路径 | 说明 |
|---|---|
| `POST /v1/auth/login` | `{"username","password"}` → `{"token",...}` |
| `POST /v1/auth/logout` | 撤销当前令牌 |
| `GET /v1/me` | 已认证身份、部门、所属租户 |
| `GET /v1/tenants/{tenant}/files` | 列表：`page`、`page_size`(≤100)、`sort`(`file_id`/`owner`/`department`)、`order`(`asc`/`desc`) |
| `GET /v1/tenants/{tenant}/files/{file_id}` | 单条读取 |
| `PATCH /v1/tenants/{tenant}/files/{file_id}` | 修改 `owner` 和/或 `department` |
| `GET /v1/admin/tenants/{tenant}/state` | 管理员查看角色/继承/规则/分配/版本 |
| `POST /v1/admin/tenants/{tenant}/roles` | 新建角色 `{"name"}` |
| `PUT /v1/admin/tenants/{tenant}/roles/{role}/parents` | 替换父角色 `{"parents": [...]}`（允许成环） |
| `PUT /v1/admin/tenants/{tenant}/roles/{role}/rules` | 替换规则 `{"rules":[{effect,action,condition}]}` |
| `PUT /v1/admin/tenants/{tenant}/users/{username}/roles` | 替换用户在该租户的直接角色 |
| `GET /v1/healthz` | 健康检查（免认证） |
| `GET /v1/authz/cache-stats` | 管理员查看缓存计数（只有计数，无授权数据） |

列表响应含 `items`、`page`、`page_size`、`total`、`has_next`、`authz_version`。
`total` 是**逐条授权后的数量**，不会泄露无权资源的数量。

错误格式：`{"error": {"code": "...", "message": "...", "details": {...}}}`。
常见状态码：400 参数错误、401 未认证、403 无权、404 不存在、405 方法不允许、
409 冲突（如角色重名）、413 请求体过大、422 语义错误（如角色/owner 不合法）。

调用者**不能**在 URL、请求头或请求体中声明自己的用户名、部门或租户成员资格：
身份仅来自令牌，部门来自 `users.department`，成员资格来自 `user_tenants`。

## CLI

```bat
python -m rbac --db data\rbac.db init [--force]
python -m rbac --db data\rbac.db serve [--host 127.0.0.1] [--port 8080]
python -m rbac --db data\rbac.db login <username> <password>
python -m rbac --db data\rbac.db state <tenant> [--admin admin]
python -m rbac --db data\rbac.db create-role <tenant> <role> [--admin admin]
python -m rbac --db data\rbac.db set-user-roles <tenant> <username> [role ...]
python -m rbac --db data\rbac.db set-role-parents <tenant> <role> [parent ...]
python -m rbac --db data\rbac.db set-role-rules <tenant> <role> '<JSON>' 
python -m rbac --db data\rbac.db set-role-rules <tenant> <role> --rules-file rules.json
python -m rbac --db data\rbac.db dump
```

`dump` 在单个读事务中导出一致快照，便于与测试/参考实现核对。

## 测试

```bat
python -m unittest discover -s tests -t . -v
```

测试会启动真实的 `python -m rbac serve` 子进程（竞态测试同时启动 4 个），
通过文件同步点构造确定性交错。测试断言返回的资源、`total`、数据库最终行状态
（`files` 的 owner/department/version、`authz_version`、角色与规则表），
而不是只看 HTTP 状态码。详见 `docs/TEST_RESULTS.md`。

## 默认值与限制

- 列表 `page_size` 上限 100；单请求体上限 64 KiB；每用户直接角色 ≤64、
  每角色父角色 ≤64、每角色规则 ≤64（防止单请求无限膨胀）
- 缓存条目上限 4096（按任意旧条目淘汰）
- 令牌有效期 8 小时；`authz_version` 每次管理事务 +1
- 只保证**单次请求内**的快照一致；跨翻页不保证同一快照（题目允许）

## 已知未完成项

见 `docs/TEST_RESULTS.md` 末尾“未完成 / 已知限制”。
