# 设计与正确性论证

## 0. 目标与非目标

目标：

1. 多租户、租户内角色、角色可继承、**允许循环**；
2. 有效角色 = 租户内继承图的**最小可达闭包**；deny 优先、默认拒绝；
3. 列表 = 同一快照内**逐条鉴权后**再排序分页，不泄露无权资源数量；
4. 写入时对**修改前**与**目标**资源都鉴权，并在同一事务内落库；
5. 管理操作递增租户权限版本；≥4 个服务进程共享数据库；
6. 撤权返回后，新请求不得继续使用旧缓存；先鉴权后被阻塞的写入若撤权先提交，
   必须重新鉴权并拒绝；不得用跨进程全局互斥锁串行化所有接口。

非目标：真实文件内容、注册、前端、外部 IdP、分布式数据库、跨页快照一致。

## 1. 数据模型

```
tenants(id, name)
tenant_meta(tenant_id PK, authz_version)           -- 每租户单调版本
users(id, username UNIQUE, department, password_hash, is_admin, is_active)
user_tenants(tenant_id, user_id)                    -- 租户成员资格（唯一事实来源）
roles(id, tenant_id, name, UNIQUE(tenant_id,name), UNIQUE(tenant_id,id))
role_parents(tenant_id, child_id, parent_id)        -- child 继承 parent
user_roles(tenant_id, user_id, role_id)             -- 直接角色
rules(id, tenant_id, role_id, effect, action, condition)
files(id, tenant_id, file_id, owner_user_id, department, version, ...)
sessions(token_hash PK, user_id, expires_at, revoked_at)
```

要点：

- 所有角色/规则表都带 `tenant_id`，且 `roles` 的唯一键是 `(tenant_id, name)`。
  跨租户可以重名；任何按 `id` 或 `name` 的查询都必须同时限定 `tenant_id`。
- `role_parents` 与 `user_roles` 的外键都指向 `(tenant_id, id)` 复合唯一键，
  因此**数据库层面**也不可能把 A 租户的角色挂到 B 租户的用户或继承边上。
- `files.owner_user_id` 通过复合外键 `(tenant_id, user_id)` 引用 `user_tenants`，
  所以文件的 owner 必须确实是该租户成员；`PATCH` 还会额外检查 owner 是否处于激活状态。
- 文件 `version` 每次成功修改 +1，用于核对「写了几次」。

## 2. 身份解析

请求只带 Bearer 令牌。服务端：

1. `sessions.token_hash = sha256(token)` 查会话（`revoked_at IS NULL`、未过期）；
2. `users.is_active = 1`；
3. 用户名、部门来自 `users`，租户成员资格来自 `user_tenants`。

URL/请求头/请求体中的用户、部门、租户都不是输入。测试
`test_caller_headers_cannot_declare_identity` 用 `X-User` / `X-Department` 覆盖尝试，
并用跨租户的 carol 证明无效果。

## 3. 有效角色闭包（循环安全）

定义：`Eff(u, t) = Reach(Direct(u, t))`，其中 `Direct` 是 `user_roles` 中该租户的
直接角色，`Reach` 沿 `role_parents`（child → parent）可达的节点集合。

实现（`authz.role_closure`）是显式栈 + `visited` 集合的迭代算法：

```
seen = set(direct)
stack = list(seen)
while stack:
    r = stack.pop()
    for p in edges[r]:
        if p not in seen:
            seen.add(p); stack.append(p)
```

性质：

- **正确**：标准可达性；每条边最多检查一次。
- **终止**：每个角色最多入栈一次，循环（自环、二元环、n 元环）不会重入。
- **非递归**：深度只受内存限制。测试用 4000 个角色构成的大环和 5000 个角色的链路，
  生产实现不会 `RecursionError`。
- **最小闭包**：只包含可达角色；不相连的角色不进入（测试
  `test_disconnected_roles_are_not_reachable`）。

规则只取 `role_id ∈ Eff(u,t)` 的行，因此「用户没被分配的角色」「别名但属于其它租户
的角色」都不会生效。

## 4. 决策函数（deny 优先，默认拒绝）

对动作 `a` 和资源 `r`：

```
matching = { rule ∈ rules(Eff) : rule.action = a ∧ cond(rule.condition, u, r) }
allow  = matching 中存在 effect = allow
deny   = matching 中存在 effect = deny
allowed = allow ∧ ¬deny
```

条件：

- `any` → 恒真
- `own` → `r.owner_user_id == u.id`
- `same_department` → `r.department == u.department`（部门取自数据库）

这是纯函数（`evaluate_rules`），不读数据库，也没有默认放行分支；没有任何匹配规则
就是拒绝。测试覆盖 allow、deny 覆盖 allow、无条件满足时拒绝、动作隔离、
规则属于非有效角色时不生效。

## 5. 版本化缓存与即时撤权

每租户 `authz_version` 是**唯一**的失效信号。任何会改变某租户授权结果的管理事务
（改用户直接角色、改建继承边、改规则、建角色）都在**同一个写事务**里：

```
UPDATE tenant_meta SET authz_version = authz_version + 1 WHERE tenant_id = ? RETURNING ...
```

请求路径（只读）：

1. 在一个 `BEGIN` 读事务中读取 `authz_version = v`；
2. 查缓存 `(tenant_id, user_id) → (v', closure, rules)`；
3. `v' == v` 才使用；否则重新计算并写入缓存；
4. 整个请求的后续鉴权都使用同一个 `v` 与同一份闭包/规则（快照一致）。

因此：

- **跨租户不串**：缓存键含 `tenant_id`，闭包查询与规则查询都带 `tenant_id` 过滤。
- **同名不混用**：角色按 id + tenant 解析，从不按全局名字解析。
- **撤权立即生效**：管理事务提交后，任何新请求读到更大的 `v`，旧缓存条目被判过期
  （`AuthzCache.get` 比较 `entry.version != version`），不会继续使用。
- **多进程一致**：`authz_version` 在共享数据库里；进程内缓存只是加速，不构成事实来源。
  测试在 4 个进程各自预热缓存后撤权，逐个进程断言拒绝。
- **只读路径不取写锁**：读事务在 WAL 下可并发；认证同样是读事务。

缓存的额外保护：条目上限 4096（防内存膨胀），统计只暴露计数（管理员），
不含任何角色名/决策。

「撤权操作返回后，新开始的请求不能继续使用旧权限」的形式化依据：撤权事务提交是
返回的前提；新请求在提交之后的读事务中必然读到新 `authz_version`（SQLite 读事务
在第一条语句时取快照，晚于提交），版本不匹配即丢弃缓存。

## 6. 列表：快照内逐条鉴权 → 排序 → 分页

`Service.list_files` 的单个读事务里依次：

1. 解析租户与成员资格（不在成员 → 403，避免枚举）；
2. 读 `authz_version`；
3. 读取该租户**全部**候选文件行（连 owner 用户名）；
4. 对每一行调用同一个 `decide(..., "read")`，只保留允许的行；
5. 对允许集合排序（`file_id` / `owner` / `department` + `file_id` 次序键）；
6. 最后按 `page`/`page_size` 切片；
7. `total` 取允许集合大小。

因此：

- 不能「先分页再过滤」——过滤发生在排序和切片之前；
- 不泄露无权数量——`total` 只统计允许行，越界页同样返回相同的 `total`；
- 同一请求内一致——版本、规则、候选行、owner 部门都在同一读事务快照中。

不为跨页保持同一快照：每次请求重新取快照，题目明确允许。

差异测试把生产结果与 `tests/reference.py` 逐条、逐页比对：后者用递归 DFS
和独立的 `filter → sort → slice` 流程，二者不共享代码。

## 7. 写入：双资源鉴权 + 同事务重校验

`Service.update_file` 分两阶段：

**阶段 1（读事务）**：读当前行、版本、闭包，对「修改前资源」鉴权 `write`；
解析目标 owner（必须是租户内激活成员）与目标部门，构造目标资源并再次鉴权 `write`。
任一失败返回 403/422，数据库不动。

（测试同步点 `after_authz` 可暂停在此，用于构造「鉴权后撤权」。）

**阶段 2（写事务，`BEGIN IMMEDIATE`）**：

1. 重新读用户、成员资格、`authz_version`、闭包；
2. 重新读当前文件行（可能已被别人改动）；
3. 重新解析 owner；
4. 对当前资源与目标资源**重新鉴权**；
5. 任一失败 → 抛 403 → 事务 `ROLLBACK`；
6. 成功 → `UPDATE ... version = version + 1` → 提交。

为什么这能防「先鉴权、后写入」竞态：

- 撤权（改角色/继承/规则）是写事务，必须获得 SQLite 的**唯一写者槽**；
- 阶段 2 也是 `BEGIN IMMEDIATE`，同样需要写者槽；
- 两者在 SQLite 层面互斥（这是存储引擎的写者串行化，不是应用全局锁，读者完全不受影响）；
- 若撤权先提交，阶段 2 的 `BEGIN IMMEDIATE` 在撤权之后开始，读到的
  `authz_version` 更新、闭包更新，重新鉴权必然按新状态判定；
- 若写入先提交，则撤权尚未生效，写入合法；撤权返回后的后续写请求会被拒绝。

因为「重新读取 + 重新鉴权 + UPDATE」都在同一个 `BEGIN IMMEDIATE` 事务内，
不存在两者之间的窗口。

「不能通过改 owner/department 提权」：目标资源也必须满足 `write`。
例如只有 `own` 写权限的人把资源转给别人，目标资源不再 `own`，拒绝；
只有 `same_department` 写权限的人把资源移出本部门，目标不再同部门，拒绝。
反向也一样：把无权写入的资源改成自己的，当前资源鉴权先失败。
测试 `test_cannot_launder_write_by_changing_owner/department` 核对数据库未变。

写事务失败时 `write_tx` 回滚并关闭连接；`Forbidden` 在回滚后抛出。

## 8. 并发模型与「不是一把大锁」

- **进程/线程**：`ThreadingHTTPServer`，每连接一线程；服务进程之间无共享内存。
- **写者**：`BEGIN IMMEDIATE` + `busy_timeout=30s` + 少量重试，最终由 SQLite 串行化。
  写事务只覆盖「重校验 + 单行 UPDATE」，毫秒级；登录的 PBKDF2 在写事务之外。
- **读者**：WAL 模式下读事务不阻塞写者，也不被写者阻塞；认证、单条读、列表都是
  读事务（`BEGIN` deferred）。
- **没有任何应用级跨进程锁**：不存在锁文件、命名互斥量或数据库中的全局锁行。
  管理写与文件写共享 SQLite 写者槽是存储层事实，与「所有接口套同一把锁」不同：
  只读请求从不触碰它。
- 证据（`tests/test_races.py`）：
  - `test_reads_proceed_while_writer_holds_write_lock`：一个写请求停在
    `after_write_begin`（已持写者槽），另外 4 个进程的读仍全部 200，耗时 <5s；
  - `test_paused_reader_does_not_block_other_reads_or_writes`：一个读请求停在
    `after_read_authz`，其它进程的读与写都正常完成；
  - `test_parallel_admin_revocations_are_serialized_by_sqlite_only`：4 个进程并发
    撤权，版本严格递增且读线程无错误。

## 9. 同步点（仅测试）

`rbac/hooks.py` 只在环境变量 `RBAC_TEST_HOOKS=1` 时启用。请求头
`X-Test-Sync: key[:point]` 让指定请求在命名点暂停，落下 `<key>.<point>.paused`
文件，直到测试写 `<key>.<point>.go` 才继续；超时返回 503。

同步点：

| 点 | 位置 |
|---|---|
| `after_read_authz` | 单条读完成鉴权之后、返回之前 |
| `after_list_snapshot` | 列表读事务取完版本与候选行之后 |
| `after_authz` | 写入阶段 1 完成（读事务已结束，写事务尚未开始） |
| `after_write_begin` | 写入阶段 2 已 `BEGIN IMMEDIATE`、尚未重校验 |

标记是普通文件，因此可协调多个独立进程。生产默认关闭；即使误开，也必须显式携带
测试头才生效，且不影响鉴权逻辑本身。

## 10. 边界与失败模式

| 场景 | 行为 |
|---|---|
| 未知租户 | 404 |
| 非成员访问租户 | 403（不区分资源存在性，避免枚举） |
| 成员访问不存在的文件 | 404 |
| 角色/owner 不在本租户 | 422 |
| 非管理员调用管理接口 | 403 |
| 角色重名 | 409 |
| 列表参数非法 / 页大小超限 | 400 |
| 请求体 >64 KiB | 413 并关闭连接 |
| 会话过期/撤销/用户停用 | 401 |
| 继承成环、自继承 | 允许，闭包安全 |
| 4000+ 角色环 | 允许，迭代闭包，无递归上限问题 |
| 管理事务并发 | SQLite 写者串行化，`authz_version` 单调 |
