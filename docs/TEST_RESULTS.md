# 测试与结果

环境：Windows 11 Pro (10.0.26200)，Windows 原生 Python 3.12.8，SQLite 3.45.3，
CPU only，无任何第三方包。

## 运行方式

```bat
python -m unittest discover -s tests -t . -v
```

## 实际结果（最终一轮）

```
Ran 65 tests in 90.0s

OK
```

连续多轮复跑（含全量 3 轮、竞态子集 2 轮）均 `OK`，未出现偶发失败。
早期一次 500 由测试同步点的文件共享冲突引起，已在 `rbac/hooks.py` 与
`tests/helpers.py` 对标记文件的创建/删除加重试后消除。

## 测试文件与覆盖点

### `tests/test_authz_unit.py`（16 项）

| 测试 | 断言要点 |
|---|---|
| `ClosureTests.test_self_loop_and_two_cycle_terminate` | 自环、二元环闭包精确 |
| `ClosureTests.test_long_cycle_terminates` | 5000 角色单环返回全部 5000 |
| `ClosureTests.test_naive_and_iterative_agree_on_random_graphs` | 300 个随机图，迭代闭包 == 朴素递归 |
| `ClosureTests.test_disconnected_roles_are_not_reachable` | 不相连角色不进闭包 |
| `DenyPriorityTests.test_deny_overrides_allow` | 同时命中 allow/deny → 拒绝 |
| `DenyPriorityTests.test_no_rule_defaults_to_deny` | 无规则 → 拒绝 |
| `DenyPriorityTests.test_condition_own_and_department` | own / same_department 精确匹配 |
| `DenyPriorityTests.test_rule_of_non_effective_role_is_ignored` | 非有效角色规则不生效 |
| `DenyPriorityTests.test_action_isolation` | write 规则不影响 read |
| `AuthorizerDatabaseTests.test_same_role_name_does_not_alias_across_tenants` | 同名 `reader` 在 alpha 允许、beta 拒绝 |
| `AuthorizerDatabaseTests.test_cache_is_keyed_by_tenant_and_version` | 改版本后旧缓存失效，且不影响另一租户 |
| `AuthorizerDatabaseTests.test_inheritance_cycle_via_database` | 数据库级环，闭包 2 个角色 |
| `AuthorizerDatabaseTests.test_cycle_depth_is_bounded_not_recursive` | 4000 角色环，返回 4000 角色、无 RecursionError |
| `CacheEvictionTests.*` | 有界缓存、过期计数 |

### `tests/test_http_api.py`（28 项）

认证与身份：
- 错误密码/未知用户 → 401；无令牌/伪造令牌 → 401；登出后令牌 → 401；
- `X-User` / `X-Department` / `X-Tenant` 头无法改变身份（跨租户 carol 访问 umbrella → 403）；
- 未知租户 → 404；非成员 → 403；请求体不能覆盖部门/owner。

读取与列表：
- 单条读取核对 `tenant/file_id/owner/department`；不存在 → 404；
- dave（reader+suspended）被 deny 覆盖，单条 403、列表 `total=0`；
- 循环继承 `alice→cycle-a⇄cycle-b→reader` 可读 A-103 且不挂起；
- 列表 `items` 已排序、`total == len(items)`、逐条可读；
- 第二页内容精确等于全量排序后的切片；
- carol（sales）列表只返回 `{A-102, A-104}`，`total=2`（而非 7），越界页仍报 `total=2`；
- 修改 carol 部门后列表集合随 `same_department` 变化。

写入：
- alice 可改自己的 A-100（数据库 department/version 均核对）；
- alice 改 bob 的 A-101 → 403，数据库 version 仍为 1；
- 把资源转给 bob → 目标资源不再 own → 403，owner 未变；
- 代码/断言覆盖 `same_department` 目标不可达时拒绝；
- owner 必须是租户内激活成员（ghost → 422；跨租户用户 → 422），数据库未变；
- 空对象/错误类型/空白部门 → 400，且行未变。

管理：
- 改角色后 `authz_version + 1`，alice 立即失读，列表变空；
- 非管理员调用管理接口 → 403，数据库角色未变；
- 改规则（加 deny）立即阻断/恢复；
- 通过 API 构造 `auditor ⇄ developer` 环后写权限按闭包生效；
- 新建角色 → 200，重名 → 409；`cache-stats` 仅管理员；100 个角色 → 400；
- 超 64 KiB 请求体 → 413，随后服务仍可正常响应。

### `tests/test_differential.py`（3 项）

- `test_random_cyclic_fixture_matches_reference`：5 个随机种子，每租户 14 文件 ×
  8 用户 × read 决策、完整列表 `total`、owner 映射、第 1/2 页（每页 3），
  全部与独立参考实现 `tests/reference.py` 完全一致；非成员单独断言 403。
  随机图含自环、任意长度环、deny/allow 全组合、跨租户同名角色。
- `test_department_change_shifts_listing_like_reference`：直接改库 + 递增版本后，
  8 用户的列表与参考实现再次完全一致。
- `test_deny_wins_and_cross_tenant_names_in_preset`：预设中 8 组
  (用户, 租户, 文件, 动作) 的允许/拒绝与参考一致；被拒写入核对 department/version 未变。

### `tests/test_races.py`（10 项，4 个独立服务进程共享一个数据库）

| 测试 | 构造方式 | 实际断言 |
|---|---|---|
| `test_revocation_is_visible_to_all_processes_after_return` | 4 进程各自预热缓存 → 管理 API 删除一个继承边 | 撤权返回后 4 个进程的单条读全 403、列表 `total=0`；数据库版本等于返回值；环的另一条边仍存在 |
| `test_blocked_write_revalidates_after_revocation` | 写请求停在 `after_authz` → 管理 API 撤掉 alice 的 ownwrite → 放行 | 写返回 403 且消息含 revalidation；数据库 department/version/owner/updated_at 全部未变 |
| `test_resource_attribute_change_interleaving_rejects_write` | bob 的写停在 `after_authz` → 管理员把 R-2 移到 finance → 放行 | 写 403；数据库保留管理员的 finance、owner=carol、version=2（只有管理员那次生效） |
| `test_reads_proceed_while_writer_holds_write_lock` | 写请求停在 `after_write_begin`（已持写者槽） | 4 个进程的读全部 200，耗时 <5s；放行后写 200、version=2 |
| `test_paused_reader_does_not_block_other_reads_or_writes` | 读请求停在 `after_read_authz` | 其余 3 进程读 200，另一进程写 200，耗时 <5s |
| `test_revocation_waits_for_inflight_write_then_applies` | 写停在 `after_write_begin`，同时发起撤权 | 撤权线程 0.5s 后仍在阻塞（未越过在途写）；放行后写 200、version=2；随后 bob 写 403 |
| `test_cache_warm_then_inheritance_edit` | 4 进程预热 → API 断继承边 → 直连 SQL 重连并递增版本 | 断边后 4 进程全 403；重连后 4 进程全 200 |
| `test_list_snapshot_is_internally_consistent` | 列表停在 `after_list_snapshot` → 撤权 → 放行 | 在途列表内部一致（排序、total==len）；撤权后新列表 `total=0` |
| `test_parallel_admin_revocations_are_serialized_by_sqlite_only` | 4 进程并发撤权 + 6 个并发读线程 | 4 次版本严格递增且互不相同；无读错误；数据库版本等于最后一次 |
| `test_revoked_session_is_rejected_immediately` | 一个进程登出，另一进程使用同一令牌 | 两进程均 401 |

### `tests/test_cli.py`（8 项）

`init` 建库/拒绝覆盖/`--force`；`dump` 一致快照与环边；`login` 正确/错误密码；
`state`；`create-role` 与重名冲突；`set-user-roles` / `set-role-parents` /
`set-role-rules` 分别使版本 +1/+2/+3 并核对 dump；未知角色、非管理员被拒；
`serve` 对缺失/未初始化数据库拒绝启动。

## 额外实测数据（非测试套件）

4 进程共享库，8 个并发读线程（每请求一次列表，page_size=10）+ 8 个写线程：

```
reads:  400 次 / 1.62s  ≈ 247 req/s，p50 ≈ 20.7ms，p95 ≈ 77.9ms
writes: 80 次 / 0.78s，0 错误
stress: 8 读线程 × 150 + 4 写线程 × 60 = 1440 次请求，全部 200
```

单请求内部耗时（进程内直接调用）：认证 ≈1.5ms、建立连接 ≈1.4ms、
列表 ≈1.5ms、单条 ≈1.4ms；HTTP 层与 Windows 本地回环的连接建立占主要部分。

## 与需求逐条对应

1. **多租户多角色 / 继承 / 环**：`roles(tenant_id,name)`、`role_parents`、迭代闭包；
   4000/5000 环测试；同角色名跨租户不串（单元 + 差异 + 预设测试）。
2. **身份不可由调用者声明**：仅 Bearer；`X-User` 等头测试；部门来自 `users`。
3. **deny 优先、默认拒绝**：`evaluate_rules` 纯函数 + 多组测试。
4. **列表逐条鉴权后排序分页、不泄露数量**：`list_files` 单读事务；
   `total` 为过滤后数量；差异测试逐页比对。
5. **写前/写目标双鉴权、同事务落库、不可提权**：`update_file` 两阶段；
   目标资源重鉴权；改 owner/department 的提权测试核对数据库。
6. **管理事务递增版本**：所有管理写入 `bump_version` 同事务；HTTP/CLI 测试核对版本。
7. **≥4 进程共享库**：竞态测试真实启动 4 个 `python -m rbac serve`。
8. **撤权返回后新请求不用旧缓存**：版本化缓存 + 4 进程预热撤权测试。
9. **先鉴权后被阻塞的写入必须重校验**：`after_authz` 同步点测试，数据库未变。
10. **不得一把全局锁、只读可并发**：两个「暂停一个请求、其他进程照常读写」测试；
    写者持写者槽时读全通。
11. **参考实现比对**：`tests/reference.py` 独立递归 DFS + 过滤→排序→分页。
12. **测试核对资源与数据库最终状态**：所有写测试均查 `files`/`versions`/规则表。

## 未完成项 / 已知限制

1. **跨翻页不保证同一快照**：每次列表请求独立取快照，因此并发修改时第 1 页与第 2 页
   可能来自不同快照。题目明确允许，但若上层需要稳定翻页需客户端带版本或游标。
2. **列表在内存中过滤全租户文件**：每请求读取该租户全部候选行后逐条鉴权（这是
   “不得先分页再过滤”的直接实现）。租户文件量很大时是 O(N) 内存与 O(N) 鉴权；
   可改为 SQL 侧半连接 + 规则展开，但会增加复杂度。目前预设规模与测试规模下无瓶颈。
3. **缓存为每进程独立**：版本号保证正确性，但撤权后各进程需重新计算一次闭包；
   没有主动推送失效。数千角色的大租户下首次请求会有一次闭包计算成本。
4. **不做密码策略、限流、审计日志持久化**：仅有登录失败即 401、会话表与访问日志开关；
   无账户锁定、无速率限制、无审计表。
5. **无 TLS**：仅监听 `127.0.0.1` 的明文 HTTP；生产需前置反向代理或加 TLS 包装。
6. **无角色/规则删除的独立接口**：通过 `PUT .../rules` 传空列表清空规则，
   通过 `PUT .../parents` 传空列表清空继承；没有单独的 DELETE 路由。
7. **同步点仅用于测试**：需显式 `RBAC_TEST_HOOKS=1` 且请求带 `X-Test-Sync`；
   默认关闭，但若在生产误开且调用者知道键名，可让请求挂起至超时（不影响鉴权正确性）。
8. **仅 Windows 原生验证**：代码是纯标准库、理论上跨平台，但只在
   Windows 11 + Python 3.12.8 + SQLite 3.45.3 上实测。
9. **写者串行是 SQLite 单写者特性**：高写并发下写请求会排队（读不受影响）。
   这不是应用级全局锁，但吞吐上限受单写者限制。
10. **未做数据库迁移框架**：`SCHEMA_VERSION=1`，`serve` 启动时校验版本，
    不匹配直接拒绝；没有增量迁移脚本。
