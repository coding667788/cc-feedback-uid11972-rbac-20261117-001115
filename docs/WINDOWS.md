# Windows 运行说明

本文档只针对 **Windows 10/11 + 原生 Python 3.12**。不需要管理员权限（除非你把数据库放在
受保护目录），不需要 Docker、WSL、Visual Studio 构建工具或任何第三方包。

## 1. 确认 Python

```bat
python --version
```

应输出 `Python 3.12.x`。若 `python` 不是 3.12，可用 `py -3.12` 代替本文所有
`python` 命令：

```bat
py -3.12 --version
py -3.12 -m unittest discover -s tests -t . -v
```

本项目的 `RUNTIME.txt` 指定了随附运行时
`D:/CC_Codex_FeedBack/runtimes/cc005-csv-python312/python.exe`；如使用它，请把该目录
加入 `PATH`，或将 `python` 替换为该完整路径。

检查 SQLite 版本（需要 ≥ 3.35 才支持 `RETURNING`；Windows 版 3.12 自带 3.45+）：

```bat
python -c "import sqlite3; print(sqlite3.sqlite_version)"
```

## 2. 不解压/不安装

代码就是源码目录，直接在项目根目录（含 `rbac\` 与 `tests\` 的那一层）运行：

```bat
cd /d "D:\...\作答工作区_uid11972-identity-20261117-001115-r1"
python -m rbac --help
```

`.gitignore` 已忽略 `*.db`、`*.db-wal`、`*.db-shm`、`.runtime-tmp/`、`__pycache__/`。

## 3. 初始化数据库

```bat
python -m rbac --db data\rbac.db init
```

首次创建会打印租户、账号、文件数等摘要。重复执行会报“already exists”；
确需重建请加 `--force`（会删除旧的 db/wal/shm 文件）：

```bat
python -m rbac --db data\rbac.db init --force
```

数据库放在本地 NTFS 磁盘上。**不要把 SQLite 数据库放在 SMB/网络共享或 OneDrive
按需同步目录中**，WAL 模式与文件锁在部分网络文件系统上不可靠。

## 4. 启动服务

单进程：

```bat
python -m rbac --db data\rbac.db serve --host 127.0.0.1 --port 8080
```

看到 `listening on http://127.0.0.1:8080` 即启动完成。`Ctrl+C` 退出。

四个进程共享同一数据库（不同窗口，或一个 `start` 脚本）：

```bat
start "rbac-8081" python -m rbac --db data\rbac.db serve --port 8081
start "rbac-8082" python -m rbac --db data\rbac.db serve --port 8082
start "rbac-8083" python -m rbac --db data\rbac.db serve --port 8083
start "rbac-8084" python -m rbac --db data\rbac.db serve --port 8084
```

进程内缓存是各自独立的，通过 SQLite 里的 `authz_version` 协同失效；不需要也不建议
再加应用层共享锁。

## 5. 调用示例（cmd）

登录并手工复制 token：

```bat
python -m rbac --db data\rbac.db login alice AlicePass1!
```

然后：

```bat
set TOKEN=<粘贴 token>
curl -H "Authorization: Bearer %TOKEN%" "http://127.0.0.1:8080/v1/tenants/acme/files?page_size=3"
curl -H "Authorization: Bearer %TOKEN%" "http://127.0.0.1:8080/v1/tenants/acme/files/A-100"
curl -X PATCH -H "Authorization: Bearer %TOKEN%" -H "Content-Type: application/json" ^
     -d "{\"department\":\"sales\"}" ^
     "http://127.0.0.1:8080/v1/tenants/acme/files/A-100"
```

> Windows 10/11 自带 `curl.exe`。PowerShell 里请用 `curl.exe` 以免与
> `Invoke-WebRequest` 别名冲突，且 JSON 引号规则不同；cmd 示例最省事。

PowerShell 等价写法：

```powershell
$login = Invoke-RestMethod -Method Post -Uri http://127.0.0.1:8080/v1/auth/login `
         -ContentType application/json -Body '{"username":"alice","password":"AlicePass1!"}'
$h = @{ Authorization = "Bearer $($login.token)" }
Invoke-RestMethod -Uri http://127.0.0.1:8080/v1/tenants/acme/files -Headers $h
```

## 6. 管理操作

```bat
set ADMIN=<admin 的 token>
curl -X PUT -H "Authorization: Bearer %ADMIN%" -H "Content-Type: application/json" ^
     -d "{\"roles\":[\"reader\"]}" ^
     "http://127.0.0.1:8080/v1/admin/tenants/acme/users/alice/roles"
```

或用 CLI（直接操作数据库，走同样的服务层与版本递增逻辑）：

```bat
python -m rbac --db data\rbac.db set-user-roles acme alice reader
python -m rbac --db data\rbac.db set-role-parents acme developer reader
python -m rbac --db data\rbac.db set-role-rules acme reader "[{\"effect\":\"allow\",\"action\":\"read\",\"condition\":\"any\"}]"
python -m rbac --db data\rbac.db dump > snapshot.json
```

## 7. 运行测试

```bat
python -m unittest discover -s tests -t . -v
```

- 全部测试会临时创建数据库与 4 个服务子进程，结束后自动清理；
- 端口自动选择空闲端口，不会占用 8080；
- 同步点通过临时目录中的标记文件协调，仅在测试子进程设置
  `RBAC_TEST_HOOKS=1` 时启用；
- 若要单独跑竞态测试：

```bat
python -m unittest tests.test_races -v
```

Windows 防火墙如弹出提示，测试仅绑定 `127.0.0.1`，可直接允许或忽略（不监听外网）。

## 8. 常见问题

| 现象 | 处理 |
|---|---|
| `ModuleNotFoundError: No module named rbac` | 确认当前目录是项目根目录（`rbac\` 的父目录）再运行 |
| `database does not exist` | 先 `init`；`serve` 不会自动建库 |
| `database is locked` | 检查是否有异常退出的进程长期持有写事务；本项目写事务都很短，`busy_timeout` 为 30s |
| 端口被占用 | 换 `--port`，或用 `netstat -ano | findstr :8080` 查占用进程 |
| 中文乱码 | 控制台可先 `chcp 65001`；HTTP 响应均为 UTF-8 |
| 杀毒软件拖慢启动 | 将项目目录加入排除项（可选） |

## 9. 环境变量

| 变量 | 作用 |
|---|---|
| `RBAC_TEST_HOOKS=1` | 启用测试同步点（仅测试；生产不要设置） |
| `RBAC_TEST_HOOK_DIR` | 同步点标记目录 |
| `RBAC_TEST_HOOK_TIMEOUT` | 同步点等待秒数（默认 30） |
| `RBAC_ACCESS_LOG=1` | 把访问日志打到 stderr |
| `RBAC_DEBUG=1` | 打印未预期异常的 traceback 到 stderr |
