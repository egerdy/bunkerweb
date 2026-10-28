# DNS Manager

BunkerWeb外部UI插件，当前版本0.5.1。面向包含官方AliDNS Python SDK和`alidns`适配模块的本Fork镜像，不是上传到未经适配的官方镜像即可使用的独立发行包。使用标准插件上传/安装流程，不能只把源码复制到插件目录。

## 功能与边界

- 凭据账号、授权DNS区域、解析记录三级导航，列表/搜索/详情/新增/编辑/删除。
- 提供商由注册表定义字段。当前真实适配器仅Alibaba Cloud DNS；测试fixture供应商不进入发布包。
- AccessKey ID/Secret和可选STS，或显式ECS RAM Role认证；后者要求UI运行节点绑定角色、可用实例元数据，使用官方凭据SDK和IMDSv2，尚未完成真实ECS验收。
- 已有凭据未勾选设置新凭据时锁定认证方式，详情/编辑显示部分掩码；列表不展示AccessKey。取消更换会恢复原认证方式/掩码。完整凭据永不返回。
- 授权区域逐行添加/删除，至少1行、最多200行；只调整本地允许范围，不注册/购买或删除云端域名。
- 记录分页与云端主机/类型筛选、增改删/启停、TTL、线路、MX优先级和同名多值。筛选使用AliDNS ADVANCED模式，不只筛当前页。

## 持久化与权限

UI挂载独立目录`/var/lib/bunkerweb-dnsmanager`（0700，UID101可写），数据库`state.sqlite3`为0600。加密密钥单独只读挂载`/run/secrets/bunkerweb-dnsmanager/key`，UID101可读，不允许world权限或group写入。使用Fernet生成密钥，不使用UI会话密钥替代。

路径可通过`BUNKERWEB_DNSMANAGER_DATA_DIR`和`BUNKERWEB_DNSMANAGER_KEY_FILE`修改；不通过普通插件settings分发。状态与密钥不挂给Worker/Scheduler。备份使用SQLite backup API，并单独受控保存密钥；直接替换密钥会使已有密文无法解密。不要提交数据库、密钥、备份或真实账号截图。

账号凭据Fernet加密，管理员API仅按查询生成部分掩码；普通用户不返回掩码。有write权限且主库可写才能修改记录，管理凭据还要求管理员。写接口POST、CSRF、确认、revision和账号锁；授权区域限制需与云端RAM权限共同使用，不能替代云端权限。

`accounts`原六列保留，`account_providers`存提供商，`account_options`存非秘密参数。历史账号默认AliDNS和默认参数；省略options时保留已有值。删除账号保留审计，存在PENDING/UNKNOWN操作时拒绝删除。参数和账号版本/审计原子更新。

## 账号级配置与检测

|参数|默认值|作用|
|---|---|---|
|HTTP_TIMEOUT|10秒|SDK连接、读取各自超时，不是完整调用总时限|
|REGION_ID|cn-hangzhou|传入SDK|
|LINE|default|新增记录默认线路|
|TTL|600秒|新增记录默认TTL|
|POLLING_INTERVAL|2秒|浏览器解析检测轮询间隔|
|PROPAGATION_TIMEOUT|60秒|浏览器解析检测等待，可设120秒|

新增记录可以覆盖TTL/Line，修改账号默认值不会覆盖已有云端记录。连接测试读取首个授权区域一条记录，证明对应API连接/读取权限，不证明写权限。

解析检测先核对云端RecordId归属，再查询固定AliDNS公共递归DoH。支持非通配符A/AAAA/CNAME/TXT值比较，展示预期与观察结果；暂停记录不标成功，其他类型暂不提供比较按钮。关闭窗口停止后续轮询，已发请求可能自行结束。匹配只代表该公共递归解析器，不代表全球缓存或全部线路已生效。

Let's Encrypt证书签发是独立链路。本插件账号与参数不会自动同步Scheduler；即便共用云账号，轮换仍需分别维护。挑战TXT的TTL/传播参数由签发配置决定。

## 审计、未知结果及并发

写前持久化PENDING意图，成功SUCCEEDED、明确拒绝REJECTED、传输错误等可能为UNKNOWN。未知结果需按云端读回、请求ID和审计人工核查，不自动重放。同账号写锁与指纹校验可阻止本系统常见冲突，但云端没有原子compare-and-swap，不能保证与其他云端写入者之间绝无竞争。

回退代码不撤销云端DNS写入。恢复旧记录需独立核对并考虑TTL。避免把HTTP成功、插件安装、模拟测试等同于真实签发/续期或生产业务验收。

## 构建与测试

`python3 misc/fork/package-dnsmanager.py /tmp/bunkerweb-artifacts`生成确定性ZIP，仅收录plugin.json和ui白名单文件。依赖与兼容测试见[构建说明](../../fork/README.md)。后端覆盖加密、权限、CSRF、修订、审计、参数和筛选；浏览器fixture使用合成账号与模拟云端，不能指向真实账号库。
