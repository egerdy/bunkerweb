# Fork 构建与测试

基于BunkerWeb 1.6.17固定运行时摘要，构建UI、Scheduler及带LKG适配的Worker。仅覆盖本Fork改动，不重新编译未变更的NGINX/ModSecurity。DNS Manager作为独立ZIP安装，不能只复制源码目录就当作原生插件发布完成。

## 输入与产物

`upstream-bases.lock.json`默认指向公开GHCR摘要，并记录配置摘要及rootfs diff IDs。Dockerfile与锁一致。`prepare-crane.py`校验固定0.22.1工具包及可执行文件；`prepare-aliyun-wheelhouse.py`按锁文件下载公开依赖并校验哈希。

源码、wheelhouse、镜像上下文、Docker认证目录、构建输出分别保存。真实Docker配置必须放在仓库外；镜像上下文只收录白名单文件，不包含数据库、密钥、`.env`或本地运维资料。

```sh
# 所有路径均为示例；替换为自己机器上仓库外的目录。
TASK_ROOT=/tmp/bunkerweb-build
python3 misc/fork/prepare-crane.py "$TASK_ROOT/tools"
python3 misc/fork/prepare-aliyun-wheelhouse.py "$TASK_ROOT/wheelhouse"
python3 misc/fork/prepare-image-context.py "$TASK_ROOT/context" \
  --wheelhouse "$TASK_ROOT/wheelhouse"
python3 "$TASK_ROOT/context/build-publish.py" "$TASK_ROOT/context" \
  --auth-directory /path/outside/checkout/docker-auth \
  --crane "$TASK_ROOT/tools/crane-v0.22.1" \
  --output "$TASK_ROOT/release" \
  --image-prefix registry.example.com/your-project \
  --tag 1.6.17-fork.1
```

构建要求Linux/amd64、Docker Buildx、Python3.9+及公开基础镜像/依赖的访问能力。认证目录自行通过容器注册表工具配置，本仓库不提供实际账号。

正式发布拒绝脏工作区、已存在标签，以及无法确定标签不存在的情况；候选需显式`--candidate`及包含`-snapshot-`的标签。记录源码提交、上下文哈希、基线内容和输出镜像digest。TLS默认开启；仅当目标确实需要HTTP时显式传`--insecure`，不更改Docker守护进程全局配置。

如使用私有镜像缓存，应在自己的忽略配置/构建目录中维护锁文件与Dockerfile，并保持两者引用一致；`mirror-upstream-bases.py --image-prefix ...`可镜像指定输入，随后核实配置摘要与diff IDs。不得覆盖已有标签。克隆本项目不会自动获得任何私有仓库访问权限。

## 插件与测试

```sh
python3 misc/fork/package-dnsmanager.py /tmp/bunkerweb-artifacts
# 先将按哈希锁定的依赖准备到misc/fork/wheelhouse（该目录已忽略）
python3 misc/fork/prepare-aliyun-wheelhouse.py misc/fork/wheelhouse
sh misc/fork/check-aliyun-compat.sh
sh misc/fork/check-dnsmanager-compat.sh
```

兼容测试容器只读、无真实云凭据。DNS Manager测试覆盖账号加密、权限、CSRF、修订、审计、提供商配置、记录筛选及模拟解析检查。`test_lkg_certificates.py`覆盖LKG证书恢复。实际签发、续期、集群配置分发、RAM Role、性能和业务调用须另行验收。

合成浏览器fixture为`tests/utils/serve_dnsmanager_fixture.py`，必须显式设置`DNSMANAGER_BROWSER_FIXTURE=yes`，并使用上述测试依赖。只绑定本地测试端口18711，设置`DNS_FIXTURE_URL=http://127.0.0.1:18711`运行`misc/fork/verify-dnsmanager-accounts-browser.cjs`；需安装Playwright及浏览器。远程合成fixture还需显式`DNS_FIXTURE_ALLOW_REMOTE=yes`，不能指向真实凭据库。

LKG故障演练工具只接受独立`bw-fork-lkg`实验项目。不要把演练脚本改指向业务环境。升级适配器、上游运行时或Certbot后，执行对应回归，再测试真实业务。

## 发布与回退

程序发布、测试环境验收、生产切换是独立步骤。部署引用实际输出digest，并保存旧digest、配置、一致性SQLite快照、独立加密密钥、证书和LKG。程序回退不会撤销云端DNS写入；结果UNKNOWN/PENDING时先对账，不能盲目重试。

环境专用发布脚本、真实域名、内部注册表和验收记录不属于本公开仓库。公开源代码中的构建/CI应使用参数、环境变量或secret引用；见[公开范围](OPEN_SOURCE.md)。
