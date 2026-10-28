# 开源提交范围与维护规则

判断标准不是“业务代码 / 非业务代码”，而是是否有权公开、是否包含真实敏感信息，以及是否属于可复用的项目资产。业务代码本身也可能是专有代码；CI、测试、文档、依赖锁和构建工具本身可以公开。

| 可以提交                                    | 应留在私有运维仓库、仓库外或忽略目录                                 |
| ------------------------------------------- | -------------------------------------------------------------------- |
| 有权发布的源码、单元测试、合成数据          | 客户/员工数据、业务数据库、真实请求和账务日志                        |
| README、架构说明、API文档、贡献指南         | 内部拓扑、资产清单、机器IP、真实业务域名及生产验收报告               |
| 通用Dockerfile、依赖锁、构建与发布脚本      | 包含实际Harbor/Jenkins地址和固定部署目标的专用版本                   |
| 使用secret引用的通用CI工作流                | AccessKey、Secret、STS Token、密码、私钥、Docker登录文件、kubeconfig |
| 占位符配置、假域名example.com、临时合成测试 | .env、SQLite及WAL、证书私钥、加密库及其解密密钥、备份包              |
| 通用离线校验工具                            | IDE状态、缓存、venv、wheelhouse、构建产物、浏览器真实账号截图        |

非公开地址不是密码，但公开内部拓扑也没有必要。将CI/发布所需地址和参数注入执行环境，不在公开脚本中硬编码；凭据使用仓库/环境secrets或外部秘密文件。禁止把本地`.git-credentials`和Docker认证配置复制到上下文或CI产物。

## 本Fork的整理方式

保留上游历史及许可，`master`作为未修改的1.6.17基线。维护分支`feat/aliyun-dns`上的自研提交按主题组织，不把部署状态、机器维护和云端操作混进业务实现提交。上游CI工作流保留原文件；它们的上游发布、集群及凭据配置不等于本Fork可直接运行的流水线。启用自有CI时先检查触发条件、目标仓库、权限和secret来源，不把内部runner暴露给不可信PR。

当前公开构建工具使用显式`--image-prefix`，默认TLS；实际私有注册表配置应由使用方提供。原环境专用工具仅保存到本地忽略目录，不属于可公开工作流。

## 同步上游

```sh
git fetch --no-tags upstream master
git switch -c maintenance/upstream-review feat/aliyun-dns
# 在维护分支审查上游差异，确定新基线后再合并/变基及更新运行时锁。
```

不能只同步源码而忽略固定镜像摘要。原生AliDNS/Certbot提供商、DNS Manager表结构与权限、LKG配置和证书恢复分别回归。新版本标签使用Fork后缀；不要将上游全部历史标签镜像到本Fork作为自己的发行版。

## 提交前与历史风险

审查`git diff --cached`，按路径暂存，运行`pre-commit run --all-files`，再运行对应测试。`.gitignore`只能阻止新的未跟踪文件，不能清除已经提交的历史，也不能代替secret扫描。

本次公开化整理只审查自研差异及可达主题提交，不构成上游所有历史的秘密审计。历史重写/删除分支不会保证GitHub缓存和其他克隆中的旧数据消失；如发现真实密钥泄漏，先撤销/轮换，再依GitHub说明处理。参考[GitHub敏感数据移除文档](https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/removing-sensitive-data-from-a-repository)。

保留[上游AGPL-3.0许可](../../LICENSE.md)、原作者与各第三方文件声明。不要把Fork标记为上游官方发行版，或声称从上游获得了本Fork未实现的能力。
