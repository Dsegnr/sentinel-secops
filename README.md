# Sentinel · 安全研判与防御工作台

面向个人与小团队的本地安全研判工具原型，提供命令行和 Web 工作台，串联公开情报查询、证据报告、主机基线检查、发现管理与告警。项目仍在持续完善，当前作为个人工程实践归档。

## 已实现的模块

- 域名与 URL 研判：DNS、邮件认证记录、证书与响应头检查，重定向和仿冒特征分析。
- IP、邮件与公开账号线索分析：聚合公开数据源，区分“存在”“未发现”“无法判定”；同名线索不作为身份归属结论。
- 凭据泄露自查：使用 k-anonymity 查询方式，不向服务端发送原始密码。
- 本地案件、发现与资产管理：结构化报告、SHA-256 证据清单、检索、归档及导出。
- Windows 主机基线与防御：只读体检、基线差异、封堵清单和可审阅的加固脚本；加固脚本由用户另行执行。
- 可选大模型研判：基于已获取的报告生成解释与防御建议，API 与通知参数由使用者自行配置。

## 技术栈

Python · FastAPI · Jinja2 · requests · Rich · YAML · PowerShell · pytest

## 安装与运行

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -e ".[web,dev]"
Copy-Item config/config.example.yaml config/config.yaml
.\.venv\Scripts\sentinel.exe --help
.\.venv\Scripts\sentinel-web.exe --host 127.0.0.1 --port 8787
```

Linux/macOS 可使用相应虚拟环境命令运行 CLI 与 Web 服务；Windows 基线检查使用 PowerShell。

```bash
sentinel domain example.com
sentinel ip 8.8.8.8
python -m pytest tests -q
```

## 公开范围

本仓库只有程序源码、通用平台定义、示例配置和代码测试，不包含个人知识库、文章档案、工具学习资料、案件、资产、基线快照、实际配置、API 密钥或内部审计文档。知识库和工具目录的本地接入代码保留，公开版本不附带其内容；依赖个人工具知识库的原测试没有纳入公开测试集。

数据源可用性、调用额度与返回内容会变化。已有代码测试不等于所有外部服务当前均可用，也不等于生产环境安全审计。使用范围为自身防御、授权资产核查和合法取证。

## 来源

公开平台定义参考 Sherlock 与 Maigret 的公开规则，保留了来源说明和上游 MIT 许可证，见 [第三方说明](NOTICE.md)。本仓库从原项目白名单导出，使用独立 Git 历史，不包含原工作区的知识库历史。
