# API Key Generator - Multi-Service Edition

[English Guide](./README_EN.md)

这是一个多服务注册器与聚合 API 上游工具，聚焦三件事：

- 注册 `Firecrawl` / `Exa` key
- 验证 key 是否真实可用，并把可用 key 提供给统一搜索层

## 当前状态

- `Firecrawl`：可用
- `Exa`：可用

## Quick Start

### 1. Clone

```bash
git clone https://github.com/skernelx/tavily-key-generator.git
cd tavily-key-generator
```

### 2. Configure

```bash
cp .env.example .env
```

编辑 `.env`，填好邮箱配置和可选上传配置。

如果已经配置了 `SERVER_URL` 和 `SERVER_ADMIN_PASSWORD`，注册成功后可以自动上传。

### 3. Run

macOS / Linux:

```bash
python3 run.py
```

或者：

```bash
./start_auto.sh
```

Windows:

```bat
start_auto.bat
```

启动后当前可选：

```text
1. Firecrawl
2. Exa
```
