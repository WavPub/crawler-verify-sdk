# WavPub Crawler Verify SDK — Python

> **中文** | **[English](#english)**

---

## 中文

支持 Python 3.9+，仅依赖主流 `cryptography` 库完成 Ed25519 签名校验。

### 安装

```bash
pip install "git+https://github.com/WavPub/crawler-verify-sdk.git#subdirectory=python"
```

### 快速开始

```python
from wavpub_crawler_verify import OfflineVerifier, OnlineVerifier

# 方式一（推荐）：0 RTT 本地离线验签
offline = OfflineVerifier()
res = offline.verify(
    token=request.headers.get("X-WavPub-Token", ""),
    host=request.headers.get("Host", ""),
    scope="rss",
)

# 方式二：在线 HTTP 回调验证
online = OnlineVerifier()
res = online.verify(
    token=request.headers.get("X-WavPub-Token", ""),
    host=request.headers.get("Host", ""),
    scope="rss",
    client_ip=client_ip,
)
```

框架示例见 [examples/fastapi_demo.py](examples/fastapi_demo.py) 与 [examples/flask_demo.py](examples/flask_demo.py)。

---

## English

Supports Python 3.9+ with only `cryptography` required for Ed25519 verification.

### Installation

```bash
pip install "git+https://github.com/WavPub/crawler-verify-sdk.git#subdirectory=python"
```

### Quick Start

```python
from wavpub_crawler_verify import OfflineVerifier, OnlineVerifier

# Mode 1 (Recommended): 0-RTT local offline verification
offline = OfflineVerifier()
res = offline.verify(
    token=request.headers.get("X-WavPub-Token", ""),
    host=request.headers.get("Host", ""),
    scope="rss",
)

# Mode 2: Online HTTP callback verification
online = OnlineVerifier()
res = online.verify(
    token=request.headers.get("X-WavPub-Token", ""),
    host=request.headers.get("Host", ""),
    scope="rss",
    client_ip=client_ip,
)
```

See framework integration examples in [examples/fastapi_demo.py](examples/fastapi_demo.py) and [examples/flask_demo.py](examples/flask_demo.py).
