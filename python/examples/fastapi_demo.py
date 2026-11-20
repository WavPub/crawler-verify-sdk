"""FastAPI 接入示例（0 RTT 离线验签 + 在线验签）。"""

from fastapi import FastAPI, Request
from wavpub_crawler_verify import HEADER_TOKEN, OfflineVerifier, OnlineVerifier

app = FastAPI()
offline = OfflineVerifier()
online = OnlineVerifier()


@app.get("/feed.xml")
def get_feed(request: Request):
    token = request.headers.get(HEADER_TOKEN, "")
    host = request.headers.get("host", "")

    # 方式一（推荐）：0 RTT 本地离线验签
    res = offline.verify(token=token, host=host, scope="rss")
    if res.valid:
        return {"verified": True, "mode": "offline", "host": res.host, "kid": res.kid}

    # 方式二：在线回调验证（演示）
    client_ip = request.client.host if request.client else ""
    online_res = online.verify(token=token, host=host, scope="rss", client_ip=client_ip)
    return {"verified": online_res.valid, "code": online_res.code, "degraded": online_res.degraded}
