"""Flask 接入示例（before_request 钩子免风控放行）。"""

from flask import Flask, g, request
from wavpub_crawler_verify import HEADER_TOKEN, OfflineVerifier

app = Flask(__name__)
verifier = OfflineVerifier()


@app.before_request
def check_wavpub_crawler():
    tok = request.headers.get(HEADER_TOKEN, "")
    if tok:
        g.wavpub_verify = verifier.verify(token=tok, host=request.host, scope="rss")
    else:
        g.wavpub_verify = None


@app.get("/feed.xml")
def feed():
    res = getattr(g, "wavpub_verify", None)
    if res and res.valid:
        return {"verified": True, "host": res.host, "scope": res.scope}
    return {"verified": False}
