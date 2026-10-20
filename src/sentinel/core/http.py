"""统一 HTTP 客户端：UA、超时、重试、可选代理。所有出网请求都必须走这里。"""

from __future__ import annotations

import time

import requests

UA = "Sentinel-SecOps/0.1 (personal triage; public data only)"


def inject_os_truststore() -> None:
    """让 Python 走系统证书库。

    本机装有网络加速器（如 Steam++ 的本地反代）时，域名解析走 127.0.0.1、
    证书由其自签根签发；certifi 不认这些根，系统证书库认。
    """
    try:
        import truststore

        truststore.inject_into_ssl()
    except Exception:  # noqa: BLE001
        pass


class HttpClient:
    def __init__(self, timeout: float = 8.0, proxy: str | None = None, retries: int = 1):
        self.timeout = timeout
        self.retries = retries
        self.session = requests.Session()
        self.session.headers["User-Agent"] = UA
        if proxy:
            self.session.proxies = {"http": proxy, "https": proxy}

    def get(
        self,
        url: str,
        *,
        params: dict | None = None,
        headers: dict | None = None,
        allow_redirects: bool = True,
        stream: bool = False,
        timeout: float | None = None,
        retries: int | None = None,
    ) -> requests.Response:
        attempts = (self.retries if retries is None else retries) + 1
        last: Exception | None = None
        for attempt in range(attempts):
            try:
                return self.session.get(
                    url,
                    params=params,
                    headers=headers,
                    allow_redirects=allow_redirects,
                    stream=stream,
                    timeout=timeout or self.timeout,
                )
            except requests.RequestException as exc:
                last = exc
                if attempt < attempts - 1:
                    time.sleep(0.4 * (attempt + 1))
        assert last is not None
        raise last

    def post(
        self,
        url: str,
        *,
        json_data: dict | None = None,
        headers: dict | None = None,
        timeout: float | None = None,
        retries: int | None = None,
    ) -> requests.Response:
        attempts = (self.retries if retries is None else retries) + 1
        last: Exception | None = None
        for attempt in range(attempts):
            try:
                return self.session.post(
                    url,
                    json=json_data,
                    headers=headers,
                    timeout=timeout or self.timeout,
                )
            except requests.RequestException as exc:
                last = exc
                if attempt < attempts - 1:
                    time.sleep(0.4 * (attempt + 1))
        assert last is not None
        raise last
