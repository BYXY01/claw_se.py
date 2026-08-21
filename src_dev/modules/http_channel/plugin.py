"""Neutral HTTP long-poll channel - the vendor-neutral real-channel example.

Real bidirectional messaging with stdlib only (urllib), no vendor SDK and no
extra dependency. The channel polls `{endpoint}/poll` (blocking long-poll for
inbound messages) and POSTs outbound text to `{endpoint}/send`.

Configuration: env var `CHANNEL_ENDPOINT` (read via api.env). When unset the
plugin registers nothing (the channel is simply not attached). Any HTTP relay /
webhook service implementing the two routes works - this is what makes the
example neutral instead of a vendor-specific IM binding.
"""
import json
import time
from urllib.request import Request, urlopen


class HttpChannelBackend:
    """A blocking HTTP long-poll backend (thread-bridged by the MsgIO bus)."""

    name = "http_channel"
    blocking = True

    def __init__(self, endpoint, api):
        self._endpoint = endpoint.rstrip("/")
        self._api = api

    def _poll_once(self):
        request = Request(self._endpoint + "/poll", method="GET")
        with urlopen(request, timeout=120) as response:
            data = json.loads(response.read().decode("utf-8"))
        return (data or {}).get("text")

    def receive(self):
        while True:
            try:
                text = self._poll_once()
            except Exception:  # noqa: BLE001 - a failed poll just retries
                text = None
            if text:
                return self._api.make_msg(text)
            time.sleep(0.5)

    def send(self, text: str) -> None:
        request = Request(
            self._endpoint + "/send",
            data=json.dumps({"text": text}).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urlopen(request, timeout=30):
            pass

    def close(self) -> None:
        pass


def PLUGIN(api) -> None:
    """Register the HTTP channel when an endpoint is configured."""
    endpoint = api.env("CHANNEL_ENDPOINT", "").strip()
    if not endpoint:
        return  # not configured: channel stays unattached
    api.register_channel(HttpChannelBackend(endpoint, api))
