import json
import os
import sys


SERVER_DIR = os.path.join(os.path.dirname(__file__), "..", "server")
sys.path.insert(0, SERVER_DIR)

from cape_integration import post_analysis_callback


class FakeResponse:
    status = 202

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False

    def read(self, size=-1):
        return b"ok"


def test_post_analysis_callback_delivers_json(monkeypatch):
    captured = {}

    def fake_urlopen(request, timeout):
        captured["url"] = request.full_url
        captured["timeout"] = timeout
        captured["method"] = request.get_method()
        captured["content_type"] = request.headers["Content-type"]
        captured["body"] = json.loads(request.data.decode("utf-8"))
        return FakeResponse()

    monkeypatch.setattr("urllib.request.urlopen", fake_urlopen)

    result = post_analysis_callback(
        "http://llm-device.local/analysis/results",
        "static_completed",
        "abc123",
        {"verdict": "suspicious"},
    )

    assert result["status"] == "delivered"
    assert result["status_code"] == 202
    assert captured["url"] == "http://llm-device.local/analysis/results"
    assert captured["method"] == "POST"
    assert captured["content_type"] == "application/json"
    assert captured["body"]["event"] == "static_completed"
    assert captured["body"]["sha256"] == "abc123"
    assert captured["body"]["data"] == {"verdict": "suspicious"}


def test_post_analysis_callback_rejects_non_http_url():
    result = post_analysis_callback(
        "file:///tmp/results.json",
        "dynamic_completed",
        "abc123",
        {"status": "completed"},
    )

    assert result["status"] == "failed"
    assert "http:// or https://" in result["error"]
