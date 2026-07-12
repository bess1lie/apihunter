import time

import pytest
import requests

from apihunter.report.dashboard import start_dashboard


@pytest.mark.anyio
async def test_dashboard_starts_and_responds():
    server = start_dashboard(host="127.0.0.1", port=8081)
    time.sleep(1)  # Wait for server to start

    try:
        response = requests.get("http://127.0.0.1:8081")
        assert response.status_code == 200
        assert "<h1>APIHunter Dashboard</h1>" in response.text
    finally:
        server.stop()
