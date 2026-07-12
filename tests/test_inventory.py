from apihunter.report.inventory import InventoryReport


def test_inventory_report_empty():
    report = InventoryReport()
    assert report.endpoints == []
    assert report.auth_methods == []
    assert report.technologies == []
    assert report.summary == {}


def test_inventory_report_populated():
    report = InventoryReport(
        endpoints=["/api/v1/users"],
        auth_methods=["Bearer"],
        technologies=["Python", "FastAPI"],
        summary={"total_endpoints": 1},
    )
    assert len(report.endpoints) == 1
    assert "Bearer" in report.auth_methods
    assert "Python" in report.technologies
    assert report.summary["total_endpoints"] == 1
