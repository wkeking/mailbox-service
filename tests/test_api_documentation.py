"""Regression tests for the browser-based OpenAPI documentation."""

from __future__ import annotations

from mailbox_service.main import app, get_openapi_viewer


def test_public_documentation_only_exposes_external_service_routes() -> None:
    """Public docs must not disclose Admin paths, schemas, or authentication."""
    route_paths = {route.path for route in app.routes}
    openapi_schema = app.openapi()
    security_schemes = openapi_schema["components"]["securitySchemes"]
    acquire_operation = openapi_schema["paths"]["/api/v1/leases/acquire"]["post"]

    assert {
        "/docs",
        "/redoc",
        "/openapi.json",
        "/openapi-viewer",
    }.issubset(route_paths)
    assert not {"/admin/docs", "/admin/redoc", "/admin/openapi.json", "/admin/openapi-viewer"}.intersection(
        route_paths
    )
    assert all(not path.startswith("/api/v1/admin/") for path in openapi_schema["paths"])
    assert set(openapi_schema["paths"]) == {
        "/health",
        "/api/v1/leases/acquire",
        "/api/v1/leases/{lease_id}/release",
        "/api/v1/leases/{lease_id}/access-token",
        "/api/v1/leases/{lease_id}/refresh-token",
        "/api/v1/mailboxes/acquire",
        "/api/v1/mailboxes/reacquire",
        "/api/v1/leases/{lease_id}/verification-code",
    }
    assert security_schemes["ClientApiKey"] == {
        "type": "apiKey",
        "description": "外部调用方 API Key，请求时写入 X-API-Key Header。",
        "in": "header",
        "name": "X-API-Key",
    }
    assert "AdminToken" not in security_schemes
    assert "ClientKeyCreateRequest" not in openapi_schema["components"]["schemas"]
    assert "MailboxListResponse" not in openapi_schema["components"]["schemas"]
    assert {"ClientApiKey": []} in acquire_operation["security"]
def test_openapi_documentation_uses_chinese_descriptions() -> None:
    """Project-provided OpenAPI titles, groups, and endpoint descriptions should use Chinese."""
    openapi_schema = app.openapi()
    acquire_operation = openapi_schema["paths"]["/api/v1/leases/acquire"]["post"]
    lease_schema = openapi_schema["components"]["schemas"]["LeaseAcquireResponse"]
    acquire_request = openapi_schema["components"]["schemas"]["LeaseAcquireRequest"]
    access_token_response = openapi_schema["components"]["schemas"]["LeaseAccessTokenResponse"]

    assert openapi_schema["info"]["title"] == "邮箱服务外部 API"
    assert acquire_operation["summary"] == "领取邮箱租约"
    assert acquire_operation["tags"] == ["外部租约"]
    assert lease_schema["description"] == "外部邮箱租约及其 mode 对应凭证。"
    assert acquire_request["properties"]["mode"]["description"]
    assert "凭证模式" in acquire_request["properties"]["mode"]["description"]
    assert "租约 ID" in lease_schema["properties"]["lease_id"]["description"]
    assert "Access Token" in access_token_response["properties"]["access_token"]["description"]


def test_openapi_viewer_has_readable_fixed_colors() -> None:
    """The human-readable JSON viewer should not depend on browser JSON theme colors."""
    response = get_openapi_viewer()
    html = response.body.decode("utf-8")

    assert response.media_type == "text/html"
    assert "OpenAPI JSON 查看器" in html
    assert "background: #111827" in html
    assert "color: #e5e7eb" in html
    assert 'fetch("/openapi.json")' in html
