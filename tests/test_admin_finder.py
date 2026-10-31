"""Unit tests for the admin-finder classification logic (no network)."""

from osint_toolkit.pentest import admin_finder as af


def test_identify_wordpress_by_url():
    assert af._identify_panel("https://x/wp-login.php", "", {}) == "WordPress"


def test_identify_phpmyadmin_by_title():
    body = "<html><head><title>phpMyAdmin 5.2</title></head><body></body></html>"
    assert af._identify_panel("https://x/pma/", body, {}) == "phpMyAdmin"


def test_identify_grafana_by_header():
    assert af._identify_panel("https://x/", "", {"server": "Grafana"}) == "Grafana"


def test_identify_none_for_plain_page():
    assert af._identify_panel("https://x/about", "<h1>About us</h1>", {}) is None


def test_classify_login_form_with_csrf():
    body = (
        '<form method="post">'
        '<input type="text" name="user">'
        '<input type="password" name="pass">'
        '<input type="hidden" name="csrf_token" value="abc">'
        '</form>'
    )
    kind, note = af._classify(200, body, {})
    assert kind == "login-form"
    assert "CSRF" in note


def test_classify_http_auth_from_status():
    kind, note = af._classify(401, "", {"www-authenticate": 'Basic realm="x"'})
    assert kind == "http-auth"
    assert "Basic" in note


def test_classify_forbidden():
    kind, _ = af._classify(403, "", {})
    assert kind == "forbidden"


def test_classify_redirect():
    kind, _ = af._classify(302, "", {})
    assert kind == "redirect-login"


def test_severity_ranking():
    # login form is the most actionable for a tester
    assert af._severity("login-form", None) == "high"
    assert af._severity("http-auth", "cPanel") == "medium"
    assert af._severity("forbidden", None) == "low"
    assert af._severity("redirect-login", None) == "info"
    # a recognised management product reachable at 200 ranks high
    assert af._severity("reachable", "phpMyAdmin") == "high"


def test_title_extraction():
    assert af._title_of("<title>  Admin Login </title>") == "Admin Login"


def test_wordlist_has_no_duplicates():
    assert len(af.ADMIN_PATHS) == len(set(af.ADMIN_PATHS))
