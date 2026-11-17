from __future__ import annotations

import pytest
from wp_url import HostNameError, ascii_host, prepare_url, redirect_url

T = "http://target:8080"


@pytest.mark.parametrize(
    ("url", "expected"),
    [
        # International host names (fixtures idn-host and the request Host header).
        (
            "http://münchen.test:8080/done/idn-host",
            "http://xn--mnchen-3ya.test:8080/done/idn-host",
        ),
        ("http://MÜNCHEN.Test/", "http://xn--mnchen-3ya.test/"),
        ("https://bücher.example.", "https://xn--bcher-kva.example./"),
        ("http://xn--strae-oqa.test/", "http://xn--strae-oqa.test/"),
        # An ASCII host is sent as written.
        ("http://Target:8080/x", "http://Target:8080/x"),
        ("http://[::1]:8080/a b", "http://[::1]:8080/a%20b"),
        # Paths and queries (fixtures path-unicode and path-space).
        (
            f"{T}/path/path-unicode/Müller?q=München",
            f"{T}/path/path-unicode/M%C3%BCller?q=M%C3%BCnchen",
        ),
        (f"{T}/path/path-space/a b", f"{T}/path/path-space/a%20b"),
        # Existing escapes are kept; escapes of unreserved characters are decoded.
        (f"{T}/a%20b%2F%C3%BC", f"{T}/a%20b%2F%C3%BC"),
        (f"{T}/%41%7e%2d", f"{T}/A~-"),
        (f"{T}/100%", f"{T}/100%"),
        # A malformed escape: "%" itself is encoded.
        (f"{T}/100%zz/a b", f"{T}/100%25zz/a%20b"),
        # Reserved characters stay, others are encoded.
        (f"{T}/a;b=c,d?x=1&y=$z", f"{T}/a;b=c,d?x=1&y=$z"),
        (f'{T}/a|b"<>^`{{}}\\', f"{T}/a%7Cb%22%3C%3E%5E%60%7B%7D%5C"),
        # Empty path, fragment.
        ("http://example.com", "http://example.com/"),
        ("http://example.com?x=1", "http://example.com/?x=1"),
        (f"{T}/a#frag ment", f"{T}/a"),
    ],
)
def test_prepare_url(url: str, expected: str) -> None:
    assert prepare_url(url) == expected


@pytest.mark.parametrize(
    "host",
    [
        "straße.test",
        "ς.test",
        "a\u200db.test",
        "a\u200cb.test",
        "ｍünchen.test",
        "münchen。test",
    ],
)
def test_host_with_version_dependent_form_is_refused(host: str) -> None:
    with pytest.raises(HostNameError) as info:
        _ = prepare_url(f"http://{host}:8080/")
    message = str(info.value)
    assert repr(host) in message
    assert "xn--" in message


def test_invalid_international_host_is_refused() -> None:
    with pytest.raises(HostNameError, match="not a valid international host name"):
        _ = ascii_host("ü" * 64 + ".test")


def test_ascii_host_is_unchanged() -> None:
    assert ascii_host("Example.COM") == "Example.COM"


@pytest.mark.parametrize(
    ("location", "expected"),
    [
        # UTF-8 bytes as http.client hands them over (decoded as Latin-1).
        ("/M\xc3\xbcller?q=a b", f"{T}/M%C3%BCller?q=a%20b"),
        # Not valid UTF-8: the Latin-1 text is encoded as UTF-8.
        ("/M\xfcller", f"{T}/M%C3%BCller"),
        ("http://m\xc3\xbcnchen.test/x", "http://xn--mnchen-3ya.test/x"),
        ("//other.test/x", "http://other.test/x"),
        ("next#part", f"{T}/dir/next"),
        (" /spaced ", f"{T}/spaced"),
    ],
)
def test_redirect_url(location: str, expected: str) -> None:
    assert redirect_url(f"{T}/dir/page", location) == expected


def test_redirect_to_refused_host_raises() -> None:
    with pytest.raises(HostNameError):
        _ = redirect_url(f"{T}/", "http://stra\xc3\x9fe.test/")
