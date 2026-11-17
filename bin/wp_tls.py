"""The SSL context of a check, built the same way on every Splunk version and
interpreter.

Every check passes its own context: splunk-launch.conf sets PYTHONHTTPSVERIFY=0,
which makes Python's implicit default context skip certificate checks.
"""

from __future__ import annotations

import os
import ssl
import threading
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Union

from logger import StanzaLogger

CA_BUNDLE_CANDIDATES: tuple[str, ...] = (
    "/etc/ssl/certs/ca-certificates.crt",  # Debian, Ubuntu
    "/etc/pki/tls/certs/ca-bundle.crt",  # RHEL family, the Splunk container images
    "/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem",  # RHEL family
    "/etc/ssl/ca-bundle.pem",  # SUSE
)
"""Operating system CA bundles, tried in this order after $SSL_CERT_FILE. Splunk's
Python is built with default CA paths that do not exist on the host."""

NO_CA_BUNDLE = "no CA bundle found, set ca_certs"

_PARTIAL_CHAIN: int = getattr(ssl, "VERIFY_X509_PARTIAL_CHAIN", 0)
"""Not defined before Python 3.10."""
_STRICTER_FLAGS = ssl.VERIFY_X509_STRICT | _PARTIAL_CHAIN
"""Set by create_default_context from Python 3.13 on. Cleared so that a chain is
judged the same on 3.9 and 3.13: no extra X.509 checks, and only a root
certificate (not an intermediate) in the bundle ends a chain."""


class TLSSetupError(Exception):
    """No SSL context can be built for these settings. The message is the event's
    error field."""


@dataclass(frozen=True)
class TLSOptions:
    """Everything a context depends on; one context is built per distinct value."""

    verify: bool
    ca_certs: str | None = None


def require_tls12(context: ssl.SSLContext, settable: bool | None = None) -> None:
    """Refuse TLS 1.0 and 1.1.

    With OpenSSL 1.0.2 (Splunk 9.4) the minimum version cannot be set and an
    assignment to it would be silently ignored, so the older protocols are
    switched off one by one there.
    """
    if settable is None:
        settable = hasattr(ssl.SSLContext, "minimum_version")
    if settable:
        context.minimum_version = ssl.TLSVersion.TLSv1_2
    else:
        context.options |= ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1


def find_ca_bundle(
    environ: Mapping[str, str] = os.environ,
    candidates: Sequence[str] = CA_BUNDLE_CANDIDATES,
) -> str | None:
    """The first readable file of $SSL_CERT_FILE and candidates, or None."""
    for path in (environ.get("SSL_CERT_FILE", "").strip(), *candidates):
        if path and os.path.isfile(path) and os.access(path, os.R_OK):
            return path
    return None


def verifying_context(cafile: str) -> ssl.SSLContext:
    """Certificate and host name checked against the CAs in cafile.

    Raises OSError if the file cannot be read and ssl.SSLError if it holds no
    usable certificate."""
    context = ssl.create_default_context(cafile=cafile)
    context.check_hostname = True
    context.verify_mode = ssl.CERT_REQUIRED
    context.verify_flags = ssl.VerifyFlags(context.verify_flags & ~_STRICTER_FLAGS)
    require_tls12(context)
    return context


def unverified_context() -> ssl.SSLContext:
    """Any certificate accepted, as Website Monitoring did."""
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    require_tls12(context)
    return context


def build_context(
    options: TLSOptions,
    log: StanzaLogger,
    environ: Mapping[str, str] = os.environ,
    candidates: Sequence[str] = CA_BUNDLE_CANDIDATES,
) -> ssl.SSLContext:
    """The context for options. Raises TLSSetupError when verification is on and
    no CA file can be loaded."""
    if not options.verify:
        return unverified_context()
    if options.ca_certs is not None:
        try:
            return verifying_context(options.ca_certs)
        except ssl.SSLError as exc:
            raise TLSSetupError(
                f"ca_certs has no usable certificate: {options.ca_certs} ({exc.reason or exc})"
            ) from None
        except OSError:
            raise TLSSetupError(f"ca_certs not readable: {options.ca_certs}") from None
    bundle = find_ca_bundle(environ, candidates)
    if bundle is None:
        raise TLSSetupError(NO_CA_BUNDLE)
    log.debug("verifying certificates with the CA bundle %s", bundle)
    try:
        return verifying_context(bundle)
    except OSError as exc:  # ssl.SSLError included
        raise TLSSetupError(f"CA bundle not usable: {bundle} ({exc})") from None


_Built = Union[ssl.SSLContext, TLSSetupError]


class ContextCache:
    """One context per TLSOptions for the life of the process.

    A CA bundle is read once, not for every check. A failure is kept as well and
    logged once, at its first use; every later check gets the same error.
    Contexts are only used to wrap sockets, which is safe across threads.
    """

    def __init__(
        self,
        environ: Mapping[str, str] = os.environ,
        candidates: Sequence[str] = CA_BUNDLE_CANDIDATES,
    ) -> None:
        self._environ: Mapping[str, str] = environ
        self._candidates: Sequence[str] = candidates
        self._lock: threading.Lock = threading.Lock()
        self._built: dict[TLSOptions, _Built] = {}

    def get(self, options: TLSOptions, log: StanzaLogger) -> ssl.SSLContext:
        """Raises TLSSetupError."""
        with self._lock:
            built = self._built.get(options)
            if built is None:
                try:
                    built = build_context(options, log, self._environ, self._candidates)
                except TLSSetupError as exc:
                    log.error("certificates cannot be verified: %s", exc)
                    built = exc
                self._built[options] = built
        if isinstance(built, TLSSetupError):
            raise TLSSetupError(str(built))
        return built


CONTEXTS = ContextCache()
"""The contexts of every check in this process."""


def describe_tls_error(exc: ssl.SSLError) -> str:
    """Short, stable text: the verification result for a certificate failure
    (certificate has expired, self-signed certificate, Hostname mismatch, ...),
    OpenSSL's reason code for other TLS failures."""
    if isinstance(exc, ssl.SSLCertVerificationError):
        detail = exc.verify_message or exc.reason or str(exc)
        return f"SSLCertVerificationError: {detail}"
    return f"SSLError: {exc.reason or exc}"
