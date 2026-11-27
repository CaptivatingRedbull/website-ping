"""Names that differ between the drop-in and the side-by-side build.

The drop-in build replaces Website Monitoring and keeps its names. The side-by-side
build (scripts/package.py --flavor side-by-side) rewrites the values below, so the
app can run next to Website Monitoring. The scheme name needs no constant: the code
only sees stanza names from splunkd, and the password realm, source, checkpoint
files and log stanza field follow them.
"""

from __future__ import annotations

APP_ID = "website_ping"
CONF_NAME = "website_monitoring"
"""The app's configuration file, without .conf."""
FLAVOR = "drop-in"

CONF_FILE = f"{CONF_NAME}.conf"
