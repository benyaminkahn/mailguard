"""Test configuration.

The backend refuses to start without MAILGUARD_API_KEY, so provide a
test-only key before any test module imports backend.main.
"""

import os

os.environ.setdefault("MAILGUARD_API_KEY", "test-only-key-not-a-secret")
