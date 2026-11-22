"""Shared gating for tests that exercise the private frozen model package."""

import os
import unittest


requires_local_model = unittest.skipIf(
    os.environ.get("SENTINELAI_CI_SYNTHETIC_ONLY") == "1",
    "requires the locally frozen Level 1 model package",
)
