"""Keep test runs out of the real Attack Lab scoreboard."""

import os
import tempfile

os.environ.setdefault("LAB_STATS_PATH", os.path.join(tempfile.mkdtemp(prefix="ladon-test-"), "lab_stats.json"))
