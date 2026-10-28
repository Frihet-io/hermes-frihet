"""Re-export of the root ``frihet`` plugin module for ``plugins/frihet-erp/frihet.py`` path parity."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

_ROOT_FRIHET = Path(__file__).resolve().parents[2] / "frihet.py"
if "frihet" in sys.modules:
    _mod = sys.modules["frihet"]
else:
    _spec = importlib.util.spec_from_file_location("frihet", _ROOT_FRIHET)
    assert _spec and _spec.loader
    _mod = importlib.util.module_from_spec(_spec)
    sys.modules["frihet"] = _mod
    _spec.loader.exec_module(_mod)

from frihet import *  # noqa: F401,F403,E402
from frihet import (  # noqa: F401,E402
    _compute_canonical_document_total,
    _format_provenanced_amount,
    _resolve_doc_amount,
    _resolve_document_amount,
    _sum_provenanced_amounts,
    brief,
    build_scenario1_complete_workspace_client,
    build_scenario2_partial_coverage_client,
    format_provenanced_amount,
    frihet_daily_brief,
    resolve_document_amount,
    sum_provenanced_amounts,
)
