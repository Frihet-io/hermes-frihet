"""Golden reference tests for the Daily/Weekly Operational Business Brief.

Mirrors the canonical Monetary & Temporal Brief Contract from
``Frihet-io/frihet-mcp#257`` (``badefc4``) and ``daily-operational-brief.test.ts``:
1. Absent != 0: ``{}`` -> ``amount=None``, ``provenance="unavailable"``, ``unavailableCount=1``.
2. Multi-currency separation: ``100 EUR`` + ``100 USD`` -> ``amount=None``,
   ``currency="MIXED"``, ``provenance="mixed_currency_unconverted"``,
   ``totalsByCurrency={"EUR": ..., "USD": ...}``.
3. Canonical discounts & taxes: line ``discount``, document ``discountRate``,
   ``taxRate``, ``equivalenceSurchargeRate``, ``irpfRate`` over the discounted
   tax-exclusive base; fail closed on ``pricesIncludeTax=True``, ``compoundTaxes``,
   ``prepayment``.
4. Honest unpaid nominal wording: ``realOutstandingBalanceDeterminable=False``,
   ``unpaidNominalSemantics="nominal_unpaid_invoice_totals_without_partial_payments"``,
   and Markdown label ``Importe nominal de facturas no marcadas como pagadas
   (saldo pendiente real no determinable sin cobros parciales)``.
5. Explicit temporal scope: ``coverage.temporalScope =
   "unfiltered_operational_sample_as_of_date"`` plus ``currentMonthActivity``
   separating the operational sample as of ``asOfDate`` from the ``periodMonth`` subset.
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import frihet  # noqa: E402


def test_scenario1_complete_workspace_brief_contract():
    client = frihet.build_scenario1_complete_workspace_client()
    brief = frihet.frihet_daily_brief(
        client,
        as_of_date="2026-10-28",
        period_month="2026-10",
        sample_limit=20,
    )

    assert brief["asOfDate"] == "2026-10-28"
    assert brief["coverage"]["overallStatus"] == "complete"
    assert brief["coverage"]["temporalScope"] == "unfiltered_operational_sample_as_of_date"
    assert brief["coverage"]["truncationWarnings"] == []

    col = brief["collectionsAndDueDates"]
    assert col["overdueCount"] == 1
    assert col["overdueTotal"]["amount"] == 1210.0
    assert col["overdueTotal"]["provenance"] == "stored_field"

    assert col["upcomingDueWithin7DaysCount"] == 1
    assert col["upcomingDueWithin7DaysTotal"]["amount"] == 1210.0
    assert col["upcomingDueWithin7DaysTotal"]["provenance"] == "derived_from_items"

    # Draft invoice (3630 EUR) is strictly excluded from open issued receivables (1210 + 1210 = 2420 EUR)
    assert col["openIssuedCount"] == 2
    assert col["openIssuedNominalTotal"]["amount"] == 2420.0
    assert col["realOutstandingBalanceDeterminable"] is False
    assert (
        col["unpaidNominalSemantics"]
        == "nominal_unpaid_invoice_totals_without_partial_payments"
    )
    assert col["draftExcludedCount"] == 1
    assert col["draftExcludedTotal"]["amount"] == 3630.0

    # Temporal separation: F-2026-041 was issued 2026-09-15, so only F-2026-048 (2026-10-20)
    # is in currentMonthActivity (2026-10)
    cma = brief["currentMonthActivity"]
    assert cma["referenceMonth"] == "2026-10"
    assert cma["issuedInvoicesInMonthCount"] == 1
    assert cma["issuedInvoicesInMonthTotal"]["amount"] == 1210.0
    assert cma["draftInvoicesInMonthCount"] == 1
    assert cma["draftInvoicesInMonthTotal"]["amount"] == 3630.0
    assert cma["quotesCreatedInMonthCount"] == 1
    assert cma["quotesCreatedInMonthTotal"]["amount"] == 2420.0
    assert cma["expensesInMonthCount"] == 2
    assert cma["expensesInMonthTotal"]["amount"] == 234.5

    # taxDeductible=False is surfaced as a valid fiscal state, never an error
    exp = brief["expensesToReview"]
    assert exp["totalSampledCount"] == 2
    assert exp["totalSampledAmount"]["amount"] == 234.5
    assert exp["nonDeductibleValidCount"] == 1
    assert exp["missingMetadataCount"] == 1

    # Read-only & human-approval invariants
    assert brief["safetyContract"]["workflowReadOnly"] is True
    assert brief["safetyContract"]["mutatingToolsCalledCount"] == 0
    assert brief["safetyContract"]["allSuggestedActionsRequireHumanApproval"] is True
    for action in brief["PrioritizedSuggestedActions"]:
        assert action["humanApprovalRequired"] is True
        assert action["mutatingToolExecuted"] is False

    assert (
        "Importe nominal de facturas no marcadas como pagadas "
        "(saldo pendiente real no determinable sin cobros parciales)"
        in brief["markdown"]
    )


def test_scenario2_partial_coverage_reports_honestly():
    client = frihet.build_scenario2_partial_coverage_client()
    brief = frihet.frihet_daily_brief(
        client,
        as_of_date="2026-10-28",
        period_month="2026-10",
        sample_limit=20,
    )

    assert brief["coverage"]["overallStatus"] == "partial"
    invoices_sr = next(
        sr for sr in brief["coverage"]["subReads"] if sr["resource"] == "invoices"
    )
    assert invoices_sr["status"] == "partial"
    assert invoices_sr["fetchedCount"] == 2
    assert invoices_sr["totalAvailable"] == 47
    assert invoices_sr["isTruncated"] is True

    quotes_sr = next(
        sr for sr in brief["coverage"]["subReads"] if sr["resource"] == "quotes"
    )
    assert quotes_sr["status"] == "failed"
    assert "timeout" in (quotes_sr.get("error") or "").lower()

    assert brief["collectionsAndDueDates"]["overdueTotal"]["amount"] == 500.0
    assert brief["collectionsAndDueDates"]["draftExcludedTotal"]["amount"] == 1500.0
    assert len(brief["coverage"]["truncationWarnings"]) >= 2


def test_golden_counterexample_1_absent_is_not_zero():
    """Rule 1: ``{}`` -> ``amount=None``, ``provenance="unavailable"``, ``unavailableCount=1``."""
    empty_doc_amount = frihet._resolve_doc_amount({}, "EUR")
    assert empty_doc_amount["amount"] is None
    assert empty_doc_amount["provenance"] == "unavailable"
    assert empty_doc_amount.get("unavailableCount") == 1

    aggregated = frihet._sum_provenanced_amounts(
        [
            empty_doc_amount,
            frihet._resolve_doc_amount({"total": 250, "currency": "EUR"}, "EUR"),
        ],
        "EUR",
    )
    assert aggregated["amount"] is None
    assert aggregated["provenance"] == "unavailable"
    assert aggregated["unavailableCount"] == 1
    assert aggregated["totalsByCurrency"]["EUR"] == {
        "amount": 250.0,
        "count": 1,
        "provenance": "stored_field",
    }

    class _MissingAmountClient:
        def call_mcp(self, server: str, tool: str, args: dict[str, Any], timeout: Any = None):
            if tool == "get_business_context":
                return {"ok": True, "result": {"company": {"currency": "EUR"}}}
            if tool == "list_invoices":
                return {
                    "ok": True,
                    "result": {
                        "data": [
                            {
                                "id": "inv_missing_amt",
                                "invoiceNumber": "F-2026-999",
                                "clientName": "Sin Importe SL",
                                "status": "overdue",
                                "dueDate": "2026-10-01",
                            }
                        ],
                        "total": 1,
                    },
                }
            return {"ok": True, "result": {"data": [], "total": 0}}

    brief = frihet.frihet_daily_brief(_MissingAmountClient(), as_of_date="2026-10-28")
    assert brief["collectionsAndDueDates"]["overdueCount"] == 1
    assert brief["collectionsAndDueDates"]["overdueTotal"]["amount"] is None
    assert brief["collectionsAndDueDates"]["overdueTotal"]["provenance"] == "unavailable"
    assert brief["collectionsAndDueDates"]["overdueTotal"]["unavailableCount"] == 1
    assert "No disponible" in brief["markdown"]


def test_golden_counterexample_2_multi_currency_separation():
    """Rule 2: ``100 EUR`` + ``100 USD`` -> ``amount=None``, ``currency="MIXED"``,
    ``provenance="mixed_currency_unconverted"``, never ``200 EUR``."""
    eur_doc = frihet._resolve_doc_amount({"total": 100, "currency": "EUR"}, "EUR")
    usd_doc = frihet._resolve_doc_amount({"total": 100, "currency": "USD"}, "EUR")
    summed = frihet._sum_provenanced_amounts([eur_doc, usd_doc], "EUR")

    assert summed["amount"] is None
    assert summed["currency"] == "MIXED"
    assert summed["provenance"] == "mixed_currency_unconverted"
    assert summed["totalsByCurrency"] == {
        "EUR": {"amount": 100.0, "count": 1, "provenance": "stored_field"},
        "USD": {"amount": 100.0, "count": 1, "provenance": "stored_field"},
    }
    assert "Multi-divisa sin convertir" in frihet._format_provenanced_amount(summed)


def test_golden_counterexample_3_canonical_discounts_taxes_and_fail_closed():
    """Rule 3: ``{items:[{quantity:1, unitPrice:100}], discountRate:10, taxRate:0, irpfRate:0}``
    -> ``90.0 EUR`` (never ``100 EUR``), plus line discount/surcharge/IRPF and fail-closed."""
    discounted_doc = frihet._resolve_doc_amount(
        {
            "items": [{"quantity": 1, "unitPrice": 100}],
            "discountRate": 10,
            "taxRate": 0,
            "irpfRate": 0,
            "currency": "EUR",
        },
        "EUR",
    )
    assert discounted_doc["amount"] == 90.0
    assert discounted_doc["provenance"] == "derived_from_items"

    full_spanish_doc = frihet._resolve_doc_amount(
        {
            "items": [{"quantity": 2, "unitPrice": 100, "discount": 10}],
            "discountRate": 5,
            "taxRate": 21,
            "equivalenceSurchargeRate": 5.2,
            "irpfRate": 15,
            "currency": "EUR",
        },
        "EUR",
    )
    # line: 100 * 0.9 = 90 -> qty 2 = 180 -> doc discount 5% = 9 -> subtotal 171
    # IVA 21% = 35.91, RE 5.2% = 8.89, IRPF 15% = 25.65 -> 171 + 35.91 + 8.89 - 25.65 = 190.15
    assert full_spanish_doc["amount"] == 190.15
    assert full_spanish_doc["provenance"] == "derived_from_items"

    tax_inclusive_doc = frihet._resolve_doc_amount(
        {
            "items": [{"quantity": 1, "unitPrice": 121}],
            "pricesIncludeTax": True,
            "taxRate": 21,
        },
        "EUR",
    )
    assert tax_inclusive_doc["amount"] is None
    assert tax_inclusive_doc["provenance"] == "unavailable"


def test_plugin_reexport_path_works():
    import importlib.util

    reexport_path = ROOT / "plugins" / "frihet-erp" / "frihet.py"
    assert reexport_path.exists()
    spec = importlib.util.spec_from_file_location("frihet_erp_reexport", reexport_path)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    res = mod._resolve_doc_amount({"items": [{"quantity": 1, "unitPrice": 100}], "discountRate": 10})
    assert res["amount"] == 90.0
