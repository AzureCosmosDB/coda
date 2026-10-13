"""Strict, unauthenticated Azure Retail Prices reads for DX-019 PITR storage only.

The public Retail Prices API needs no Azure credential. This provider deliberately accepts only the
live-verified Cosmos PITR recurring-storage meter and rejects redirects, cross-host pagination,
partial region coverage, duplicate current records, restore meters, mixed currencies, and any
near-match. It never guesses a price.
"""

from __future__ import annotations

import json
import math
import threading
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timezone

RETAIL_PRICES_BASE_URL = "https://prices.azure.com/api/retail/prices"
RETAIL_PRICES_HOST = "prices.azure.com"
PITR_PRODUCT_NAME = "Azure Cosmos DB - PITR"
PITR_SKU_NAME = "Backup"
PITR_STORAGE_METER_NAME = "Cont 30D Bckp Continuous Backup"
PITR_SERVICE_NAME = "Azure Cosmos DB"
PITR_UNIT = "1 GB"


class RetailPriceUnavailable(ValueError):
    """Retail Price API evidence failed strict provenance or completeness checks."""


@dataclass(frozen=True)
class PitrStoragePrice:
    """One region's current exact PITR recurring-storage list price."""

    arm_region_name: str
    currency: str
    rate_per_gb_month: float
    meter_id: str
    effective_start_date: str
    effective_end_date: str | None = None


class _RejectRedirects(urllib.request.HTTPRedirectHandler):
    """Prevent urllib from silently following an attacker-controlled redirect target."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: ANN001, ANN201
        return None


def _parse_effective(value: object) -> datetime:
    """Parse a Retail Prices effective timestamp as aware UTC."""
    if not isinstance(value, str) or not value:
        raise RetailPriceUnavailable("retail_price_effective_date_missing")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise RetailPriceUnavailable("retail_price_effective_date_invalid") from exc
    if parsed.tzinfo is None:
        raise RetailPriceUnavailable("retail_price_effective_date_not_timezone_aware")
    return parsed.astimezone(timezone.utc)


def _is_exact_storage_record(item: dict, currency: str) -> bool:
    """Match the exact live recurring-storage identity; restore and 7-day meters cannot pass."""
    return (
        item.get("serviceName") == PITR_SERVICE_NAME
        and item.get("productName") == PITR_PRODUCT_NAME
        and item.get("skuName") == PITR_SKU_NAME
        and item.get("meterName") == PITR_STORAGE_METER_NAME
        and item.get("type") == "Consumption"
        and item.get("unitOfMeasure") == PITR_UNIT
        and item.get("tierMinimumUnits") == 0.0
        and item.get("isPrimaryMeterRegion") is True
        and item.get("currencyCode") == currency
    )


class RetailPricesProvider:
    """Read and cache immutable exact PITR storage rates from fixed ``prices.azure.com`` HTTPS."""

    def __init__(self, *, currency: str = "USD", timeout_seconds: float = 15.0) -> None:
        self.currency = currency.upper()
        self._timeout_seconds = timeout_seconds
        self._opener = urllib.request.build_opener(_RejectRedirects)
        self._cache: dict[tuple[tuple[str, ...], str, str], tuple[PitrStoragePrice, ...]] = {}
        self._cache_lock = threading.Lock()

    def _initial_url(self) -> str:
        query = urllib.parse.urlencode({
            "$filter": (
                f"serviceName eq '{PITR_SERVICE_NAME}' and "
                f"productName eq '{PITR_PRODUCT_NAME}'"
            ),
            "currencyCode": self.currency,
        })
        return f"{RETAIL_PRICES_BASE_URL}?{query}"

    @staticmethod
    def _validate_url(url: str) -> None:
        parsed = urllib.parse.urlsplit(url)
        if (
            parsed.scheme != "https"
            or parsed.hostname != RETAIL_PRICES_HOST
            or parsed.username is not None
            or parsed.password is not None
            or parsed.port not in (None, 443)
        ):
            raise RetailPriceUnavailable("retail_price_pagination_left_fixed_https_host")

    def _fetch_page(self, url: str) -> dict:
        """Fetch one JSON page without authentication or redirect following."""
        self._validate_url(url)
        request = urllib.request.Request(url, headers={"Accept": "application/json"}, method="GET")
        try:
            with self._opener.open(request, timeout=self._timeout_seconds) as response:
                return json.loads(response.read().decode("utf-8"))
        except (urllib.error.URLError, json.JSONDecodeError) as exc:
            raise RetailPriceUnavailable("retail_price_request_failed") from exc

    def _all_items(self) -> tuple[dict, ...]:
        url: str | None = self._initial_url()
        seen: set[str] = set()
        items: list[dict] = []
        while url:
            self._validate_url(url)
            if url in seen:
                raise RetailPriceUnavailable("retail_price_pagination_loop")
            seen.add(url)
            payload = self._fetch_page(url)
            if payload.get("BillingCurrency") != self.currency:
                raise RetailPriceUnavailable("retail_price_response_currency_mismatch")
            page_items = payload.get("Items")
            if not isinstance(page_items, list):
                raise RetailPriceUnavailable("retail_price_items_missing")
            items.extend(item for item in page_items if isinstance(item, dict))
            next_page = payload.get("NextPageLink")
            if next_page is not None and not isinstance(next_page, str):
                raise RetailPriceUnavailable("retail_price_next_page_invalid")
            url = next_page
        return tuple(items)

    def pitr_storage_prices(
        self,
        arm_regions: tuple[str, ...],
        *,
        as_of: datetime,
    ) -> tuple[PitrStoragePrice, ...]:
        """Return one exact current PITR storage rate for every requested canonical ARM region."""
        if as_of.tzinfo is None:
            raise RetailPriceUnavailable("retail_price_as_of_not_timezone_aware")
        normalized = tuple(region.casefold() for region in arm_regions)
        if not normalized or len(set(normalized)) != len(normalized):
            raise RetailPriceUnavailable("retail_price_regions_missing_or_duplicate")
        as_of_utc = as_of.astimezone(timezone.utc)
        cache_key = (normalized, self.currency, as_of_utc.isoformat())
        with self._cache_lock:
            cached = self._cache.get(cache_key)
        if cached is not None:
            return cached

        requested = set(normalized)
        current: dict[str, list[tuple[datetime, dict]]] = {region: [] for region in normalized}
        for item in self._all_items():
            region = str(item.get("armRegionName") or "").casefold()
            if region not in requested or not _is_exact_storage_record(item, self.currency):
                continue
            start = _parse_effective(item.get("effectiveStartDate"))
            end_value = item.get("effectiveEndDate")
            end = _parse_effective(end_value) if end_value else None
            if start <= as_of_utc and (end is None or as_of_utc < end):
                current[region].append((start, item))

        result: list[PitrStoragePrice] = []
        for region in normalized:
            candidates = current[region]
            if not candidates:
                raise RetailPriceUnavailable(f"retail_price_region_missing:{region}")
            if len(candidates) != 1:
                raise RetailPriceUnavailable(f"retail_price_region_duplicate:{region}")
            _, item = candidates[0]
            try:
                price = float(item["retailPrice"])
            except (KeyError, TypeError, ValueError) as exc:
                raise RetailPriceUnavailable("retail_price_value_invalid") from exc
            if not math.isfinite(price) or price < 0:
                raise RetailPriceUnavailable("retail_price_value_invalid")
            meter_id = str(item.get("meterId") or "")
            if not meter_id:
                raise RetailPriceUnavailable("retail_price_meter_id_missing")
            result.append(PitrStoragePrice(
                arm_region_name=region,
                currency=self.currency,
                rate_per_gb_month=price,
                meter_id=meter_id,
                effective_start_date=str(item["effectiveStartDate"]),
                effective_end_date=(
                    str(item["effectiveEndDate"]) if item.get("effectiveEndDate") else None
                ),
            ))

        immutable = tuple(result)
        with self._cache_lock:
            self._cache[cache_key] = immutable
        return immutable
