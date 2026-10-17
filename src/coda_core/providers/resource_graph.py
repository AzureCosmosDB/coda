"""Bounded NoSQL discovery through ARG with the same SDK identity used for diagnosis."""

from coda_core.providers.management import ManagementReader


def _literal(value: str) -> str:
    """Quote a scope value without turning it into executable KQL."""
    return "'" + value.replace("'", "''") + "'"


def list_graph_accounts(
    credential, subscription: str, *, resource_group: str | None = None,
    account: str | None = None, max_accounts: int = 5000,
) -> list[tuple[str, str]]:
    """Read a complete bounded ARG inventory; never silently truncate the selected scope."""
    if type(max_accounts) is not int or max_accounts <= 0:
        raise ValueError("ARG account limit must be a positive integer.")
    query = (
        "resources | where type =~ 'microsoft.documentdb/databaseaccounts' "
        "| where kind == 'GlobalDocumentDB' "
    )
    if resource_group:
        query += f"| where resourceGroup =~ {_literal(resource_group)} "
    if account:
        query += f"| where name =~ {_literal(account)} "
    query += "| project id, resourceGroup, name | order by name asc"
    reader = ManagementReader(credential)
    rows = []
    skip = None
    seen = set()
    for _ in range(20):
        options = {"resultFormat": "objectArray", "$top": 1000}
        if skip:
            options["$skipToken"] = skip
        result = reader.request(
            "/providers/Microsoft.ResourceGraph/resources?api-version=2022-10-01",
            {"subscriptions": [subscription], "query": query, "options": options},
        )
        if not isinstance(result.get("data"), list):
            raise ValueError("ARG returned an invalid account inventory.")
        for item in result["data"]:
            if not isinstance(item, dict) or any(
                not isinstance(item.get(key), str) or not item[key]
                for key in ("id", "resourceGroup", "name")
            ):
                raise ValueError("ARG returned an incomplete account identity.")
            if not item["id"].casefold().startswith(f"/subscriptions/{subscription}/".casefold()):
                raise ValueError("ARG returned an account outside the requested subscription.")
            if resource_group and item["resourceGroup"].casefold() != resource_group.casefold():
                raise ValueError("ARG returned an account outside the requested resource group.")
            if account and item["name"].casefold() != account.casefold():
                raise ValueError("ARG returned an account outside the requested account scope.")
            rows.append((item["resourceGroup"], item["name"]))
            if len(rows) > max_accounts:
                raise ValueError("ARG account limit exceeded; narrow the selected scope.")
        skip = result.get("$skipToken")
        if not skip:
            if str(result.get("resultTruncated", "false")).casefold() == "true":
                raise ValueError("ARG inventory was truncated.")
            return rows
        if skip in seen:
            raise ValueError("ARG repeated an inventory page.")
        seen.add(skip)
    raise ValueError("ARG pagination limit exceeded.")
