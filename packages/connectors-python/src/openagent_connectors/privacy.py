"""Pure provider schema selectors for trusted official connector hosts.

No Core dependency and no identity/consent inference. The host supplies a verified
provider, operation and actual provider JSON result, then binds each selection to
its authenticated app, installation, grant and tenant. Unknown data retains an
unknown subject; it must never become an unattributed or nonpersonal exemption.
"""
from __future__ import annotations
from dataclasses import dataclass
import json

@dataclass(frozen=True, slots=True)
class SubjectSelection:
    subjects: tuple[str, ...] = ()
    nonpersonal: bool = False

@dataclass(frozen=True, slots=True)
class ProviderFragment:
    path: tuple[str | int, ...]
    selection: SubjectSelection

def provider_id(value: object) -> str:
    if isinstance(value, bool) or not isinstance(value, (str, int)):
        raise ValueError("A provider-validated numeric identity is required")
    text = str(value)
    if not text.isascii() or not text.isdecimal() or not 0 < int(text) < 2**64:
        raise ValueError("Invalid provider numeric identity")
    return str(int(text))

_ENTITY_SCHEMA = {
    "commerce.shopify.customers.list": (("data", "customers", "nodes"), "Customer", True),
    "commerce.shopify.customers.get": (("data", "customer"), "Customer", False),
    "commerce.shopify.customers.update": (("data", "customerUpdate", "customer"), "Customer", False),
    "commerce.shopify.orders.list": (("data", "orders", "nodes"), "Order", True),
    "commerce.shopify.orders.get": (("data", "order"), "Order", False),
    "commerce.shopify.orders.close": (("data", "orderClose", "order"), "Order", False),
    "commerce.shopify.products.list": (("data", "products", "nodes"), "Product", True),
    "commerce.shopify.products.get": (("data", "product"), "Product", False),
    "commerce.shopify.products.update": (("data", "productUpdate", "product"), "Product", False),
}

def _verified_entity_subject(value, kind):
    if not isinstance(value, dict) or not isinstance(value.get("id"), str):
        raise ValueError("Provider record lacks its schema-verified identity")
    prefix = "gid://shopify/" + kind + "/"
    if not value["id"].startswith(prefix):
        raise ValueError("Provider identity does not match the selected entity schema")
    return (kind.lower() + ":" + provider_id(value["id"][len(prefix):]),)

def provider_fragment_specs(operation, data):
    """Partition known GraphQL records; unknown data stays subject-unknown.

    These selectors describe the published provider query schemas. IDs come
    from exact provider response nodes, never model arguments or text matching.
    None denotes a nonpersonal provider subtree, still bound to app/shop/consent; () means
    provider data of unknown subject and therefore cannot complete a customer job.
    """
    schema = _ENTITY_SCHEMA.get(operation)
    if schema is None:
        return (((), ()),)
    entity_path, kind, plural = schema
    specs = []
    nodes = 0

    def walk(value, path=()):
        nonlocal nodes
        nodes += 1
        if nodes > 4096 or len(path) > 60:
            raise ValueError("Provider fragment partition exceeds its bound")
        if path == entity_path:
            if value is None:
                specs.append((path, None))
            elif plural:
                if not isinstance(value, list) or len(value) > 4096:
                    raise ValueError("Provider list does not match the selected entity schema")
                if not value:
                    specs.append((path, None))
                for index, record in enumerate(value):
                    subject = _verified_entity_subject(record, kind)
                    specs.append((path + (index,), None if kind == "Product" else subject))
            else:
                subject = _verified_entity_subject(value, kind)
                specs.append((path, None if kind == "Product" else subject))
            return
        if (operation == "commerce.shopify.customers.update"
                and path == ("data", "customerUpdate", "userErrors")
                and type(value) is list and not value):
            # Only a successful compiled mutation's empty error collection.
            # It still belongs to the verified app/shop/grant in the host.
            specs.append((path, None))
            return
        if (operation == "commerce.shopify.products.list"
                and path == ("data", "productsCount") and isinstance(value, dict)
                and set(value) == {"count", "precision"}
                and type(value["count"]) is int and 0 <= value["count"] < 2**31
                and type(value["precision"]) is str
                and value["precision"] in {"EXACT", "AT_LEAST"}):
            # Shopify Count: Int! plus the closed CountPrecision enum.
            # Technical store metadata retains the host's app/shop/grant origin.
            specs.append((path, None))
            return
        if path == ("extensions", "cost") and isinstance(value, dict):
            numeric = lambda item: type(item) in {int, float} and 0 <= item < 1e12
            allowed = {"requestedQueryCost", "actualQueryCost", "throttleStatus"}
            throttle = value.get("throttleStatus", {})
            if (set(value) <= allowed and isinstance(throttle, dict)
                    and set(throttle) <= {"maximumAvailable", "currentlyAvailable", "restoreRate"}
                    and all(numeric(item) for key, item in value.items() if key != "throttleStatus")
                    and all(numeric(item) for item in throttle.values())):
                specs.append((path, None))
                return
        if plural and path == entity_path[:-1] + ("pageInfo",) and isinstance(value, dict) and set(value) == {"hasNextPage", "endCursor"}:
            if type(value["hasNextPage"]) is not bool or not (value["endCursor"] is None or isinstance(value["endCursor"], str)):
                raise ValueError("Provider pagination does not match the reviewed schema")
            specs.append((path, None))
            return
        if path in {("data", "shop", "currencyCode"), ("data", "shop", "ianaTimezone")} and isinstance(value, str):
            specs.append((path, None))
            return
        if isinstance(value, dict) and value:
            for key, child in value.items():
                walk(child, path + (key,))
        elif isinstance(value, list) and value:
            for index, child in enumerate(value):
                walk(child, path + (index,))
        else:
            specs.append((path, ()))
    walk(data)
    if len(specs) > 4096:
        raise ValueError("Provider fragment partition exceeds its bound")
    return tuple(specs)

def invocation_origin_spec(operation, arguments):
    """Classify only exact compiled query shapes before canonical begin_tool.

    Returns (subjects, nonpersonal). Free text queries or unknown input shapes
    never acquire a guessed customer label or a nonpersonal exemption.
    """
    if not isinstance(arguments, dict):
        raise ValueError("Provider invocation arguments must be a JSON object")
    if operation not in _ENTITY_SCHEMA:
        return (), False
    lists = {"commerce.shopify.products.list", "commerce.shopify.orders.list", "commerce.shopify.customers.list"}
    if operation in lists and set(arguments) <= {"first", "after", "query"}:
        first = arguments.get("first", 50)
        if (type(first) is int and 1 <= first <= 250 and arguments.get("after") in (None, "")
                and arguments.get("query") in (None, "")):
            return (), True
    gets = {"commerce.shopify.customers.get": "Customer", "commerce.shopify.orders.get": "Order",
            "commerce.shopify.products.get": "Product"}
    if operation in gets and set(arguments) == {"id"}:
        kind = gets[operation]
        subjects = _verified_entity_subject(arguments, kind)
        return ((), True) if kind == "Product" else (subjects, False)
    if operation == "commerce.shopify.customers.update" and set(arguments) == {"input"}:
        return _verified_entity_subject(arguments["input"], "Customer"), False
    return (), False


def _validate_json(value):
    remaining = 65_536
    def visit(node, depth=0):
        nonlocal remaining
        remaining -= 1
        if remaining < 0:
            raise ValueError("Provider JSON node count exceeds its bound")
        if depth > 60:
            raise ValueError("Provider JSON nesting exceeds its bound")
        if isinstance(node, dict):
            if len(node) > 4096 or len(node) > remaining:
                raise ValueError("Provider JSON object count exceeds its bound")
            if not all(isinstance(key, str) for key in node):
                raise ValueError("Provider JSON keys must be strings")
            for child in node.values(): visit(child, depth + 1)
        elif isinstance(node, list):
            if len(node) > 4096 or len(node) > remaining:
                raise ValueError("Provider JSON array count exceeds its bound")
            for child in node: visit(child, depth + 1)
        elif node is not None and type(node) not in {bool, int, float, str}:
            raise ValueError("Provider payload must be plain JSON")
        elif isinstance(node, str) and len(node) > 2 << 20:
            raise ValueError("Provider JSON string exceeds its bound")
    visit(value)
    if len(json.dumps(value, ensure_ascii=False, allow_nan=False).encode()) > 2 << 20:
        raise ValueError("Provider JSON exceeds its bound")


def result_fragments(provider: str, operation: str, payload: object) -> tuple[ProviderFragment, ...]:
    if provider != "shopify" or not isinstance(operation, str):
        raise ValueError("No reviewed privacy schema exists for this provider")
    if not isinstance(payload, dict):
        raise ValueError("The official provider result must be a JSON object")
    _validate_json(payload)
    specs = provider_fragment_specs(operation, payload)
    return tuple(ProviderFragment(path, SubjectSelection(tuple(subjects or ()), subjects is None))
                 for path, subjects in specs)


def invocation_selection(provider: str, operation: str, arguments: object) -> SubjectSelection:
    if provider != "shopify" or not isinstance(operation, str):
        raise ValueError("No reviewed privacy schema exists for this provider")
    _validate_json(arguments)
    subjects, nonpersonal = invocation_origin_spec(operation, arguments)
    return SubjectSelection(tuple(subjects), nonpersonal)
