"""Plans, search types and credit costs.

One place decides what a plan can do, so the UI, the API and the scanner can
never disagree about a gate.
"""
from __future__ import annotations

# --- search types ---------------------------------------------------------

SEARCH_TYPES: list[dict] = [
    {
        "id": "phone",
        "label": "Phone",
        "hint": "E.164 or local format",
        "placeholder": "+1 202 555 0143",
        "pro": False,
        "cost": 1,
        "blurb": "Normalises the number, flags its country and carrier type, and checks it against public breach and abuse feeds.",
    },
    {
        "id": "email",
        "label": "Email",
        "hint": "mailbox address",
        "placeholder": "someone@example.com",
        "pro": False,
        "cost": 1,
        "blurb": "Mail deliverability (MX), disposable-provider flag, Gravatar presence and public breach exposure.",
    },
    {
        "id": "username",
        "label": "Username",
        "hint": "handle or profile URL",
        "placeholder": "mrbeast",
        "pro": False,
        "cost": 1,
        "blurb": "The full endpoint sweep — every supported site is checked and matches stream back live.",
    },
    {
        "id": "name",
        "label": "Name",
        "hint": "real name",
        "placeholder": "John Smith",
        "pro": True,
        "cost": 3,
        "blurb": "Generates handle candidates from a name and reports which social profiles match them.",
    },
    {
        "id": "wallet",
        "label": "Wallet",
        "hint": "ETH / BTC / SOL / TRX address",
        "placeholder": "0x3bcC6F90F5fc09FDeAfB4AECF2EA367Ed32E12D4",
        "pro": True,
        "cost": 2,
        "blurb": "On-chain balance, transaction count and first-seen activity for Bitcoin, Ethereum, Solana and Tron.",
    },
    {
        "id": "ip",
        "label": "IP",
        "hint": "IPv4 / IPv6 address",
        "placeholder": "8.8.8.8",
        "pro": True,
        "cost": 1,
        "blurb": "Geolocation, ISP and ASN, reverse DNS and proxy / hosting / mobile flags.",
    },
    {
        "id": "domain",
        "label": "Domain",
        "hint": "hostname",
        "placeholder": "example.com",
        "pro": False,
        "cost": 1,
        "blurb": "RDAP registration data plus live A, AAAA, MX, NS, TXT and SOA records.",
    },
    {
        "id": "image",
        "label": "Image",
        "hint": "image URL",
        "placeholder": "https://example.com/photo.jpg",
        "pro": True,
        "cost": 3,
        "blurb": "Reverse-image lookup across Yandex, Bing and TinEye — every page that still hosts the picture.",
    },
]

SEARCH_TYPE_IDS = [t["id"] for t in SEARCH_TYPES]
PRO_ONLY_TYPES = {t["id"] for t in SEARCH_TYPES if t["pro"]}
TYPE_BY_ID = {t["id"]: t for t in SEARCH_TYPES}


def type_cost(kind: str) -> int:
    t = TYPE_BY_ID.get(kind)
    return t["cost"] if t else 1


def is_pro_type(kind: str) -> bool:
    return kind in PRO_ONLY_TYPES


# --- plans ----------------------------------------------------------------

PLANS: dict[str, dict] = {
    "free": {
        "id": "free",
        "name": "Free",
        "price": "$0",
        "period": "forever",
        "credits": 0,
        "daily_credits": 5,
        "adult": False,
        "api": False,
        "bulk": False,
        "reports": False,
        "cases": 10,
        "tagline": "Run a public sweep and see how it works.",
        "features": [
            "Username, email, phone and domain search",
            "5 credits per day",
            "10 cloud cases",
            "Public endpoint corpus (737 sources)",
        ],
    },
    "pro": {
        "id": "pro",
        "name": "Pro",
        "price": "$4.99",
        "period": "per month",
        "credits": 500,
        "daily_credits": 0,
        "adult": True,
        "api": True,
        "bulk": True,
        "reports": True,
        "cases": 500,
        "tagline": "Every search type, the full corpus and the API.",
        "features": [
            "Everything in Free",
            "Name, wallet, IP and image search",
            "500 credits per month",
            "Full endpoint corpus including adult sources",
            "Bulk search (BETA)",
            "API access with your own key",
            "PDF and Word reports",
            "500 cloud cases",
            "No captcha",
        ],
    },
    "team": {
        "id": "team",
        "name": "Team",
        "price": "$9.99",
        "period": "per month",
        "credits": 2000,
        "daily_credits": 0,
        "adult": True,
        "api": True,
        "bulk": True,
        "reports": True,
        "cases": 5000,
        "tagline": "Shared credit pool and priority capacity for a team.",
        "features": [
            "Everything in Pro",
            "2,000 credits per month",
            "Shared credit pool across seats",
            "5,000 cloud cases",
            "Priority scan capacity",
            "Dedicated support",
        ],
    },
}

FREE_PLAN = "free"
DEFAULT_PLAN = "free"


def get_plan(plan_id: str | None) -> dict:
    return PLANS.get(plan_id or DEFAULT_PLAN, PLANS[DEFAULT_PLAN])


def is_pro(plan_id: str | None) -> bool:
    """Pro means any paid tier — team included."""
    return (plan_id or DEFAULT_PLAN) in ("pro", "team")


def plan_for_credits(credits: int) -> str:
    """Which plan a raw credit balance implies (used by the admin console)."""
    if credits >= 2000:
        return "team"
    if credits >= 500:
        return "pro"
    return FREE_PLAN
