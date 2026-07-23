from .bugcrowd import BugcrowdAdapter
from .hackerone import HackerOneAdapter
from .intigriti import IntigritiAdapter
from .yeswehack import YesWeHackAdapter

ADAPTERS = {
    "hackerone": HackerOneAdapter,
    "intigriti": IntigritiAdapter,
    "yeswehack": YesWeHackAdapter,
    "bugcrowd": BugcrowdAdapter,
}

# Alias mapping — Mini App'dan kelgan platform nomlarini normalize qilish uchun
PLATFORM_ALIASES: dict[str, str] = {
    "hackerone": "hackerone",
    "h1": "hackerone",
    "intigriti": "intigriti",
    "intigriti.com": "intigriti",
    "yeswehack": "yeswehack",
    "ywh": "yeswehack",
    "bugcrowd": "bugcrowd",
    "bc": "bugcrowd",
}


def normalize_platform(name: str) -> str:
    """Return canonical platform key from any common name variant."""
    key = name.strip().lower().replace(" ", "").replace("-", "").replace("_", "")
    return PLATFORM_ALIASES.get(key, key)


def get_adapter(kind: str):
    """Return adapter class for a platform name. Raises ValueError for unknown platforms."""
    canonical = normalize_platform(kind)
    try:
        return ADAPTERS[canonical]
    except KeyError as exc:
        supported = ", ".join(sorted(ADAPTERS))
        raise ValueError(f"Unsupported platform '{kind}'. Supported: {supported}") from exc


# ── Shared Asset Type Normalizer ──────────────────────────────────────────────
# Single source of truth for asset type names — used by ALL adapters.
# Raw values coming from any platform API are mapped here to consistent labels.

_EXACT_MAP: dict[str, str] = {
    # ALLCAPS / underscore form (HackerOne JSON)
    "URL": "URL",
    "WILDCARD": "Wildcard",
    "CIDR": "CIDR",
    "IP_ADDRESS": "IP Address",
    "SOURCE_CODE": "Source Code",
    "DOWNLOADABLE_EXECUTABLES": "Executable",
    "HARDWARE": "Hardware/IoT",
    "GOOGLE_PLAY_APP_ID": "Android: Play Store",
    "APPLE_STORE_APP_ID": "Apple: App Store",
    "WINDOWS_APP_STORE_APP_ID": "Windows: App Store",
    "OTHER_APK": "Android: APK",
    "OTHER_IPA": "Apple: IPA",
    "TESTFLIGHT": "Apple: TestFlight",
    "OTHER": "Other",
    "SMART_CONTRACT": "Smart Contract",
    "API": "API",
    "AI_MODEL": "AI Model",
    "DEVICE": "Hardware/IoT",
    # Already-good labels (idempotent)
    "Wildcard": "Wildcard",
    "IP Address": "IP Address",
    "Source Code": "Source Code",
    "Executable": "Executable",
    "Hardware/IoT": "Hardware/IoT",
    "Android: Play Store": "Android: Play Store",
    "Apple: App Store": "Apple: App Store",
    "Windows: App Store": "Windows: App Store",
    "Android: APK": "Android: APK",
    "Apple: IPA": "Apple: IPA",
    "Apple: TestFlight": "Apple: TestFlight",
    "Smart Contract": "Smart Contract",
    "AI Model": "AI Model",
}

# Lowercase/normalised keyword fallback (for Bugcrowd/YesWeHack/Intigriti)
_KEYWORD_MAP: list[tuple[str, str]] = [
    ("wildcard", "Wildcard"),
    ("sourcecode", "Source Code"),
    ("source_code", "Source Code"),
    ("source code", "Source Code"),
    ("executable", "Executable"),
    ("downloadable", "Executable"),
    ("testflight", "Apple: TestFlight"),
    ("googleplay", "Android: Play Store"),
    ("playstore", "Android: Play Store"),
    ("android", "Android: Play Store"),
    ("appstore", "Apple: App Store"),
    ("ios", "Apple: App Store"),
    ("apple", "Apple: App Store"),
    ("windowsstore", "Windows: App Store"),
    ("windowsapp", "Windows: App Store"),
    ("smartcontract", "Smart Contract"),
    ("aimodel", "AI Model"),
    ("hardware", "Hardware/IoT"),
    ("device", "Hardware/IoT"),
    ("iot", "Hardware/IoT"),
    ("ipaddress", "IP Address"),
    ("cidr", "CIDR"),
    ("apk", "Android: APK"),
    ("ipa", "Apple: IPA"),
    ("api", "API"),
    ("url", "URL"),
    ("web", "URL"),
    ("other", "Other"),
]


def normalize_asset_type(raw: str) -> str:
    """Map any raw asset type string from any platform to a canonical label.

    Lookup order:
    1. Exact match in _EXACT_MAP (handles all-caps H1 values)
    2. Keyword-based match on lowercased+stripped value
    3. Return the raw string as-is (or 'Other' if empty)
    """
    if not raw or not raw.strip():
        return "Other"
    raw = raw.strip()

    # 1. Exact match (case-sensitive — covers both ALLCAPS and already-good labels)
    if raw in _EXACT_MAP:
        return _EXACT_MAP[raw]

    # 2. Case-insensitive exact match
    upper = raw.upper().strip()
    if upper in _EXACT_MAP:
        return _EXACT_MAP[upper]

    # 3. Keyword fallback on normalised key
    key = raw.lower().replace(" ", "").replace("_", "").replace("-", "")
    for item in _KEYWORD_MAP:
        if isinstance(item, tuple) and len(item) == 2:
            pattern, mapped = item
            if pattern in key:
                return mapped

    return raw or "Other"
