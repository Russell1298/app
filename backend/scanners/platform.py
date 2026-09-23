"""
Hosted-platform detection.

On Shopify, Wix and Squarespace the platform, not the site owner, sets the
response headers, the cookies it issues and the TLS configuration. A report that
tells a merchant to "raise your HSTS max-age" on Shopify is pinning the platform's
decision on someone who cannot change it. Findings on those settings are still
shown, attributed to the platform, and are not scored.

Only markers each platform sets on every storefront response are used, so an
ordinary site that merely embeds a Shopify buy button is not mistaken for one.
"""

import httpx


def hosted_platform(response: httpx.Response) -> str | None:
    headers = response.headers
    server = headers.get("server", "").lower()
    set_cookies = " ".join(headers.get_list("set-cookie")).lower()

    if (
        any(h in headers for h in ("x-shopid", "x-shopify-stage", "x-sorting-hat-shopid"))
        or "shopify" in headers.get("powered-by", "").lower()
        or "_shopify_y=" in set_cookies
        or "_shopify_s=" in set_cookies
    ):
        return "Shopify"
    if "x-wix-request-id" in headers or "pepyaka" in server:
        return "Wix"
    if "squarespace" in server:
        return "Squarespace"
    return None
