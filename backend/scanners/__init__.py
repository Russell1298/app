"""
Scanner package.

USER_AGENT is shared by every scanner so a site owner reading their access
logs sees one consistent, identifiable client with a working contact URL,
rather than several different strings pointing at a domain we no longer own.
"""

USER_AGENT = "Sekura-Scanner/1.0 (+https://sekura.cloud/security)"

SCAN_HEADERS = {"User-Agent": USER_AGENT}
