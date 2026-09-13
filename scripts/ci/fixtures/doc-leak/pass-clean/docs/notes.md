# Clean prose, including the near-misses that must not fire

Point your clients at https://vault.example.com — any origin works, andvari is
endpoint-agnostic. The reference instance's own host label is CT122 (and CT 121
next to it), which docs/ROADMAP.md ratifies as one household's label rather than
part of the product.

Releases are cut by `scripts/prestige-release.ps1`; the current fleet is 0.26.3
and the extension track is at 0.26.0. Older notes mention 0.10.0 and 1.10.0.

Addresses just outside the private ranges are ordinary public addresses and are
not leaks: 172.15.0.1, 100.63.0.1, 11.0.0.1, 193.168.0.1.
