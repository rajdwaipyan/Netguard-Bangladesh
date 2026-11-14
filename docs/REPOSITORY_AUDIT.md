# Repository Audit

## Audit scope

This audit covers the files currently present in the workspace, including
`netguard_bangladesh.py`, the deterministic tests, all phase documentation,
`.gitignore`, `index.html`, and the empty `netguard_data` directory.

The workspace is **not a Git repository**. No branch, remote, history, staged
file set, commit, or GitHub publication can be verified from this workspace.

## Existing capabilities

| Area | Actual status |
|---|---|
| Phase 1 foundations | Conditional acceptance documented; real Windows ping/ARP behavior and queue workers are tested |
| Phase 2 discovery | Conditional scope; Windows interface parsing and authorized private IPv4 ICMP discovery |
| Phase 3A gateway | Conditional scope; selected-interface gateway and ARP evidence |
| Phase 3B router assessment | Conditional scope; bounded local TCP/HTTP/TLS observations |
| Phase 3C UPnP/DNS | Conditional scope; IPv4 SSDP and consent-based UDP A/AAAA checks |
| Phase 3D Wi-Fi | Conditional scope; `netsh wlan` metadata and informational baselines |
| Phase 3E firmware intelligence | Conditional scope; registration, NVD/KEV clients, CPE/version matching, advisory records, and stale-cache reporting |

No phase has real-world validation evidence in this workspace. Phase reports
explicitly record this limitation.

## Architecture

The application is a single Tkinter module containing discovery, assessment,
wireless, firmware intelligence, persistence, and GUI code. Background workers
publish through `queue.Queue`; `root.after()` drains the queue on the Tk main
thread. Persistence uses one atomic JSON document under the user's local
application data directory.

The design is service-like internally, but it has not yet been split into
packages. Avoid a presentation-only rewrite until service boundaries and
platform tests justify it.

## Dependencies

Core functionality uses the Python standard library. NumPy, Matplotlib, and
scikit-learn are optional runtime integrations detected at import time. Ruff
is the development static-analysis dependency in `requirements-dev.txt`.
Npcap is not required by the implemented features.

## Testing status

The latest local verification executed:

- `python -m unittest discover -s tests -v`
- **80 tests passed, 0 failed**
- `python -m py_compile netguard_bangladesh.py tests\test_discovery_engine.py tests\test_runtime_probes.py`
- Compilation passed.

Tests are deterministic and mock Windows subprocesses, sockets, HTTPS
responses, and worker dependencies. No live network or external intelligence
request was made.

## Security and privacy findings

- No hardcoded API key was found; `NVD_API_KEY` is read from the environment.
- Firmware synchronization sends public manufacturer/model search terms only.
- No credentials, private addresses, MAC addresses, or router configuration are
  sent to public intelligence providers.
- Legacy simulated router vulnerability UI is unreachable and explicitly
  disabled.
- `index.html` is an unrelated static portfolio page and contains a contact
  address. It should be reviewed by the owner before public publication.
- Test fixtures contain documentation-only private IPv4 addresses; they are
  synthetic and should remain clearly identified as fixtures.

## Publication blockers

1. The workspace is not a Git repository and has no configured remote.
2. No `LICENSE` file exists; the owner must choose and add a license.
3. No verified GitHub owner, repository URL, branch, or authentication context
   is available.
4. No screenshots have been captured and redacted.
5. The monolithic application and JSON persistence remain maintainability
   limitations.
6. The current CI workflow and community files are newly prepared but cannot
   be validated against GitHub until a repository exists.
7. Live Windows/network/source validation has not been performed here.

## Recommendation

The workspace is **publication-prepared but not publishable from this
environment**. Add a verified Git repository, owner-approved license, redacted
screenshots, and remote configuration before committing or pushing.
