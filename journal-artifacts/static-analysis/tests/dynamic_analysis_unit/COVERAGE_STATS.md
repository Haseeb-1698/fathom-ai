# Dynamic Analysis Test Coverage

Command:

```bash
tests/dynamic_analysis_unit/run_dynamic_coverage.sh
```

Success stats:

```text
44 passed in 0.79s
```

Coverage stats:

```text
Name                           Stmts   Miss Branch BrPart  Cover
--------------------------------------------------------------------------
server/cape_integration.py       216     48     58     15    73%
server/dynamic/__init__.py         4      0      0      0   100%
server/dynamic/loader.py          33      1     10      0    98%
server/dynamic/normalizer.py      14      0      4      0   100%
server/dynamic/parser.py         121      9     78     12    89%
--------------------------------------------------------------------------
TOTAL                            388     58    150     27    82%
```

Notes:

- The test bundle is offline and mocked; it does not execute malware or submit samples to CAPE.
- The lower coverage in `cape_integration.py` is mostly from live-network callback delivery, HTML report retrieval, timeout waiting, and alternate unsafe/missing report paths that are intentionally not exercised against real services.
- The focused dynamic parser/normalizer/loader modules are covered strongly: loader 98%, parser 89%, normalizer 100%.

