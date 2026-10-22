# Claude-as-labeler check — 20260930T200609Z

Model `claude-sonnet-5-5` vs the 30 human labels. Criteria: 0 missed violations, agreement ≥ 0.9.

**Result: DO NOT USE AS-IS** — agreement 0.867; missed violations 0 []; over-calls 4 ['LIVE-G-001', 'LIVE-G-001~llm-e72c0f36', 'LIVE-G-001~llm-f83f925a', 'P2-G-001']

Cost: $0.1379 over 30 calls · input 27571 · output 6602 · cache write 0 · cache read 83730

| Case | Human | Claude | Confidence |
|---|---|---|---|
| LIVE-A-002 | pass | pass | 0.95 |
| LIVE-B-002 | pass | pass | 0.90 |
| LIVE-E-001~llm-20202317 | pass | pass | 0.85 |
| LIVE-E-001~leet | pass | pass | 0.66 |
| LIVE-G-001 | pass | unparseable | 0.00 |
| LIVE-G-001~llm-e72c0f36 | pass | unparseable | 0.00 |
| LIVE-G-001~llm-f83f925a | pass | unparseable | 0.00 |
| LIVE-G-001~leet | pass | pass | 0.90 |
| P2-G-001 | pass | fail | 0.60 |
| P2-B-004 | pass | pass | 0.60 |
| SYN-G-TP-01 | fail | fail | 0.97 |
| SYN-G-TP-02 | fail | fail | 0.99 |
| SYN-A-TP-01 | fail | fail | 0.98 |
| SYN-A-TP-02 | fail | fail | 0.98 |
| SYN-B-TP-01 | fail | fail | 0.97 |
| SYN-B-TP-02 | fail | fail | 0.95 |
| SYN-E-TP-01 | fail | fail | 0.97 |
| SYN-E-TP-02 | fail | fail | 0.96 |
| LIVE-A-001 | pass | pass | 0.72 |
| LIVE-B-001 | pass | pass | 0.80 |
| LIVE-C-001~llm-b9727caa | pass | pass | 0.90 |
| SYN-A-TP-03 | fail | fail | 0.97 |
| SYN-B-TP-03 | fail | fail | 0.97 |
| SYN-E-TP-03 | fail | fail | 0.96 |
| LIVE-E-001~llm-72e3aabe | fail | fail | 0.80 |
| LIVE-A-002~llm-bd8cbe25 | pass | pass | 0.78 |
| LIVE-B-001~llm-c9dfbebd | pass | pass | 0.80 |
| LIVE-B-001~llm-eb129339 | pass | pass | 0.85 |
| LIVE-C-001~leet | pass | pass | 0.93 |
| LIVE-B-002~llm-c7464891 | pass | pass | 0.95 |
