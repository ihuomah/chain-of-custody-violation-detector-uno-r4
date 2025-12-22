# chain-of-custody-violation-detector-uno-r4

# Chain-of-Custody Violation Detection System (CoC-VDS)

A cyber-physical prototype built on Arduino Uno R4 WiFi that detects and records **chain-of-custody violations** in a supply-chain delivery scenario (factory → courier → data center).

Unlike simple “tamper detection”, this system models **custody states**, validates **authorised handovers**, and raises violations when handling/opening occurs outside custody rules.

## Project Phases
- **Phase 1 — Hardware Bring-up & Calibration:** verify sensors and collect baseline ranges for thresholds.
- **Phase 2 — Custody Model & Rules:** define roles, states, and violation rules.
- **Phase 3 — State Machine Implementation:** implement custody states and violation detection logic (OLED UI).
- **Phase 4** — Forensic Logging & Integrity (hash-chained logs).
- **Phase 5** — Threat simulation & metrics.
- **Phase 6** — Final Testing, Documentation & Demo.