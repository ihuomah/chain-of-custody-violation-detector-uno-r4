# Chain-of-Custody Violation Detection System (CoC-VDS)

A **cyber-physical security prototype** built on **Arduino Uno R4 WiFi** that enforces and detects **chain-of-custody violations** during high-value asset transport (e.g. factory → courier → data center).

Unlike basic *tamper detection*, this system models **custody states**, validates **authorized handovers**, and detects **process violations** such as unauthorized movement, seal breaches, and failed transfers.

---

## Why This Matters
In regulated environments (digital forensics, hardware supply chains, evidence handling), the key question is not:

> *“Was the package opened?”*

But rather:

> *“Was the chain of custody preserved?”*

An asset can remain physically intact yet still become **legally inadmissible** due to undocumented handling.  
CoC-VDS is designed to detect exactly those failures.

---

## System Overview
The system correlates **identity**, **motion**, and **enclosure state** to enforce custody rules in real time:

- **RFID (MFRC522)** — role-based identity (admin vs courier)
- **IMU (MPU6050 / GY-87)** — movement and handling detection
- **LDR (photoresistor)** — enclosure opening / seal breach detection
- **OLED (SSD1306)** — live operational status (development UI)
- **Serial logging** — event-driven diagnostics

Sensor thresholds are **auto-calibrated** at boot and treated as a trust boundary in Phase 3.

---

## Custody Roles
- **WHITE tag (Admin / Sealer / Receiver)**  
  Seals the asset at origin and receives it at destination.  
  *Not authorized to transport.*

- **BLUE tag (Handler / Courier)**  
  Takes custody and may transport the sealed asset.  
  *Not authorized to open the enclosure.*

---

## Project Phases

| Phase       | Focus                                                     |
|-------------|-----------------------------------------------------------|
| **Phase 1** | Hardware bring-up & baseline sensing                      |
| **Phase 2** | Custody model, roles, and violation rules                 |
| **Phase 3** | State machine enforcement & real-time violation detection |
| **Phase 4** | Stealth UI, forensic logging, integrity hardening         |
| **Phase 5** | Threat simulation & adversarial testing                   |
| **Phase 6** | Final validation, documentation, and demo                 |

---

## Current Status — Phase 3 Complete
Phase 3 implements a **finite state machine (FSM)** that enforces custody integrity *after sealing*.

It detects:
- motion without custody
- seal breaches via light exposure
- failed or incomplete handovers
- unauthorized state transitions

Phase 3 deliberately focuses on **enforcement**, not attribution or stealth.

Detailed Phase 3 documentation:  
 [`docs/phase3_state_machine_enforcement.md.txt`](docs/phase3_state_machine_enforcement.md.txt)

---

## Scope & Threat Model (High Level)
Phase 3 assumes:
- a trusted sealing action
- token-based RFID credentials
- no protection prior to sealing

These assumptions are explicitly documented and hardened in Phase 4.

---

## Roadmap (Phase 4 Preview)
Phase 4 extends the system with:
- non-revealing (stealth) UI behavior
- append-only, tamper-evident custody logs
- calibration hardening & sanity bounds
- MFA and multi-party authorization
- post-incident forensic reconstruction

---

## Disclaimer
This project is a **research and learning prototype** intended to explore custody enforcement, cyber-physical security, and forensic integrity concepts.  
It is not a production security device.
