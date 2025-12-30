# Chain-of-Custody Violation Detection System (CoC-VDS)

**CoC-VDS** is a **cyber-physical security prototype** designed for the **Arduino Uno R4 WiFi**. It is engineered to protect high-value assets during transport (e.g., Factory → Courier → Data Center) by **enforcing strict custody protocols**.

Most security systems ask: *“Was the box opened?”* **CoC-VDS** asks: **“Was the person holding the box authorized to open it at that exact time?”**

---

**The Core Philosophy**
In digital forensics and high-stakes hardware supply chains, an asset can remain physically intact but still be **legally compromised** if the chain of custody is broken.

Traditional tamper-evident seals are reactive and "loud." **CoC-VDS is proactive and silent**. It models the transport process itself, enforcing who is allowed to access the asset, when they can do it, and under what conditions. If a rule is broken, the system doesn't scream; it silently records an immutable forensic record.

---

**How It Works**
The system acts as a **Silent Witness** by correlating three data streams:

**Identity:** RFID-based role enforcement (Admin vs. Courier).

**Environment:** Light (LDR) and Motion (IMU) sensing.

**State:** A "fail-closed" state machine that only permits authorized transitions.

---

**Role Breakdown**
**WHITE Tag (Admin/Receiver):** Authorized to seal, unseal, and service the asset. Not authorized to transport.

**BLUE Tag (Courier/Handler):** Authorized to take custody and transport the sealed unit. **Never authorized to open it.**

---

**Advanced Security Features (Phase 4)**
Phase 4 transitioned the project from a simple monitor to a forensic-grade security device:

**Stealth UI:** The OLED mimics a standard, boring "Shipping Label." It provides zero feedback to an attacker during a breach.

**Cryptographic Chaining:** Every log entry is **HMAC-SHA256 signed** and chained to the previous record. This makes it mathematically impossible to delete or reorder history without detection.

**Hardware-Bound Keys:** Keys are derived from the **Uno R4 Silicon Unique ID**, ensuring the firmware (and its logs) cannot be cloned to another device.

**Offline Audit Portal:** A device-hosted WiFi SoftAP allows auditors to extract signed reports and CSV data without needing a cloud connection or external apps.

---

**Live Demonstrations**
1. **The "Sneaky Courier" (End-to-End Logic)**
This is the primary operational demo. An Admin seals the unit, and a Courier takes custody. While "In Transit," the courier pries the lid to peek inside. The system provides **no feedback,** but silently logs a **High-Severity Violation**. The breach is only revealed when the Admin performs an audit.

2. **The "Bit-Flip" (Cryptographic Integrity)**
This demo proves the math works. Using a dedicated serial command, we manually flip a single bit in the EEPROM—simulating physical memory tampering. The Audit Report immediately flags the **exact record** where the HMAC check failed, marking the entire chain as **FAILED.**

---

**Adversarial Simulation Suite**
The repository includes specialized builds to test the system against sophisticated attacks:

**Data Integrity:** Per-record HMAC-SHA256 validation.

**History Continuity:**  Hash-chain link verification (detects record deletion/reordering).

**Transfer Integrity:** (Roadmap) Browser-side SHA-256 verification of exported data.

---

**Repository Roadmap**
![COC_VDS Final Build-Phase 4 Hardened](src/coc_vds_forensic-engine/) : The "Production" firmware including Stealth UI and Chaining.

![Adversarial Build](demos/) : Adversarial builds for bit-flip and reordering/delete tests.

![Technical Documentation](docs/) : Technical deep-dives into the state machine and crypto-implementation.

---

**Future Work**
**Temporal Resilience:** Integrating a battery-backed RTC for absolute timestamping during power loss.

**Multi-Party Authorization:** Requiring two distinct Admin tags to "unlock" high-privilege states.

**Hardware Root of Trust:** Moving key storage to a dedicated Secure Element (e.g., ATECC608).

---

**Disclaimer**
This is a research prototype exploring the intersection of embedded systems and forensic integrity. While it uses professional-grade cryptographic principles, it is intended for educational and demonstrative purposes, not for production security environments.

**Security isn't about being loud. It's about being certain.**
