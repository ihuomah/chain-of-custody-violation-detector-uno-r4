/*
 * This is a demo build for adversarial testing.
 * Project: CoC-VDS Adversarial Suite
 * Version: 1.0 (Bit-Flip Simulation)
 * Author: Chinyere Ihuoma Uwa (Kyma)
 * Date: December 2025
 * * Description:
 * This is an adversarial test build designed to validate the 
 * CoC-VDS Forensic Engine's HMAC-SHA256 integrity checks.
 * * Simulation: Low-level EEPROM bit-flipping to trigger forensic alerts.
 *
 * 
 *  Serial commands to enter/exit AUDIT MODE cleanly from DEMO flow
 *    Commands (Serial Monitor):
 *      HELP
 *      A                 -> toggle AUDIT MODE (same as triple-tap)
 *      AUDIT             -> toggle AUDIT MODE
 *      AUDIT ON          -> force AUDIT MODE ON (starts AP + portal)
 *      AUDIT OFF         -> force AUDIT MODE OFF (stops AP + portal)
 *      DEMO EXIT         -> disarm demo mode (stops demo commands)
 *
 * 
 */

#include <Wire.h>
#include <Adafruit_GFX.h>
#include <Adafruit_SSD1306.h>
#include <SPI.h>
#include <MFRC522.h>
#include <MPU6050.h>
#include <EEPROM.h>

#include <Crypto.h>
#include <SHA256.h>
#include <stddef.h>
#include <string.h>

#include <WiFiS3.h>


static const bool DEBUG_MODE = true;
static const bool STEALTH_DEMO_HINTS = false;

// =========================================================
//                  DEMO SETTINGS
// =========================================================
#define DEMO_ENABLE 1  // set  1 in demo builds

// Pick ONE demo per demo build:
#define DEMO1_EEPROM_MODIFY 1  // Keep this to 1 to enable Demo 1 (bit-flip record)
#define DEMO2_DELETE_REORDER 0 // Keep this to 1 or 0 to disable if not used in this build

// Future demos DISABLED - (Safe to delete these lines entirely) 
// #define DEMO3_CSV_TAMPER 0
// #define DEMO5_POWER_LOSS 0

// Optional: add boot-time log repair (recommended for Demo 5 & production-hardening)
#define DEMO_REPAIR_TRUNCATE_INVALID 1

// Safety: require "DEMO ARM" before running demos
static bool demoArmed = false;


#define SCREEN_WIDTH 128
#define SCREEN_HEIGHT 64
#define OLED_RESET -1
Adafruit_SSD1306 display(SCREEN_WIDTH, SCREEN_HEIGHT, &Wire, OLED_RESET);


#define RFID_SS 10
#define RFID_RST 9
MFRC522 rfid(RFID_SS, RFID_RST);


#define LDR_PIN A0
MPU6050 imu;


#define VIOLATION_LED_PIN 7


static const char UID_ADMIN[] = "AAAAAAAA"; // Replace with your own admin / White card UID
static const char UID_HANDLER[] = "BBBBBBBB"; // Replace with your own handler / Blue tag UID


int LIGHT_THRESHOLD = 120;
long MOTION_THRESHOLD = 22000;


const unsigned long DOUBLE_TAP_WINDOW_MS = 3000;
const unsigned long TRANSFER_WINDOW_MS = 60000;


static unsigned long lastViolationLoggedMs = 0;
static const unsigned long VIOLATION_DEBOUNCE_MS = 1500;


static unsigned long lastRfidAcceptMs = 0;
static const unsigned long RFID_DEBOUNCE_MS = 650;


static uint8_t adminTapCount = 0;
static unsigned long adminTapWindowStartMs = 0;
static const unsigned long ADMIN_TAP_WINDOW_MS = 5000;


static unsigned long clearArmUntilMs = 0;
static const unsigned long CLEAR_ARM_WINDOW_MS = 60000;


enum State : uint8_t {
  UNINITIALIZED,
  SEALED_IDLE,
  IN_CUSTODY,
  TRANSFER_WINDOW,
  RECEIVED_FINAL,
  ADMIN_OPEN_STATE
};
State state = UNINITIALIZED;


enum Custodian : uint8_t { CUST_NONE = 0,
                           CUST_HANDLER = 1,
                           CUST_RECEIVER = 2 };
Custodian currentCustodian = CUST_NONE;


unsigned long transferStartMs = 0;
unsigned long lastHandlerScanMs = 0;
bool handlerArmedForDoubleTap = false;


static bool journeyCompromised = false;
static bool auditMode = false;



// Event codes
static const uint8_t EVT_BOOT = 0x10;
static const uint8_t EVT_CAL_SEAL_BASELINE = 0x11;

static const uint8_t EVT_SEALED = 0x20;
static const uint8_t EVT_SEAL_REFUSED = 0x42;

static const uint8_t EVT_CUSTODY_TAKEN = 0x21;
static const uint8_t EVT_TRANSFER_WINDOW_OPEN = 0x22;
static const uint8_t EVT_RECEIVED_FINAL = 0x23;

static const uint8_t EVT_ADMIN_OPEN = 0x30;
static const uint8_t EVT_ADMIN_RESEAL = 0x31;

static const uint8_t EVT_VIOLATION = 0xE0;

static const uint8_t EVT_LOG_EXPORT = 0xF0;
static const uint8_t EVT_LOG_CLEARED = 0xF1;

static const uint8_t EVT_TIME_SYNC = 0x60;

// Violation reason codes 
static const uint32_t V_LIGHT_EXPOSURE = 0x01;
static const uint32_t V_MOTION_NO_CUST = 0x02;
static const uint32_t V_XFER_EXPIRED = 0x03;

// Severity tags in flags
static const uint16_t SEV_INFO = 0x0001;
static const uint16_t SEV_WARN = 0x0002;
static const uint16_t SEV_HIGH = 0x0003;
static const uint16_t SEV_CRITICAL = 0x0004;

// Your Uno R4 Unique Device ID (hex string)
// Run the 'hardware-uid-provisioning' tool in /tools to find your device's ID.
static const char UNO_R4_UID_HEX[] = "00000000000000000000000000000000";

// Master secret used to derive device-unique keys.
// NOTE: In a production environment, this would be stored in a Hardware 
// Secure Element (HSM) rather than source code. 
static const uint8_t MASTER_SECRET[] = {
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

static uint8_t DERIVED_KEY[32];
static uint8_t KEY_ID16[16];


static const uint16_t EEPROM_BYTES = 8192;
static const uint16_t META_ADDR = 0;
static const uint16_t META_SIZE = 64;
static const uint16_t LOG_BASE = META_ADDR + META_SIZE;

static const uint16_t REC_SIZE = 100;
static const uint16_t MAX_RECORDS = (EEPROM_BYTES - LOG_BASE) / REC_SIZE;


static const uint16_t SEAL_REFUSE_MARGIN_SLOTS = 3;


struct LogMeta {
  uint32_t magic;   // "C4LG" = 0x43344C47
  uint8_t version;  // 1
  uint8_t recSize;  // 100
  uint16_t maxRecords;

  uint16_t writeIndex;
  uint16_t recordCount;
  uint16_t bootCounter;
  uint16_t reserved;

  uint8_t lastHmac[32];
};
static LogMeta meta;
static uint16_t g_bootId = 0;


#pragma pack(push, 1)
struct LogRecord {
  uint8_t version;
  uint8_t event;
  uint16_t flags;
  uint16_t boot_id;
  uint16_t seq;
  uint32_t uptime_s;

  uint32_t tag_id;
  uint32_t data1;
  uint32_t data2;

  uint8_t prev_hmac[32];
  uint8_t hmac[32];

  uint8_t valid;  // 0xA5 committed
};
#pragma pack(pop)

static_assert(sizeof(LogRecord) <= REC_SIZE, "LogRecord too big");


enum ChainFailReason : uint8_t {
  CHAIN_OK = 0,
  FAIL_PREV_LINK = 1,
  FAIL_RECORD_HMAC = 2
};

static void verifyChainAndMaster(uint8_t masterOut[32],
                                 bool& chainOk,
                                 int& firstBadIndex,
                                 ChainFailReason& failReason);


static const char* chainFailTextC(ChainFailReason r);


static inline void eepromReadBlock(uint16_t addr, uint8_t* out, uint16_t len) {
  for (uint16_t i = 0; i < len; i++) out[i] = EEPROM.read(addr + i);
}
static inline void eepromWriteBlock(uint16_t addr, const uint8_t* in, uint16_t len) {
  for (uint16_t i = 0; i < len; i++) EEPROM.update(addr + i, in[i]);
}


static uint8_t hexNibble(char c) {
  if (c >= '0' && c <= '9') return (uint8_t)(c - '0');
  if (c >= 'a' && c <= 'f') return (uint8_t)(c - 'a' + 10);
  if (c >= 'A' && c <= 'F') return (uint8_t)(c - 'A' + 10);
  return 0;
}
static uint8_t hexToBytes(const char* hex, uint8_t* out, uint8_t maxOut) {
  uint8_t n = 0;
  while (*hex && *(hex + 1) && n < maxOut) {
    out[n++] = (hexNibble(hex[0]) << 4) | hexNibble(hex[1]);
    hex += 2;
  }
  return n;
}


static void hmac_sha256(const uint8_t* key, size_t keyLen,
                        const uint8_t* msg, size_t msgLen,
                        uint8_t out[32]) {
  const size_t BLOCK = 64;
  uint8_t k0[BLOCK];
  memset(k0, 0, BLOCK);

  if (keyLen > BLOCK) {
    SHA256 sha;
    sha.reset();
    sha.update(key, keyLen);
    sha.finalize(k0, 32);
  } else {
    memcpy(k0, key, keyLen);
  }

  uint8_t ipad[BLOCK], opad[BLOCK];
  for (size_t i = 0; i < BLOCK; i++) {
    ipad[i] = k0[i] ^ 0x36;
    opad[i] = k0[i] ^ 0x5C;
  }

  uint8_t inner[32];
  SHA256 sha;
  sha.reset();
  sha.update(ipad, BLOCK);
  sha.update(msg, msgLen);
  sha.finalize(inner, 32);

  sha.reset();
  sha.update(opad, BLOCK);
  sha.update(inner, 32);
  sha.finalize(out, 32);
}


static void deriveKey() {
  uint8_t uidBytes[32];
  uint8_t uidLen = hexToBytes(UNO_R4_UID_HEX, uidBytes, sizeof(uidBytes));

  SHA256 sha;
  sha.reset();
  sha.update(uidBytes, uidLen);
  sha.update(MASTER_SECRET, sizeof(MASTER_SECRET));
  sha.finalize(DERIVED_KEY, 32);

  uint8_t tmp[32];
  sha.reset();
  sha.update(DERIVED_KEY, 32);
  sha.finalize(tmp, 32);
  memcpy(KEY_ID16, tmp, 16);
}

// Compact UID hash (FNV-1a)
static uint32_t fnv1a32_bytes(const uint8_t* data, uint8_t len) {
  uint32_t h = 2166136261u;
  for (uint8_t i = 0; i < len; i++) {
    h ^= data[i];
    h *= 16777619u;
  }
  return h;
}


static void saveMeta() {
  eepromWriteBlock(META_ADDR, (uint8_t*)&meta, sizeof(LogMeta));
}
static void loadMetaOrInit() {
  eepromReadBlock(META_ADDR, (uint8_t*)&meta, sizeof(LogMeta));
  if (meta.magic != 0x43344C47u || meta.version != 1 || meta.recSize != (uint8_t)REC_SIZE || meta.maxRecords != MAX_RECORDS) {
    memset(&meta, 0, sizeof(meta));
    meta.magic = 0x43344C47u;
    meta.version = 1;
    meta.recSize = (uint8_t)REC_SIZE;
    meta.maxRecords = MAX_RECORDS;
    meta.writeIndex = 0;
    meta.recordCount = 0;
    meta.bootCounter = 0;
    memset(meta.lastHmac, 0, 32);
    saveMeta();
    if (DEBUG_MODE) {
      Serial.print("[LOG] Rebuilt meta. recordCount=");
      Serial.println(meta.recordCount);
    }
  }
}

static uint16_t remainingSlots() {
  if (meta.maxRecords <= meta.recordCount) return 0;
  return (meta.maxRecords - meta.recordCount);
}
static bool logHasSpaceForNewJourney() {
  uint16_t rem = remainingSlots();
  uint16_t tenPct = (uint16_t)(meta.maxRecords / 10);
  uint16_t threshold = (tenPct > SEAL_REFUSE_MARGIN_SLOTS) ? tenPct : SEAL_REFUSE_MARGIN_SLOTS;
  return rem > threshold;
}


static bool appendRecord(uint8_t event, uint32_t tagId, uint32_t data1, uint32_t data2, uint16_t flags = 0) {
  if (meta.recordCount >= meta.maxRecords) return false;

  LogRecord r;
  memset(&r, 0, sizeof(r));
  r.version = 1;
  r.event = event;
  r.flags = flags;
  r.boot_id = g_bootId;
  r.seq = meta.recordCount;
  r.uptime_s = (uint32_t)(millis() / 1000UL);
  r.tag_id = tagId;
  r.data1 = data1;
  r.data2 = data2;
  memcpy(r.prev_hmac, meta.lastHmac, 32);
  r.valid = 0x00;

  const uint8_t* raw = (const uint8_t*)&r;
  const size_t hmacLen = offsetof(LogRecord, hmac);
  hmac_sha256(DERIVED_KEY, 32, raw, hmacLen, r.hmac);

  uint16_t addr = LOG_BASE + (meta.writeIndex * REC_SIZE);
  eepromWriteBlock(addr, (uint8_t*)&r, sizeof(LogRecord));
  EEPROM.update(addr + offsetof(LogRecord, valid), 0xA5);

  memcpy(meta.lastHmac, r.hmac, 32);
  meta.writeIndex++;
  meta.recordCount++;
  saveMeta();
  return true;
}

static bool readRecord(uint16_t i, LogRecord& out) {
  if (i >= meta.recordCount) return false;
  uint16_t addr = LOG_BASE + (i * REC_SIZE);
  eepromReadBlock(addr, (uint8_t*)&out, sizeof(LogRecord));
  return (out.valid == 0xA5);
}

static void computeRecordHmac(const LogRecord& r, uint8_t out32[32]) {
  const uint8_t* raw = (const uint8_t*)&r;
  const size_t hmacLen = offsetof(LogRecord, hmac);
  hmac_sha256(DERIVED_KEY, 32, raw, hmacLen, out32);
}

// =========================================================
//     CHAIN VERIFICATION: show where it broke + why
// =========================================================
static void verifyChainAndMaster(uint8_t masterOut[32],
                                 bool& chainOk,
                                 int& firstBadIndex,
                                 ChainFailReason& failReason) {
  chainOk = true;
  firstBadIndex = -1;
  failReason = CHAIN_OK;

  SHA256 bundle;
  bundle.reset();

  uint8_t prev[32];
  memset(prev, 0, 32);

  for (uint16_t i = 0; i < meta.recordCount; i++) {
    LogRecord r;
    if (!readRecord(i, r)) continue;

    if (memcmp(r.prev_hmac, prev, 32) != 0 && chainOk) {
      chainOk = false;
      firstBadIndex = (int)i;
      failReason = FAIL_PREV_LINK;
    }

    uint8_t recomputed[32];
    computeRecordHmac(r, recomputed);
    if (memcmp(recomputed, r.hmac, 32) != 0 && chainOk) {
      chainOk = false;
      firstBadIndex = (int)i;
      failReason = FAIL_RECORD_HMAC;
    }

    memcpy(prev, r.hmac, 32);
    bundle.update((const uint8_t*)&r, sizeof(LogRecord));
  }

  uint8_t bundleDigest[32];
  bundle.finalize(bundleDigest, 32);
  hmac_sha256(DERIVED_KEY, 32, bundleDigest, 32, masterOut);
}



static void demo1_modifyRecord(uint16_t targetIndex);


static uint16_t recAddr(uint16_t i) {
  return (uint16_t)(LOG_BASE + (i * REC_SIZE));
}


static void eepromXorByte(uint16_t addr, uint8_t mask) {
  uint8_t v = EEPROM.read(addr);
  EEPROM.update(addr, (uint8_t)(v ^ mask));
}


static void demoPrintChainStatus() {
  uint8_t master[32];
  bool ok;
  int bad;
  ChainFailReason why;
  verifyChainAndMaster(master, ok, bad, why);

  Serial.print("[DEMO] Chain: ");
  if (ok) Serial.println("VERIFIED");
  else {
    Serial.print("FAILED at #");
    Serial.print(bad);
    Serial.print(" reason=");
    Serial.println(chainFailTextC(why));
  }
}


static void repairTruncateInvalid() {
#if DEMO_REPAIR_TRUNCATE_INVALID
  uint16_t firstBad = meta.recordCount;  
  for (uint16_t i = 0; i < meta.recordCount; i++) {
    uint16_t addr = recAddr(i);
    uint8_t v = EEPROM.read(addr + offsetof(LogRecord, valid));
    if (v != 0xA5) {
      firstBad = i;
      break;
    }
  }

  if (firstBad < meta.recordCount) {
    Serial.print("[REPAIR] Truncating log from ");
    Serial.print(meta.recordCount);
    Serial.print(" -> ");
    Serial.println(firstBad);

    if (firstBad == 0) {
      memset(meta.lastHmac, 0, 32);
    } else {
      LogRecord r;
      readRecord((uint16_t)(firstBad - 1), r);
      memcpy(meta.lastHmac, r.hmac, 32);
    }

    meta.recordCount = firstBad;
    meta.writeIndex = firstBad;
    saveMeta();
  }
#endif
}


static void printHelp() {
  Serial.println("Commands:");
  Serial.println("  HELP               -> show this list");
  Serial.println("  A                  -> toggle AUDIT MODE (AP portal on/off)");
  Serial.println("  AUDIT              -> toggle AUDIT MODE");
  Serial.println("  AUDIT ON           -> force AUDIT MODE ON");
  Serial.println("  AUDIT OFF          -> force AUDIT MODE OFF");
  Serial.println("  DEMO ARM           -> arm demo commands");
  Serial.println("  DEMO1              -> run demo #1 (if enabled)");
  Serial.println("  STATUS             -> print chain status");
  Serial.println("  DEMO DISARM        -> disarm demo commands");
  Serial.println("  DEMO EXIT          -> alias for DEMO DISARM");
  Serial.println("Tip: After AUDIT ON, connect to AP + open http://192.168.4.1/report");
}

static void handleDemoSerial() {
#if DEMO_ENABLE
  static String line;

  while (Serial.available()) {
    char c = (char)Serial.read();
    if (c == '\r') continue;

    if (c != '\n') {
      line += c;
      if (line.length() > 140) line.remove(0, line.length() - 140);
      continue;
    }

    
    line.trim();
    if (!line.length()) {
      line = "";
      continue;
    }

    
    if (line.equalsIgnoreCase("HELP") || line.equalsIgnoreCase("?")) {
      printHelp();
      line = "";
      continue;
    }

    if (line.equalsIgnoreCase("A") || line.equalsIgnoreCase("AUDIT")) {
      setAuditMode(!auditMode);
      Serial.print("[SERIAL] AUDIT MODE -> ");
      Serial.println(auditMode ? "ON (portal started)" : "OFF (portal stopped)");
      line = "";
      continue;
    }

    if (line.equalsIgnoreCase("AUDIT ON")) {
      setAuditMode(true);
      Serial.println("[SERIAL] AUDIT MODE forced ON (portal started)");
      line = "";
      continue;
    }

    if (line.equalsIgnoreCase("AUDIT OFF")) {
      setAuditMode(false);
      Serial.println("[SERIAL] AUDIT MODE forced OFF (portal stopped)");
      line = "";
      continue;
    }

    if (line.equalsIgnoreCase("DEMO EXIT")) {
      demoArmed = false;
      Serial.println("[DEMO] Disarmed (exit). You can now use AUDIT ON for the web UI.");
      line = "";
      continue;
    }

    // ---- Demo commands ----
    if (line.equalsIgnoreCase("DEMO ARM")) {
      demoArmed = true;
      Serial.println("[DEMO] Armed. Commands: DEMO1, STATUS, DEMO DISARM");
      Serial.println("       Tip: Type AUDIT ON anytime to open the web portal.");
      line = "";
      continue;
    }

    if (line.equalsIgnoreCase("DEMO DISARM") || line.equalsIgnoreCase("DISARM")) {
      demoArmed = false;
      Serial.println("[DEMO] Disarmed.");
      line = "";
      continue;
    }

    if (line.equalsIgnoreCase("STATUS") || line.equalsIgnoreCase("DEMO STATUS")) {
      demoPrintChainStatus();
      line = "";
      continue;
    }

    if (!demoArmed) {
      Serial.println("[DEMO] Ignored (not armed). Type: DEMO ARM");
      Serial.println("       Or use: AUDIT ON  (to open the web UI portal)");
      line = "";
      continue;
    }

#if DEMO1_EEPROM_MODIFY
    if (line.equalsIgnoreCase("DEMO1")) {
      demo1_modifyRecord(2);
      Serial.println("[DEMO] Tip: now type AUDIT ON to open /report and explain the failure visually.");
      line = "";
      continue;
    }
#endif

    Serial.println("[DEMO] Unknown command. Type HELP.");
    line = "";
  }
#endif
}

// =========================================================
// DEMO 1: Modify a byte inside a valid record (HMAC mismatch)
// =========================================================
static void demo1_modifyRecord(uint16_t targetIndex) {
#if DEMO_ENABLE && DEMO1_EEPROM_MODIFY
  if (meta.recordCount == 0) {
    Serial.println("[DEMO1] No records.");
    return;
  }
  if (targetIndex >= meta.recordCount) targetIndex = (uint16_t)(meta.recordCount / 2);

  uint16_t addr = recAddr(targetIndex);

  // Flip one bit inside data1 field
  uint16_t flipAddr = (uint16_t)(addr + offsetof(LogRecord, data1));
  eepromXorByte(flipAddr, 0x01);

  Serial.print("[DEMO1] Modified record #");
  Serial.print(targetIndex);
  Serial.println(" (flipped 1 bit in data1).");

  demoPrintChainStatus();
#endif
}

// =========================================================
//            TIME SYNC / EPOCH CALCULATION
// =========================================================

struct BootEpochCache {
  uint16_t boot_id;
  int32_t epochMinusUptime;
  bool valid;
};
static BootEpochCache bootEpochCache[10];

static void cacheInit() {
  for (int i = 0; i < 10; i++) {
    bootEpochCache[i].valid = false;
    bootEpochCache[i].boot_id = 0;
    bootEpochCache[i].epochMinusUptime = 0;
  }
}

static bool getEpochMinusUptimeForBoot(uint16_t bootId, int32_t& out) {
  for (int i = 0; i < 10; i++) {
    if (bootEpochCache[i].valid && bootEpochCache[i].boot_id == bootId) {
      out = bootEpochCache[i].epochMinusUptime;
      return true;
    }
  }
  for (uint16_t i = 0; i < meta.recordCount; i++) {
    LogRecord r;
    if (!readRecord(i, r)) continue;
    if (r.boot_id != bootId) continue;
    if (r.event != EVT_TIME_SYNC) continue;

    uint32_t epoch = r.data1;
    uint32_t upS = r.data2;
    int32_t offset = (int32_t)epoch - (int32_t)upS;

    for (int k = 0; k < 10; k++) {
      if (!bootEpochCache[k].valid) {
        bootEpochCache[k].valid = true;
        bootEpochCache[k].boot_id = bootId;
        bootEpochCache[k].epochMinusUptime = offset;
        break;
      }
    }
    out = offset;
    return true;
  }
  return false;
}

static String isoUtc(uint32_t epoch) {
  uint32_t t = epoch;
  uint32_t sec = t % 60;
  t /= 60;
  uint32_t min = t % 60;
  t /= 60;
  uint32_t hour = t % 24;
  t /= 24;

  int64_t z = (int64_t)t + 719468;
  int64_t era = (z >= 0 ? z : z - 146096) / 146097;
  uint32_t doe = (uint32_t)(z - era * 146097);
  uint32_t yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
  int64_t y = (int64_t)yoe + era * 400;
  uint32_t doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
  uint32_t mp = (5 * doy + 2) / 153;
  uint32_t d = doy - (153 * mp + 2) / 5 + 1;
  uint32_t m = mp + (mp < 10 ? 3 : -9);
  y += (m <= 2);

  char buf[32];
  snprintf(buf, sizeof(buf), "%04ld-%02u-%02u %02u:%02u:%02uZ",
           (long)y, (unsigned)m, (unsigned)d,
           (unsigned)hour, (unsigned)min, (unsigned)sec);
  return String(buf);
}

static bool recordEpoch(const LogRecord& r, uint32_t& outEpoch) {
  int32_t offset;
  if (!getEpochMinusUptimeForBoot(r.boot_id, offset)) return false;
  outEpoch = (uint32_t)((int64_t)offset + (int64_t)r.uptime_s);
  return true;
}

// =========================================================
// Persistent forensic memory + infer last state
// =========================================================
static void reconstructFromLog() {
  journeyCompromised = false;

  uint8_t lastEvent = 0;
  for (uint16_t i = 0; i < meta.recordCount; i++) {
    LogRecord r;
    if (!readRecord(i, r)) continue;
    lastEvent = r.event;
    if (r.event == EVT_VIOLATION) journeyCompromised = true;
  }

  switch (lastEvent) {
    case EVT_CUSTODY_TAKEN:
      state = IN_CUSTODY;
      currentCustodian = CUST_HANDLER;
      break;
    case EVT_TRANSFER_WINDOW_OPEN:
      state = TRANSFER_WINDOW;
      currentCustodian = CUST_HANDLER;
      break;
    case EVT_SEALED:
    case EVT_ADMIN_RESEAL:
      state = SEALED_IDLE;
      currentCustodian = CUST_NONE;
      break;
    case EVT_RECEIVED_FINAL:
      state = RECEIVED_FINAL;
      currentCustodian = CUST_RECEIVER;
      break;
    default: break;
  }
}


static long readMotionMagnitude() {
  int16_t ax, ay, az;
  imu.getAcceleration(&ax, &ay, &az);
  return (long)abs(ax) + (long)abs(ay) + (long)abs(az);
}
static int readLight() {
  return analogRead(LDR_PIN);
}

static bool readUidIfPresent(uint8_t uidBytes[10], uint8_t& uidLen, char uidHexOut[21]) {
  uidLen = 0;
  uidHexOut[0] = '\0';

  if (!rfid.PICC_IsNewCardPresent()) return false;
  if (!rfid.PICC_ReadCardSerial()) return false;

  uidLen = rfid.uid.size;
  for (uint8_t i = 0; i < uidLen; i++) uidBytes[i] = rfid.uid.uidByte[i];

  static const char* hexd = "0123456789abcdef";
  for (uint8_t i = 0; i < uidLen; i++) {
    uidHexOut[i * 2] = hexd[(uidBytes[i] >> 4) & 0xF];
    uidHexOut[i * 2 + 1] = hexd[uidBytes[i] & 0xF];
  }
  uidHexOut[uidLen * 2] = '\0';

  rfid.PICC_HaltA();
  rfid.PCD_StopCrypto1();
  return true;
}

static bool isAdminHex(const char* uidHex) {
  return (strcmp(uidHex, UID_ADMIN) == 0);
}
static bool isHandlerHex(const char* uidHex) {
  return (strcmp(uidHex, UID_HANDLER) == 0);
}

// =========================================================
//                  FORENSIC VIOLATION LOGGING
// =========================================================
static void logViolationOnce(uint32_t reasonCode, int lightVal, long motionVal) {
  journeyCompromised = true;

  unsigned long now = millis();
  if (now - lastViolationLoggedMs < VIOLATION_DEBOUNCE_MS) return;
  lastViolationLoggedMs = now;

  uint32_t packed = ((uint32_t)(lightVal & 0xFFFF) << 16) | (uint32_t)(motionVal & 0xFFFF);
  appendRecord(EVT_VIOLATION, 0, reasonCode, packed, SEV_HIGH);

  if (DEBUG_MODE) {
    Serial.print("[VIOLATION] reason=0x");
    Serial.print(reasonCode, HEX);
    Serial.print(" light=");
    Serial.print(lightVal);
    Serial.print(" motion=");
    Serial.println(motionVal);
  }
}


static void drawShippingLabel(bool maintenanceReq) {
  display.clearDisplay();
  display.drawRect(0, 0, 128, 64, SSD1306_WHITE);

  display.fillRect(2, 2, 124, 12, SSD1306_WHITE);
  display.setTextColor(SSD1306_BLACK);
  display.setCursor(6, 5);
  display.print("COC SHIPMENT");
  display.setTextColor(SSD1306_WHITE);

  display.setCursor(6, 18);
  display.print("STATUS: ");
  if (maintenanceReq) display.print("MAINTENANCE REQ");
  else {
    if (state == UNINITIALIZED) display.print("READY");
    else if (state == SEALED_IDLE) display.print("SEALED");
    else if (state == IN_CUSTODY) display.print("IN TRANSIT");
    else if (state == TRANSFER_WINDOW) display.print("DELIVERY");
    else if (state == RECEIVED_FINAL) display.print("RECEIVED");
    else if (state == ADMIN_OPEN_STATE) display.print("SERVICE");
    else display.print("OK");
  }

  for (int x = 6; x < 122; x += 3) {
    int h = (x % 9 == 0) ? 18 : 14;
    display.drawLine(x, 42, x, 42 + h, SSD1306_WHITE);
  }

  display.drawRect(6, 36, 116, 6, SSD1306_WHITE);
  int pct = 0;
  if (state == UNINITIALIZED) pct = 5;
  else if (state == SEALED_IDLE) pct = 20;
  else if (state == IN_CUSTODY) pct = 55;
  else if (state == TRANSFER_WINDOW) pct = 85;
  else if (state == RECEIVED_FINAL) pct = 100;
  int fillW = (int)(114 * pct / 100);
  display.fillRect(7, 37, fillW, 4, SSD1306_WHITE);

  display.setCursor(6, 56);
  display.print("Transit: ");
  display.print(pct);
  display.print("%");
  display.display();
}

static void drawAuditScreen(int lightVal, long motionVal) {
  display.clearDisplay();
  display.setCursor(0, 0);
  display.print("AUDIT MODE");

  display.setCursor(0, 12);
  display.print("Logs: ");
  display.print(meta.recordCount);
  display.print("/");
  display.print(meta.maxRecords);

  if (STEALTH_DEMO_HINTS) {
    display.setCursor(0, 26);
    display.print("L:");
    display.print(lightVal);
    display.print(" M:");
    display.print((int)(motionVal & 0xFFFF));
  }

  display.display();
}


static void calibrateBaseline() {
  const int samples = 40;
  long lightSum = 0;
  long motionSum = 0;

  for (int i = 0; i < samples; i++) {
    lightSum += readLight();
    motionSum += readMotionMagnitude();
    delay(25);
  }

  int lightAvg = (int)(lightSum / samples);
  long motionAvg = (long)(motionSum / samples);

  LIGHT_THRESHOLD = lightAvg + 80;
  if (LIGHT_THRESHOLD > 1023) LIGHT_THRESHOLD = 1023;
  MOTION_THRESHOLD = motionAvg + 4000;

  if (DEBUG_MODE) {
    Serial.print("[BASELINE] light_avg=");
    Serial.print(lightAvg);
    Serial.print(" motion_avg=");
    Serial.println(motionAvg);

    Serial.print("[THRESH] LIGHT_THRESHOLD=");
    Serial.print(LIGHT_THRESHOLD);
    Serial.print(" MOTION_THRESHOLD=");
    Serial.println(MOTION_THRESHOLD);
  }

  appendRecord(EVT_CAL_SEAL_BASELINE, 0, (uint32_t)lightAvg, (uint32_t)motionAvg, SEV_INFO);
}

// =========================================================
//                     WEB PORTAL (SoftAP)
// =========================================================
static WiFiServer server(80);
static bool portalRunning = false;

static const char PORTAL_PASS[] = "PASSWORD PLACEHOLDER"; // WiFi AP passcode
static const char CLEAR_PASSCODE[] = "0000"; // Audit clear passcode
static char apSsid[40];

static void httpBegin(WiFiClient& client, const char* statusLine, const char* contentType) {
  client.println(statusLine);
  client.print("Content-Type: ");
  client.println(contentType);
  client.println("Connection: close");
  client.println();
}

static void httpRedirect(WiFiClient& client, const char* location) {
  client.println("HTTP/1.1 302 Found");
  client.print("Location: ");
  client.println(location);
  client.println("Connection: close");
  client.println();
}

static String hex32(const uint8_t* b, int n) {
  const char* hexd = "0123456789ABCDEF";
  String s;
  s.reserve(n * 2);
  for (int i = 0; i < n; i++) {
    s += hexd[(b[i] >> 4) & 0xF];
    s += hexd[b[i] & 0xF];
  }
  return s;
}

static const char* eventNameC(uint8_t e) {
  switch (e) {
    case EVT_BOOT: return "BOOT";
    case EVT_CAL_SEAL_BASELINE: return "CAL_BASELINE";
    case EVT_SEALED: return "SHIPMENT_SEALED";
    case EVT_SEAL_REFUSED: return "SEAL_REFUSED";
    case EVT_CUSTODY_TAKEN: return "CUSTODY_TAKEN";
    case EVT_TRANSFER_WINDOW_OPEN: return "TRANSFER_WINDOW_OPEN";
    case EVT_RECEIVED_FINAL: return "RECEIVED_FINAL";
    case EVT_ADMIN_OPEN: return "ADMIN_OPEN";
    case EVT_ADMIN_RESEAL: return "ADMIN_RESEAL";
    case EVT_VIOLATION: return "VIOLATION";
    case EVT_LOG_EXPORT: return "LOG_EXPORT";
    case EVT_LOG_CLEARED: return "LOG_CLEARED";
    case EVT_TIME_SYNC: return "TIME_SYNC";
    default: return "UNKNOWN";
  }
}

static const char* violationReasonC(uint32_t code) {
  switch (code) {
    case V_LIGHT_EXPOSURE: return "LIGHT_EXPOSURE";
    case V_MOTION_NO_CUST: return "MOTION_WITHOUT_CUSTODY";
    case V_XFER_EXPIRED: return "TRANSFER_WINDOW_EXPIRED";
    default: return "UNKNOWN_REASON";
  }
}

static const char* sevNameC(uint16_t f) {
  switch (f) {
    case SEV_INFO: return "INFO";
    case SEV_WARN: return "WARN";
    case SEV_HIGH: return "HIGH";
    case SEV_CRITICAL: return "CRITICAL";
    default: return "UNK";
  }
}

static const char* chainFailTextC(ChainFailReason r) {
  switch (r) {
    case FAIL_PREV_LINK: return "prev_hmac mismatch (deletion/reorder)";
    case FAIL_RECORD_HMAC: return "record HMAC mismatch (bit-flip/edit)";
    default: return "unknown";
  }
}

static void startPortal() {
  if (portalRunning) return;

  const char* u = UNO_R4_UID_HEX;
  int n = strlen(u);
  const char* tail = (n >= 4) ? (u + (n - 4)) : u;
  snprintf(apSsid, sizeof(apSsid), "CoC-VDS-AUDIT-%s", tail);

  if (DEBUG_MODE) {
    Serial.print("[WIFI] Starting AP SSID=");
    Serial.print(apSsid);
    Serial.print(" PASS=");
    Serial.println(PORTAL_PASS);
  }

  WiFi.end();
  delay(200);

  int status = WiFi.beginAP(apSsid, PORTAL_PASS);
  delay(1000);
  if (status != WL_AP_LISTENING) {
    if (DEBUG_MODE) Serial.println("[WIFI] AP failed to start");
    return;
  }

  server.begin();
  portalRunning = true;

  if (DEBUG_MODE) {
    IPAddress ip = WiFi.localIP();
    Serial.print("[WIFI] AP IP: ");
    Serial.println(ip);
  }
}

static void stopPortal() {
  if (!portalRunning) return;
  server.end();
  WiFi.end();
  portalRunning = false;
  if (DEBUG_MODE) Serial.println("[WIFI] AP stopped");
}

static void setAuditMode(bool on) {
  auditMode = on;
  clearArmUntilMs = 0;
  if (DEBUG_MODE) {
    Serial.print("[AUDIT] ");
    Serial.println(auditMode ? "ON" : "OFF");
  }
  if (auditMode) startPortal();
  else stopPortal();
}

/
static void streamCsvExport(WiFiClient& client) {
  appendRecord(EVT_LOG_EXPORT, 0, 0, 0, SEV_INFO);

  httpBegin(client, "HTTP/1.1 200 OK", "text/csv");

  SHA256 sha;
  sha.reset();

  auto printAndHash = [&](const char* s) {
    client.print(s);
    sha.update((const uint8_t*)s, strlen(s));
  };

  const char* header = "record_index,boot_id,uptime_s,epoch_utc,event,event_name,severity,tag_id,data1,data2\n";
  printAndHash(header);

  for (uint16_t i = 0; i < meta.recordCount; i++) {
    LogRecord r;
    if (!readRecord(i, r)) continue;

    uint32_t ep;
    bool hasEp = recordEpoch(r, ep);

    char line[220];
    if (hasEp) {
      snprintf(line, sizeof(line),
               "%u,%u,%lu,%lu,0x%02X,%s,%s,0x%08lX,0x%08lX,0x%08lX\n",
               (unsigned)i,
               (unsigned)r.boot_id,
               (unsigned long)r.uptime_s,
               (unsigned long)ep,
               (unsigned)r.event,
               eventNameC(r.event),
               sevNameC(r.flags),
               (unsigned long)r.tag_id,
               (unsigned long)r.data1,
               (unsigned long)r.data2);
    } else {
      snprintf(line, sizeof(line),
               "%u,%u,%lu,,0x%02X,%s,%s,0x%08lX,0x%08lX,0x%08lX\n",
               (unsigned)i,
               (unsigned)r.boot_id,
               (unsigned long)r.uptime_s,
               (unsigned)r.event,
               eventNameC(r.event),
               sevNameC(r.flags),
               (unsigned long)r.tag_id,
               (unsigned long)r.data1,
               (unsigned long)r.data2);
    }

    printAndHash(line);
  }

  uint8_t digestBytes[32];
  sha.finalize(digestBytes, 32);
  String digestHex = hex32(digestBytes, 32);

  client.print("DIGEST,SHA256,");
  client.print(digestHex);
  client.print("\n");

  uint8_t master[32];
  bool chainOk;
  int badIndex;
  ChainFailReason failReason;
  verifyChainAndMaster(master, chainOk, badIndex, failReason);

  client.print("CHECKSUM,HMAC-SHA256,");
  client.print(hex32(master, 32));
  client.print(",");
  if (chainOk) client.print("CHAIN_VERIFIED\n");
  else {
    client.print("CHAIN_FAILED_AT_");
    client.print(badIndex);
    client.print(" (");
    client.print(chainFailTextC(failReason));
    client.print(")\n");
  }
}


static void streamReportHtml(WiFiClient& client) {
  appendRecord(EVT_LOG_EXPORT, 0, 0, 0, SEV_INFO);

  uint8_t master[32];
  bool chainOk;
  int badIndex;
  ChainFailReason failReason;
  verifyChainAndMaster(master, chainOk, badIndex, failReason);

  httpBegin(client, "HTTP/1.1 200 OK", "text/html");

  client.print("<html><head><meta charset='utf-8'>");
  client.print("<meta name='viewport' content='width=device-width, initial-scale=1'>");
  client.print("<title>CoC-VDS Audit Report</title></head>");
  client.print("<body style='font-family:system-ui,Segoe UI,Arial'>");
  client.print("<h2>CoC-VDS Signed Audit Report</h2>");

  client.print("<p><b>Device UID:</b> ");
  client.print(UNO_R4_UID_HEX);
  client.print("<br><b>Key Fingerprint (16):</b> ");
  client.print(hex32(KEY_ID16, 16));

  client.print("<br><b>Chain Integrity:</b> ");
  if (chainOk) {
    client.print("<span style='color:green;font-weight:800'>VERIFIED</span>");
  } else {
    client.print("<span style='color:red;font-weight:800'>FAILED</span>");
    client.print(" &mdash; Integrity lost at <b>Record #");

    client.print(badIndex);
    client.print("</b> (");
    client.print(chainFailTextC(failReason));
    client.print(")");
  }

  client.print("<br><b>Master HMAC (device authenticity):</b> ");
  client.print(hex32(master, 32));
  client.print("</p>");

  client.print("<p>");
  client.print("<a href='/'>Home</a> | ");
  client.print("<a href='/export.csv'>Download CSV</a> | ");
  client.print("<a href='/confirm-clear'>Export & Clear</a> | ");
  client.print("<a href='/report'>Refresh</a>");
  client.print("</p>");

  client.print("<hr><h3>Timeline</h3>");
  client.print("<pre style='background:#111;color:#eee;padding:12px;border-radius:10px;overflow:auto'>");

  for (uint16_t i = 0; i < meta.recordCount; i++) {
    LogRecord r;
    if (!readRecord(i, r)) continue;

    uint32_t ep;
    if (recordEpoch(r, ep)) {
      client.print("[");
      client.print(isoUtc(ep));
      client.print("] ");
    } else {
      client.print("[boot ");
      client.print(r.boot_id);
      client.print(" +");
      client.print(r.uptime_s);
      client.print("s] ");
    }

    client.print("[");
    client.print(sevNameC(r.flags));
    client.print("] #");
    client.print(i);
    client.print(" ");
    client.print(eventNameC(r.event));

    if (r.event == EVT_VIOLATION) {
      client.print(" (");
      client.print(violationReasonC(r.data1));
      client.print(")");
    }
    client.print("\n");
  }

  client.print("</pre></body></html>");
}

static void streamIndexHtml(WiFiClient& client) {
  httpBegin(client, "HTTP/1.1 200 OK", "text/html; charset=utf-8");
  client.print("<html><head><meta name='viewport' content='width=device-width, initial-scale=1'>");
  client.print("<title>CoC-VDS Audit</title></head><body style='font-family:system-ui,Segoe UI,Arial'>");
  client.print("<h2>CoC-VDS Auditor</h2>");
  client.print("<p><button onclick='syncTime()' style='padding:10px 14px;font-size:16px'>Sync Time (Auto)</button></p>");
  client.print("<script>"
               "function syncTime(){"
               " const epoch=Math.floor(Date.now()/1000);"
               " window.location.href='/sync?epoch='+epoch;"
               "}"
               "</script>");
  client.print("<p><a href='/report'>View Signed Report</a></p>");
  client.print("<p><a href='/export.csv'>Download CSV</a></p>");
  client.print("<p><a href='/confirm-clear'>Export & Clear</a></p>");
  client.print("<p style='color:gray'>AP stays online while Audit Mode is ON. Toggle Audit OFF (triple-tap) or Serial AUDIT OFF to stop AP.</p>");
  client.print("</body></html>");
}

static void streamConfirmClearHtml(WiFiClient& client) {
  if (auditMode) clearArmUntilMs = millis() + CLEAR_ARM_WINDOW_MS;

  httpBegin(client, "HTTP/1.1 200 OK", "text/html; charset=utf-8");
  client.print("<html><head><meta name='viewport' content='width=device-width, initial-scale=1'>");
  client.print("<title>Confirm Clear</title></head><body style='font-family:system-ui,Segoe UI,Arial'>");
  client.print("<h2>Export & Clear</h2>");
  client.print("<p><b>Warning:</b> Clearing deletes on-device evidence log metadata.</p>");
  client.print("<p>Step 1: Download CSV first. Step 2: Enter passcode to clear.</p>");
  client.print("<p style='color:green;font-weight:700'>Clear window armed for 60 seconds (Audit Mode must remain ON).</p>");
  client.print("<form action='/clear' method='GET'>");
  client.print("Passcode: <input name='code' type='password' /> ");
  client.print("<input type='submit' value='CONFIRM CLEAR' />");
  client.print("</form>");
  client.print("<p><a href='/report'>Back to report</a></p>");
  client.print("</body></html>");
}

static void clearLogs() {
  appendRecord(EVT_LOG_CLEARED, 0, 0, 0, SEV_WARN);

  meta.writeIndex = 0;
  meta.recordCount = 0;
  memset(meta.lastHmac, 0, 32);
  saveMeta();

  journeyCompromised = false;
  state = UNINITIALIZED;
  currentCustodian = CUST_NONE;
  clearArmUntilMs = 0;

  if (DEBUG_MODE) Serial.println("[LOG] Cleared. New journey can start.");
}

static void handlePortal() {
  if (!portalRunning) return;

  WiFiClient client = server.available();
  if (!client) return;

  client.setTimeout(1500);

  String reqLine = client.readStringUntil('\r');
  client.readStringUntil('\n');

  while (client.available()) {
    String h = client.readStringUntil('\n');
    if (h == "\r" || h.length() == 0) break;
  }

  int sp1 = reqLine.indexOf(' ');
  int sp2 = reqLine.indexOf(' ', sp1 + 1);
  if (sp1 < 0 || sp2 < 0) {
    client.stop();
    return;
  }
  String fullPath = reqLine.substring(sp1 + 1, sp2);

  String path = fullPath;
  String query = "";
  int q = fullPath.indexOf('?');
  if (q >= 0) {
    path = fullPath.substring(0, q);
    query = fullPath.substring(q + 1);
  }

  if (DEBUG_MODE) {
    Serial.print("[HTTP] ");
    Serial.println(fullPath);
  }

  if (path == "/" || path == "/index") {
    streamIndexHtml(client);
  } else if (path == "/sync") {
    String epochStr = "";
    int p = query.indexOf("epoch=");
    if (p >= 0) epochStr = query.substring(p + 6);
    uint32_t epoch = (uint32_t)epochStr.toInt();

    if (epoch > 100000) {
      appendRecord(EVT_TIME_SYNC, 0, epoch, (uint32_t)(millis() / 1000UL), SEV_INFO);
      cacheInit();
    }
    httpRedirect(client, "/report");
  } else if (path == "/report") {
    streamReportHtml(client);
  } else if (path == "/export.csv") {
    streamCsvExport(client);
  } else if (path == "/confirm-clear") {
    streamConfirmClearHtml(client);
  } else if (path == "/clear") {
    String code = "";
    int p = query.indexOf("code=");
    if (p >= 0) code = query.substring(p + 5);

    bool ok = true;
    if (!auditMode) ok = false;
    if (millis() > clearArmUntilMs) ok = false;
    if (code != String(CLEAR_PASSCODE)) ok = false;

    httpBegin(client, "HTTP/1.1 200 OK", "text/html");
    if (ok) {
      clearLogs();
      client.print("<html><body style='font-family:system-ui,Segoe UI,Arial'>");
      client.print("<h2>CLEARED</h2><p>Logs cleared. Device reset to READY.</p><p><a href='/'>Home</a></p>");
      client.print("</body></html>");
    } else {
      client.print("<html><body style='font-family:system-ui,Segoe UI,Arial'>");
      client.print("<h2>DENIED</h2><p>Clear conditions not met. Ensure:</p><ul>");
      client.print("<li>Audit Mode is ON</li>");
      client.print("<li>You opened <b>/confirm-clear</b> within the last 60s</li>");
      client.print("<li>Passcode is correct</li>");
      client.print("</ul><p><a href='/confirm-clear'>Try again</a></p>");
      client.print("</body></html>");
    }
  } else {
    httpBegin(client, "HTTP/1.1 404 Not Found", "text/plain");
    client.print("404 Not Found");
  }

  delay(10);
  client.stop();
}


void setup() {
  Serial.begin(115200);

  pinMode(VIOLATION_LED_PIN, OUTPUT);
  digitalWrite(VIOLATION_LED_PIN, LOW);

  Wire.begin();
  SPI.begin();

  if (!display.begin(SSD1306_SWITCHCAPVCC, 0x3C)) {
    if (DEBUG_MODE) Serial.println("OLED not found");
    while (true) {}
  }
  display.clearDisplay();
  display.setTextSize(1);
  display.setTextColor(SSD1306_WHITE);

  pinMode(RFID_SS, OUTPUT);
  digitalWrite(RFID_SS, HIGH);
  rfid.PCD_Init();
  if (DEBUG_MODE) Serial.println("RFID ready");

  imu.initialize();
  if (DEBUG_MODE) Serial.println(imu.testConnection() ? "IMU OK" : "IMU NOT detected");

  deriveKey();
  loadMetaOrInit();
  repairTruncateInvalid();

  cacheInit();

  meta.bootCounter++;
  g_bootId = meta.bootCounter;
  saveMeta();

  appendRecord(EVT_BOOT, 0, (uint32_t)g_bootId, 0, SEV_INFO);

  delay(250);
  calibrateBaseline();
  reconstructFromLog();

  if (DEBUG_MODE) {
    Serial.println("Ready. Scan WHITE to seal, BLUE to take custody.");
    Serial.println("Admin triple-tap toggles AUDIT MODE (starts/stops WiFi portal).");
    Serial.println("Serial: type 'AUDIT ON' to start web portal, 'AUDIT OFF' to stop, 'HELP' for more.");
    Serial.println("Demo: Type 'DEMO ARM' then 'DEMO1' (for demo builds).");
    Serial.println("----------------------------------------------");
  }
}


void loop() {
  handleDemoSerial();  
  handlePortal();

  int lightVal = readLight();
  long motionVal = readMotionMagnitude();

  // LED: covert by default. Only maintenance pulse in audit mode when DEBUG_MODE.
  if (!DEBUG_MODE) {
    digitalWrite(VIOLATION_LED_PIN, LOW);
  } else {
    if (auditMode && !logHasSpaceForNewJourney()) {
      static unsigned long lastBlink = 0;
      static bool led = false;
      if (millis() - lastBlink > 600) {
        lastBlink = millis();
        led = !led;
        digitalWrite(VIOLATION_LED_PIN, led ? HIGH : LOW);
      }
    } else {
      digitalWrite(VIOLATION_LED_PIN, LOW);
    }
  }

  
  uint8_t uidBytes[10];
  uint8_t uidLen = 0;
  char uidHex[21];
  uidHex[0] = '\0';

  bool gotUidRaw = readUidIfPresent(uidBytes, uidLen, uidHex);
  bool gotUid = false;

  if (gotUidRaw) {
    unsigned long now = millis();
    if (now - lastRfidAcceptMs >= RFID_DEBOUNCE_MS) {
      gotUid = true;
      lastRfidAcceptMs = now;
      if (DEBUG_MODE) {
        Serial.print("[RFID] UID=");
        Serial.println(uidHex);
      }
    }
  }

  if (gotUid && isAdminHex(uidHex)) {
    unsigned long now = millis();
    if (adminTapCount == 0) adminTapWindowStartMs = now;

    if (now - adminTapWindowStartMs <= ADMIN_TAP_WINDOW_MS) {
      adminTapCount++;
    } else {
      adminTapCount = 1;
      adminTapWindowStartMs = now;
    }

    if (adminTapCount >= 3) {
      adminTapCount = 0;
      setAuditMode(!auditMode);
    }
  }

 
  if (gotUid && state != RECEIVED_FINAL) {
    uint32_t tagId = fnv1a32_bytes(uidBytes, uidLen);
    bool maintenanceReq = !logHasSpaceForNewJourney();

    if (isAdminHex(uidHex) && state == UNINITIALIZED && maintenanceReq) {
      if (!auditMode) setAuditMode(true);
      appendRecord(EVT_SEAL_REFUSED, tagId, (uint32_t)meta.recordCount, (uint32_t)meta.maxRecords, SEV_WARN);
      if (DEBUG_MODE) Serial.println("[STATE] STORAGE LOW -> ENTERING AUDIT MODE (export/clear required)");
    } else if (isAdminHex(uidHex) && state == UNINITIALIZED) {
      state = SEALED_IDLE;
      currentCustodian = CUST_NONE;
      journeyCompromised = false;
      lastViolationLoggedMs = 0;
      appendRecord(EVT_SEALED, tagId, (uint32_t)LIGHT_THRESHOLD, (uint32_t)MOTION_THRESHOLD, SEV_INFO);
      if (DEBUG_MODE) Serial.println("[STATE] SEALED_IDLE (sealed by WHITE)");
    } else if (isAdminHex(uidHex) && state == SEALED_IDLE) {
      state = ADMIN_OPEN_STATE;
      appendRecord(EVT_ADMIN_OPEN, tagId, (uint32_t)lightVal, (uint32_t)motionVal, SEV_WARN);
      if (DEBUG_MODE) Serial.println("[STATE] ADMIN_OPEN (authorized)");
    } else if (isAdminHex(uidHex) && state == ADMIN_OPEN_STATE) {
      state = SEALED_IDLE;
      appendRecord(EVT_ADMIN_RESEAL, tagId, (uint32_t)lightVal, (uint32_t)motionVal, SEV_INFO);
      if (DEBUG_MODE) Serial.println("[STATE] SEALED_IDLE (resealed)");
    } else if (isHandlerHex(uidHex) && state == SEALED_IDLE) {
      state = IN_CUSTODY;
      currentCustodian = CUST_HANDLER;
      appendRecord(EVT_CUSTODY_TAKEN, tagId, 0, 0, SEV_INFO);
      if (DEBUG_MODE) Serial.println("[STATE] IN_CUSTODY (BLUE took custody)");
      lastHandlerScanMs = millis();
      handlerArmedForDoubleTap = true;
    } else if (isHandlerHex(uidHex) && state == IN_CUSTODY) {
      unsigned long now = millis();
      if (handlerArmedForDoubleTap && (now - lastHandlerScanMs <= DOUBLE_TAP_WINDOW_MS)) {
        state = TRANSFER_WINDOW;
        transferStartMs = now;
        appendRecord(EVT_TRANSFER_WINDOW_OPEN, tagId, (uint32_t)(TRANSFER_WINDOW_MS / 1000UL), 0, SEV_INFO);
        if (DEBUG_MODE) Serial.println("[STATE] TRANSFER_WINDOW (BLUE double-tap)");
        handlerArmedForDoubleTap = false;
      } else {
        lastHandlerScanMs = now;
        handlerArmedForDoubleTap = true;
        if (DEBUG_MODE) Serial.println("[INFO] BLUE tap 1/2 (tap again within 3s)");
      }
    } else if (isAdminHex(uidHex) && state == TRANSFER_WINDOW) {
      state = RECEIVED_FINAL;
      currentCustodian = CUST_RECEIVER;
      appendRecord(EVT_RECEIVED_FINAL, tagId, 0, 0, SEV_INFO);
      if (DEBUG_MODE) Serial.println("[STATE] RECEIVED_FINAL (received by WHITE)");
    }
  }

  
  if (state != UNINITIALIZED && state != RECEIVED_FINAL && state != ADMIN_OPEN_STATE) {
    if (lightVal > LIGHT_THRESHOLD) logViolationOnce(V_LIGHT_EXPOSURE, lightVal, motionVal);
  }
  if (state == SEALED_IDLE) {
    if (motionVal > MOTION_THRESHOLD) logViolationOnce(V_MOTION_NO_CUST, lightVal, motionVal);
  }
  if (state == TRANSFER_WINDOW) {
    if (millis() - transferStartMs > TRANSFER_WINDOW_MS) logViolationOnce(V_XFER_EXPIRED, lightVal, motionVal);
  }

  
  bool maintenanceReq = !logHasSpaceForNewJourney();
  if (!auditMode) {
    drawShippingLabel(maintenanceReq);
  } else {
    drawAuditScreen(lightVal, motionVal);
    if (maintenanceReq) {
      display.setCursor(0, 56);
      display.print("STORAGE LOW -> EXPORT");
      display.display();
    }
  }

  delay(80);
}
