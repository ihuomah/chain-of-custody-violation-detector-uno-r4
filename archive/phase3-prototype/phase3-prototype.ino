/*
 * Project: CoC-VDS (Chain-of-Custody Violation Detection System)
 * Board: Arduino Uno R4 WiFi
 * Version: 3.0 Prototype - State Machine & Custody Logic
 * Author:  Chinyere Ihuoma Uwa (Kyma)
 * Date:    December 2025
 * 
 * * Description:
 * Milestone build focusing on the "Fail-Closed" State Machine. 
 * This version established the Custody Roles (Admin vs. Courier) and 
 * the logic for transition-based violation detection before the 
 * implementation of cryptographic hash-chaining in Phase 4.
 *
 * 
 * Notes:
 *  - No stealth UI
 *  - No persistent logging
 *  - Thresholds auto-calibrated at boot
 */
 
#include <Wire.h>
#include <Adafruit_GFX.h>
#include <Adafruit_SSD1306.h>
#include <SPI.h>
#include <MFRC522.h>
#include <MPU6050.h>


#define SCREEN_WIDTH 128
#define SCREEN_HEIGHT 64
#define OLED_RESET -1
Adafruit_SSD1306 display(SCREEN_WIDTH, SCREEN_HEIGHT, &Wire, OLED_RESET);


#define RFID_SS 10
#define RFID_RST 9
MFRC522 rfid(RFID_SS, RFID_RST);


#define LDR_PIN A0
MPU6050 imu;


static const char UID_ADMIN[] = "AAAAAAAA"; // Replace with your own admin / White card UID
static const char UID_HANDLER[] = "BBBBBBBB"; // Replace with your own handler / Blue tag UID


int  LIGHT_THRESHOLD  = 120;     
long MOTION_THRESHOLD = 22000;   


const unsigned long DOUBLE_TAP_WINDOW_MS = 3000;
const unsigned long TRANSFER_WINDOW_MS   = 60000;


const bool SERIAL_HEARTBEAT_ENABLED = false;  
const unsigned long HB_INTERVAL_MS = 2000;


enum State {
  UNINITIALIZED,
  SEALED_IDLE,
  IN_CUSTODY,
  TRANSFER_WINDOW,
  VIOLATION_LOCK,
  RECEIVED_FINAL
};

State state = UNINITIALIZED;


String currentCustodian = "NONE";
unsigned long transferStartMs = 0;


unsigned long lastHandlerScanMs = 0;
bool handlerArmedForDoubleTap = false;


unsigned long lastHbMs = 0;


long readMotionMagnitude() {
  int16_t ax, ay, az;
  imu.getAcceleration(&ax, &ay, &az);
  return (long)abs(ax) + (long)abs(ay) + (long)abs(az);
}


int readLight() {
  return analogRead(LDR_PIN);
}


String readUidIfPresent() {
  
  if (!rfid.PICC_IsNewCardPresent()) return "";
  if (!rfid.PICC_ReadCardSerial()) return "";

  String uidStr = "";
  for (byte i = 0; i < rfid.uid.size; i++) {
    if (rfid.uid.uidByte[i] < 0x10) uidStr += "0";
    uidStr += String(rfid.uid.uidByte[i], HEX);
  }
  uidStr.toLowerCase();

  rfid.PICC_HaltA();
  rfid.PCD_StopCrypto1(); 

  return uidStr;
}

bool isAdmin(const String& uid) {
  return uid == String(UID_ADMIN);
}

bool isHandler(const String& uid) {
  return uid == String(UID_HANDLER);
}

const char* stateName(State s) {
  switch (s) {
    case UNINITIALIZED:   return "UNINITIALIZED";
    case SEALED_IDLE:     return "SEALED_IDLE";
    case IN_CUSTODY:      return "IN_CUSTODY";
    case TRANSFER_WINDOW: return "TRANSFER_WINDOW";
    case VIOLATION_LOCK:  return "VIOLATION_LOCK";
    case RECEIVED_FINAL:  return "RECEIVED_FINAL";
    default:              return "UNKNOWN";
  }
}

void setViolation(const char* reason) {
  state = VIOLATION_LOCK;

  Serial.print("[VIOLATION] ");
  Serial.println(reason);

  display.clearDisplay();
  display.setCursor(0, 0);
  display.println("STATUS: VIOLATION");
  display.println(reason);
  display.display();
}

void showStatus(int lightVal, long motionVal, const String& lastUid) {
  display.clearDisplay();
  display.setCursor(0, 0);

  display.print("STATE: ");
  display.println(stateName(state));

  display.print("Cust: ");
  display.println(currentCustodian);

  display.print("Light: ");
  display.println(lightVal);

  display.print("Motion: ");
  display.println(motionVal);

  display.print("RFID: ");
  display.println(lastUid.length() ? lastUid : "none");

  if (state == TRANSFER_WINDOW) {
    unsigned long elapsed = millis() - transferStartMs;
    long remaining = (long)TRANSFER_WINDOW_MS - (long)elapsed;
    if (remaining < 0) remaining = 0;
    display.print("TW left: ");
    display.print(remaining / 1000);
    display.println("s");
  }

  display.display();
}

void calibrateBaseline() {
 
  const int samples = 40;
  long lightSum = 0;
  long motionSum = 0;

  for (int i = 0; i < samples; i++) {
    lightSum += readLight();
    motionSum += readMotionMagnitude();
    delay(25);
  }

  int lightAvg = lightSum / samples;
  long motionAvg = motionSum / samples;


  LIGHT_THRESHOLD = lightAvg + 80;             
  if (LIGHT_THRESHOLD > 1023) LIGHT_THRESHOLD = 1023;

  
  MOTION_THRESHOLD = motionAvg + 4000;         

  Serial.print("[BASELINE] light_avg=");
  Serial.print(lightAvg);
  Serial.print(" motion_avg=");
  Serial.println(motionAvg);

  Serial.print("[THRESH] LIGHT_THRESHOLD=");
  Serial.print(LIGHT_THRESHOLD);
  Serial.print(" MOTION_THRESHOLD=");
  Serial.println(MOTION_THRESHOLD);
}

void setup() {
  Serial.begin(115200);

  Wire.begin();
  SPI.begin();

  
  if (!display.begin(SSD1306_SWITCHCAPVCC, 0x3C)) {
    Serial.println("OLED not found");
    while (true);
  }
  display.clearDisplay();
  display.setTextSize(1);
  display.setTextColor(SSD1306_WHITE);
  display.setCursor(0, 0);
  display.println("CoC-VDS Phase 3");
  display.println("Supply-Chain Mode");
  display.display();

 
  pinMode(RFID_SS, OUTPUT);
  digitalWrite(RFID_SS, HIGH);
  rfid.PCD_Init();
  Serial.println("RFID ready");

  
  imu.initialize();
  Serial.println(imu.testConnection() ? "IMU OK" : "IMU NOT detected");

  delay(500);

  calibrateBaseline();

  Serial.println("Ready. Scan WHITE to seal, BLUE to take custody.");
  Serial.println("----------------------------------------------");
}

void loop() {
  int lightVal = readLight();
  long motionVal = readMotionMagnitude();

 
  if (state != UNINITIALIZED && state != RECEIVED_FINAL && state != VIOLATION_LOCK) {
    if (lightVal > LIGHT_THRESHOLD) {
      setViolation("Light exposure detected");
    }
  }

  if (state == SEALED_IDLE) {
    if (motionVal > MOTION_THRESHOLD) {
      setViolation("Motion w/o custody");
    }
  }

  if (state == TRANSFER_WINDOW) {
    if (millis() - transferStartMs > TRANSFER_WINDOW_MS) {
      setViolation("Transfer window expired");
    }
  }

  
  String uid = readUidIfPresent();

  
  if (uid.length()) {
    Serial.print("[RFID] UID=");
    Serial.println(uid);
  }

 
  if (uid.length() && state != VIOLATION_LOCK && state != RECEIVED_FINAL) {

    if (isAdmin(uid) && state == UNINITIALIZED) {
      state = SEALED_IDLE;
      currentCustodian = "NONE";
      Serial.println("[STATE] SEALED_IDLE (sealed by WHITE)");
    }
    else if (isHandler(uid) && state == SEALED_IDLE) {
      state = IN_CUSTODY;
      currentCustodian = "HANDLER";
      Serial.println("[STATE] IN_CUSTODY (BLUE took custody)");
      lastHandlerScanMs = millis();
      handlerArmedForDoubleTap = true;
    }
    else if (isHandler(uid) && state == IN_CUSTODY) {
      unsigned long now = millis();
      if (handlerArmedForDoubleTap && (now - lastHandlerScanMs <= DOUBLE_TAP_WINDOW_MS)) {
        state = TRANSFER_WINDOW;
        transferStartMs = now;
        Serial.println("[STATE] TRANSFER_WINDOW (BLUE double-tap)");
        handlerArmedForDoubleTap = false;
      } else {
        lastHandlerScanMs = now;
        handlerArmedForDoubleTap = true;
        Serial.println("[INFO] BLUE tap 1/2 (tap again within 3s)");
      }
    }
    else if (isAdmin(uid) && state == TRANSFER_WINDOW) {
      state = RECEIVED_FINAL;
      currentCustodian = "RECEIVER";
      Serial.println("[STATE] RECEIVED_FINAL (received by WHITE)");
    }
    else {
      Serial.print("[INFO] No valid transition. state=");
      Serial.print(stateName(state));
      Serial.print(" uid=");
      Serial.println(uid);
    }
  }

  
  showStatus(lightVal, motionVal, uid);

  
  if (SERIAL_HEARTBEAT_ENABLED && millis() - lastHbMs >= HB_INTERVAL_MS) {
    lastHbMs = millis();
    Serial.print("[HB] state=");
    Serial.print(stateName(state));
    Serial.print(" cust=");
    Serial.print(currentCustodian);
    Serial.print(" light=");
    Serial.print(lightVal);
    Serial.print(" motion=");
    Serial.print(motionVal);
    Serial.print(" lastRFID=");
    Serial.println(uid.length() ? uid : "none");
  }

  delay(100);
}
