#include <Wire.h>
#include <Adafruit_GFX.h>
#include <Adafruit_SSD1306.h>
#include <SPI.h>
#include <MFRC522.h>
#include <MPU6050.h>

#define SCREEN_WIDTH 128
#define SCREEN_HEIGHT 64
#define OLED_RESET -1

#define RFID_SS 10
#define RFID_RST 9

#define LDR_PIN A0


#define LED_PIN 7

Adafruit_SSD1306 display(SCREEN_WIDTH, SCREEN_HEIGHT, &Wire, OLED_RESET);
MFRC522 rfid(RFID_SS, RFID_RST);
MPU6050 imu;

void setup() {
  Serial.begin(115200);
  Wire.begin();
  SPI.begin();


  pinMode(LED_PIN, OUTPUT);
  digitalWrite(LED_PIN, LOW);


  if (!display.begin(SSD1306_SWITCHCAPVCC, 0x3C)) {
    Serial.println("OLED not found");
    while (true);
  }
  display.clearDisplay();
  display.setTextSize(1);
  display.setTextColor(SSD1306_WHITE);
  display.setCursor(0,0);
  display.println("CoC Calibration");
  display.display();

  
  rfid.PCD_Init();
  Serial.println("RFID ready");


  imu.initialize();
  if (!imu.testConnection()) {
    Serial.println("IMU NOT detected");
  } else {
    Serial.println("IMU OK");
  }

  delay(1000);
}

void loop() {
 
  int lightVal = analogRead(LDR_PIN);

 
  int16_t ax, ay, az;
  imu.getAcceleration(&ax, &ay, &az);
  long motion = abs(ax) + abs(ay) + abs(az);

 
  bool cardDetected = false;
  String uidStr = "";

  if (rfid.PICC_IsNewCardPresent() && rfid.PICC_ReadCardSerial()) {
    cardDetected = true;
    for (byte i = 0; i < rfid.uid.size; i++) {
      uidStr += String(rfid.uid.uidByte[i], HEX);
    }
    rfid.PICC_HaltA();
  }

  
  digitalWrite(LED_PIN, cardDetected ? HIGH : LOW);

 
  display.clearDisplay();
  display.setCursor(0,0);
  display.println("CALIBRATION MODE");
  display.print("Light: ");
  display.println(lightVal);
  display.print("Motion: ");
  display.println(motion);
  display.print("RFID: ");
  display.println(cardDetected ? uidStr : "none");
  display.display();

 
  Serial.print("Light=");
  Serial.print(lightVal);
  Serial.print(" | Motion=");
  Serial.print(motion);
  if (cardDetected) {
    Serial.print(" | RFID=");
    Serial.print(uidStr);
  }
  Serial.println();

  delay(500);
}
