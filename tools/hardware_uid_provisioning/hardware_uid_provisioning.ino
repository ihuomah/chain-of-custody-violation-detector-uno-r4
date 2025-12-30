// Retrieve and print the unique device ID of the Uno R4 board

#include "bsp_api.h"

void printUniqueDeviceID() {
  
  bsp_unique_id_t const * uid = R_BSP_UniqueIdGet();

  Serial.print("Uno R4 Unique Device ID: ");
  
  
  for (int i = 0; i < 4; i++) {
    
    if (uid->unique_id_words[i] < 0x10000000) Serial.print("0");
    Serial.print(uid->unique_id_words[i], HEX);
  }
  Serial.println();
}

void setup() {
  Serial.begin(115200);
  while (!Serial); 
  delay(1000); 
  printUniqueDeviceID();
}

void loop() {}