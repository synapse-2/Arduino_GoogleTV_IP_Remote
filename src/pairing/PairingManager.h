#include <Arduino.h>
#include <WiFiClientSecure.h>
//#include <Crypto.h>
// #include <SHA256.h>
#include <vector>
#include "pairing/PairingMessageHelper.h"
#include "certificateMgr/CertificateGenerator.h"


#ifndef PAIRINGMANAGER_H
#define PAIRINGMANAGER_H


class PairingManager {
public:
   // bool sendCode(const String& code);
    void begin(IPAddress host, uint16_t port, String service_name, String model);
    // bool connected();
    // void loop();
    // bool isSecure = false;

protected:
    // std::vector<uint8_t> hexStringToBytes(const String &hexString);
    // void handleResponse(Pairing_PairingMessage *message);
    // std::vector<uint8_t> chunks;
};
#endif