
#include <Arduino.h>
#include <WiFiClientSecure.h>
#include "pairingmessage.pb.h"

#ifndef PAIRING_MESSAGE_MANAGER_H
#define PAIRING_MESSAGE_MANAGER_H

namespace PairingMessageHelper
{
    uint8_t *createPairingRequest(String service_name, String model);
    uint8_t *encodePairingMessage(Pairing_PairingMessage &message);
    // uint8_t* createPairingOption() ;
    // uint8_t* createPairingConfiguration() ;
    // uint8_t* createPairingSecret(const uint8_t *secret) ;
    // uint8_t* encodePairingMessage(Pairing_PairingMessage &message);
}

#endif // PAIRING_MESSAGE_MANAGER_H