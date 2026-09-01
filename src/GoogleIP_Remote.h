#pragma once

#include <Arduino.h>
#include <vector>
#include <string>
#include "FF.h"

#include <wolfssl/wolfcrypt/settings.h>
#ifdef WOLFSSL_ESPIDF
#include <esp_log.h>
#include <rtc_wdt.h>
#include <wolfssl/wolfcrypt/port/Espressif/esp32-crypt.h>
#endif

#include <wolfssl/version.h>
#include <wolfssl/wolfcrypt/types.h>
// wolfSSL - wolfCrypt options and headers
#include <wolfssl/ssl.h>
#include <wolfssl/wolfcrypt/asn.h>
#include <wolfssl/wolfcrypt/rsa.h>
#include <wolfssl/wolfcrypt/random.h>
#include <wolfssl/wolfcrypt/coding.h>

#ifndef GIPR_GOOGLEIP_TVPORT_SEND
#define GIPR_GOOGLEIP_TVPORT_SEND 6466
#endif

#ifndef GIPR_ANDRIOD_TV_RMOETE_SERVICE
#define GIPR_ANDRIOD_TV_RMOETE_SERVICE "androidtvremote2"
#endif

#ifndef GIPR_GOOGLE_CROMECAST_SERVICE
#define GIPR_GOOGLE_CROMECAST_SERVICE "googlecast"
#endif

#ifndef GIPR_GOOGLE_FRENDLY_NAME
#define GIPR_GOOGLE_FRENDLY_NAME "fn"
#endif

#ifndef GIPR_ANDROID_BT_NAME
#define GIPR_ANDROID_BT_NAME "bt"
#endif

#ifndef GIPR_GOOGLE_MODEL_NAME
#define GIPR_GOOGLE_MODEL_NAME "md"
#endif

#ifndef GIPR_CERT_COUNTRY
#define GIPR_CERT_COUNTRY "US"
#endif

#ifndef GIPR_CERT_STATE
#define GIPR_CERT_STATE "California"
#endif

#ifndef GIPR_CERT_CITY
#define GIPR_CERT_CITY "Mountain View"
#endif

#ifndef GIPR_CERT_ORG
#define GIPR_CERT_ORG "Google Inc."
#endif

#ifndef GIPR_CERT_STATE
#define GIPR_CERT_STATE "California"
#endif

#ifndef GIPR_CERT_UNIT
#define GIPR_CERT_UNIT "Android"
#endif

#ifndef GIPR_CERT_EMAIL
#define GIPR_CERT_EMAIL "email@google.com"
#endif

#ifndef GIPR_RSA_KEY_LENGTH
#define GIPR_RSA_KEY_LENGTH 2048
#endif

#ifndef GIPR_DER_BUFFER
#define GIPR_DER_BUFFER 4096
#endif

#ifndef GIPR_PEM_BUFFER
#define GIPR_PEM_BUFFER 4096
#endif

#ifndef GIPR_RSA_NONBLOCK_TIME
#define GIPR_RSA_NONBLOCK_TIME 100 // 1 miccrosecs on 240Mhtz
#endif

#ifndef GIPR_WOLFSSL_ERROR_TXT_BUFF
#define GIPR_WOLFSSL_ERROR_TXT_BUFF 80 // note this will be on the heap stack
#endif

#ifndef GIPR_DELAY_TO_YEILD_MiliSec
#define GIPR_DELAY_TO_YEILD_MiliSec 10
#endif

#ifndef GIPR_CERT_FILE_NAME
#define GIPR_CERT_FILE_NAME "/selfCert.pem"
#endif

#ifndef GIPR_PRIKEY_FILE_NAME
#define GIPR_PRIKEY_FILE_NAME "/priKey.pem"
#endif

#define CONFIG_NIMBLE_USE_MAGIC_ENUM y

namespace GoogleIPRemote
{

    struct DiscoveredTv
    {
        String friendlyName;
        String hostName;
        String model;
        String ip;
        String btMac;
        String ipMac;
    };

    // progress call back with prog percentage, if the call back returns false then the process is canceled.
    typedef bool (*progressCallback)(String work, int progPercent);

    // call back for the pin number
    typedef String (*getSecretforPairing)(DiscoveredTv tv);

    class GoogleTvRemote
    {
    public:
        GoogleTvRemote();
        ~GoogleTvRemote();

        bool connectToTV(DiscoveredTv tv, progressCallback callBack = NULL);

        // get the TV's on the IP network
        static std::vector<DiscoveredTv> scanForTvs();
        static bool haveSelfCertificate();
        static bool makeNewSelfCertificate(progressCallback callBack = NULL);
        static String getWolfsslTxtError(int error);


        // Connection lifecycle
        // bool connect(const char *ipAddress, const char *clientCert, const char *clientKey);
        // void disconnect();
        // bool isConnected();
        // void loop(); // Must be called in main loop to process pings/keepalives

        // Remote input actions
        // bool sendKey(Keycode keycode, Direction direction = Direction_SHORT);
        // bool sendPing();

    protected:
        static String getMacFromIp(const String &ipStr);
        static void forceArpResolution(const String &ipStr);
        static FRESULT ffat_write_buffer(const TCHAR *path, const void *buffer, UINT bytes_to_write, String beginMessage, String endMessage);
        bool createSSLCtx(progressCallback callBack);

        const char *_ip;
        unsigned long _lastPingTime;
        const unsigned long _pingInterval = 5000; // Keep-alive interval
        bool is_connceted = false;
        bool is_paired = false; 
        WOLFSSL_CTX* ctx = NULL;

        // Helper to abstract Nanopb encoding and socket transmission
        // bool transmitMessage(const RemoteMessage &message);
    };

}