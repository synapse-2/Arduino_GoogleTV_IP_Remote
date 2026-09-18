#pragma once

#include <Arduino.h>
#include <vector>
#include <string>
#include "FF.h"
#include "lwip/sockets.h"
#include <sys/param.h>
#include "remotemessage.pb.h"
#include "pairingmessage.pb.h"
#include "esp_http_client.h"

#if defined(WOLFSSL_USER_SETTINGS)
#include <wolfssl/wolfcrypt/settings.h>
#if defined(WOLFSSL_ESPIDF)
#include <wolfssl/version.h>
#include <wolfssl/ssl.h>
#include <wolfssl/wolfcrypt/types.h>
#include <wolfcrypt/benchmark/benchmark.h>
#include <wolfssl/wolfcrypt/port/Espressif/esp-sdk-lib.h>
#include <wolfssl/wolfcrypt/port/Espressif/esp32-crypt.h>
#endif
#endif

#ifndef GIPR_GOOGLEIP_TVPORT_SEND
#define GIPR_GOOGLEIP_TVPORT_SEND 6466
#endif

#ifndef GIPR_GOOGLEIP_TVPORT_PAIRING
#define GIPR_GOOGLEIP_TVPORT_PAIRING 6467
#endif


#ifndef GIPR_TCP_HANDSHAKE_TIMEOUT_MiliSec
#define GIPR_TCP_HANDSHAKE_TIMEOUT_MiliSec 3000
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
#define GIPR_WOLFSSL_ERROR_TXT_BUFF 512 // note this will be on the heap stack
#endif

#ifndef GIPR_DELAY_TO_YEILD_MiliSec
#define GIPR_DELAY_TO_YEILD_MiliSec 10
#endif

#ifndef GIPR_CERT_VOLPREFIX
#define GIPR_CERT_VOLPREFIX "/ffat" // used for the fopen connand used by wolfssl
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

    typedef enum _RemoteMode
    {
        STARTUP = 1,
        CONNECTED_TO_TV = 2,
        CONNECTED_TO_PAIRING = 3,
        INIT_WOL = 4,
        DISCONNECTED = 5

    } RemoteMode;

    // progress call back with prog percentage, if the call back returns false then the process is canceled.
    typedef bool (*progressCallback)(String work, int progPercent);

    // call back for the pin number
    typedef String (*getSecretforPairing)(DiscoveredTv tv);

    class GoogleTvRemote
    {
    public:
        GoogleTvRemote();
        ~GoogleTvRemote();

        void connectToTV(DiscoveredTv tv, progressCallback callBack = NULL);
        void loopRemoteConnection();
        bool isConnected();
        bool isPaired();
        void unPair();

        void disconnect();

        // get the TV's on the IP network
        static std::vector<DiscoveredTv> scanForTvs();
        static bool haveSelfCertificate();
        static bool makeNewSelfCertificate(progressCallback callBack = NULL);

        static String getWolfsslTxtError(WOLFSSL * ssl, int error,  bool &isError );

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
        bool makeSSLConnectBase(bool paring_complete);
        bool connectTCPHandshake(uint16_t port, int32_t timeout_ms);

        bool makeSSLConnectRemote();
        bool makeSSLConnectPairing();

        static bool wakeUpTV(String ip);
        static esp_err_t http_WOL_event_handler(esp_http_client_event_t *evt);

        static int SSLSendBytes(WOLFSSL *ssl, char *msg, int sz, void *ctx);
        static int SSLReceiveBytes(WOLFSSL *ssl, char *reply, int sz, void *ctx);
        static bool waitForSocket(int socket_fd, int condition, int32_t timeout_ms);

        static Remote_RemoteMessage *unpack_remote_message(const uint8_t *buffer, size_t buffer_length);
        static Pairing_PairingMessage *unpack_paring_message(const uint8_t *buffer, size_t buffer_length);

        static Pairing_PairingMessage *createPairingRequest();
        static std::vector<uint8_t> pack_message(Pairing_PairingMessage *msg);
        static void encodeMessegToSend(std::vector<uint8_t> &dataBuffer);

        static Pairing_PairingMessage *createParingOptionMsg();
        static void printPacket(uint8_t *packet, size_t len);
        static void printParingMessage(Pairing_PairingMessage* msg);

        unsigned long _lastPingTime;
        const unsigned long _pingInterval = 5000; // Keep-alive interval
        bool is_paired = false;
        WOLFSSL_CTX *ctx = NULL;
        WOLFSSL *ssl = NULL;
        int sockFD = -1;
        DiscoveredTv tvInit;
        progressCallback callBackInit;
        RemoteMode API_state =  DISCONNECTED;
        int connectRetries = 0;

        std::vector<uint8_t> readDataCunks;

        // Helper to abstract Nanopb encoding and socket transmission
        // bool transmitMessage(const RemoteMessage &message);
    };

}