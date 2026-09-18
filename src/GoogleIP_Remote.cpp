
#include "GoogleIP_Remote.h"
#include <ESPmDNS.h>
#include <WiFi.h>
#include <lwip/etharp.h>
#include <lwip/ip_addr.h>
#include <UtilityFunctions.h>
#include "FFat.h"
#include "FS.h"
#include "FF.h"
#include "esp_task_wdt.h" // Required to manually feed the watchdog

#include <stdio.h>
#include <string.h>
#include <sys/param.h>
#include <pb_decode.h>
#include <pb_encode.h>
#include "remotemessage.pb.h"
#include "pairingmessage.pb.h"

// Essential BSD Socket / LwIP headers
#include "lwip/sockets.h"
#include "lwip/sys.h"
#include <lwip/netdb.h>
#include "esp_http_client.h"

#if defined(CONFIG_NIMBLE_USE_MAGIC_ENUM)
#include "magic_enum/magic_enum.hpp"
#include "magic_enum/magic_enum_iostream.hpp"
#endif

/* wolfSSL */
/* Always include wolfcrypt/settings.h before any other wolfSSL file.    */
/* Reminder: settings.h pulls in user_settings.h; don't include it here. */
/* undefine Arduino as that gives an error in WOLFSSL */

#if defined(WOLFSSL_USER_SETTINGS)
#include <wolfssl/wolfcrypt/settings.h>
#if defined(WOLFSSL_ESPIDF)
#include <wolfssl/version.h>
#include <wolfssl/ssl.h>
#include <wolfssl/wolfcrypt/types.h>
#include <wolfcrypt/benchmark/benchmark.h>
#include <wolfssl/wolfcrypt/port/Espressif/esp-sdk-lib.h>
#include <wolfssl/wolfcrypt/port/Espressif/esp32-crypt.h>
#include <wolfssl/wolfcrypt/rsa.h>
#include <wolfssl/wolfcrypt/asn_public.h>
#endif
#endif

namespace GoogleIPRemote
{
    std::vector<DiscoveredTv> GoogleTvRemote::scanForTvs()
    {
        std::vector<DiscoveredTv> tvList;

        for (int f = 0; f < 3; f++)
        {
            UtilityFunctions::debugLog("[Discovery] Browsing for _androidtvremote2._tcp services ...");
            // Query mDNS for the specific Android/Google TV remote service service type
            int numServices = MDNS.queryService(GIPR_ANDRIOD_TV_RMOETE_SERVICE, "tcp");

            if (numServices == 0)
            {
                UtilityFunctions::debugLog("[Discovery] No Google TVs found on the local network.");
            }
            else
            {

                UtilityFunctions::debugLogf("[Discovery] Found %d potential device(s):\n", numServices);

                for (int i = 0; i < numServices; ++i)
                {
                    DiscoveredTv tv;

                    // 1. Resolve human-readable name (falls back to hostname if empty)

                    tv.hostName = MDNS.hostname(i);

                    // 2. Resolve IP Address
                    tv.ip = MDNS.address(i).toString();

                    // 3. Resolve MAC Address
                    if (MDNS.hasTxt(i, GIPR_ANDROID_BT_NAME))
                    {
                        tv.btMac = MDNS.txt(i, GIPR_ANDROID_BT_NAME);
                    }
                    else
                    {
                        tv.btMac = "";
                    }
                    tv.ipMac = getMacFromIp(tv.ip);

                    // Deduplication Step: Look for a matching IP in the master list, if not found add
                    bool found = false;
                    for (auto &existingDev : tvList)
                    {
                        if (existingDev.ip == tv.ip)
                        {
                            found = true;
                        }
                    }

                    if (!found)
                    {
                        tvList.push_back(tv);
                    }
                }
            }

            // get additional info using crome cast service

            UtilityFunctions::debugLog("[Discovery] Browsing for _googlecast._tcp services ...");

            numServices = MDNS.queryService(GIPR_GOOGLE_CROMECAST_SERVICE, "tcp");
            if (numServices == 0)
            {
                UtilityFunctions::debugLog("[Discovery] No crome cast TVs found on the local network.");
            }
            else
            {

                for (int i = 0; i < numServices; ++i)
                {

                    // 2. Resolve IP Address
                    String cromeIP = MDNS.address(i).toString();

                    // Deduplication Step: Look for a matching IP in the master list, if not found do nothing
                    for (auto &existingDev : tvList)
                    {
                        if (existingDev.ip == cromeIP)
                        {
                            if (MDNS.hasTxt(i, GIPR_GOOGLE_FRENDLY_NAME))
                            {
                                existingDev.friendlyName = MDNS.txt(i, GIPR_GOOGLE_FRENDLY_NAME);
                            }

                            if (MDNS.hasTxt(i, GIPR_GOOGLE_MODEL_NAME))
                            {
                                existingDev.model = MDNS.txt(i, GIPR_GOOGLE_MODEL_NAME);
                            }
                            break;
                        }
                    }
                }
            }
        } // do this three times to get accurate results
        return tvList;
    }

    // Low-level helper to lookup MAC addresses inside the ESP32 network stack cache
    String GoogleTvRemote::getMacFromIp(const String &ipStr)
    {
        ip_addr_t targetIp;
        ip4addr_aton(ipStr.c_str(), ip_2_ip4(&targetIp));

        struct eth_addr *ethAddr = nullptr;
        const ip4_addr_t *filteredIp = nullptr;
        struct netif *netInterface = nullptr;

        // Query lwIP components to find matched hardware entries in active cache table
        err_t lookupResult = etharp_find_addr(&netif_list[0], ip_2_ip4(&targetIp), &ethAddr, &filteredIp);

        if (lookupResult >= 0 && ethAddr != nullptr)
        {
            char macBuf[18];
            snprintf(macBuf, sizeof(macBuf), "%02X:%02X:%02X:%02X:%02X:%02X",
                     ethAddr->addr[0], ethAddr->addr[1], ethAddr->addr[2],
                     ethAddr->addr[3], ethAddr->addr[4], ethAddr->addr[5]);
            return String(macBuf);
        }

        // not in teh arp table force a UDP packet
        forceArpResolution(ipStr);

        // retry

        // Query lwIP components to find matched hardware entries in active cache table
        lookupResult = etharp_find_addr(&netif_list[0], ip_2_ip4(&targetIp), &ethAddr, &filteredIp);

        if (lookupResult >= 0 && ethAddr != nullptr)
        {
            char macBuf[18];
            snprintf(macBuf, sizeof(macBuf), "%02X:%02X:%02X:%02X:%02X:%02X",
                     ethAddr->addr[0], ethAddr->addr[1], ethAddr->addr[2],
                     ethAddr->addr[3], ethAddr->addr[4], ethAddr->addr[5]);
            return String(macBuf);
        }

        // Default fallback identifier if network hops haven't fully filled out cache yet
        return "UNKNOWN";
    }

    void GoogleTvRemote::forceArpResolution(const String &ipStr)
    {
        IPAddress targetIP;
        if (targetIP.fromString(ipStr))
        {
            // Create a basic native UDP client
            WiFiUDP dummyClient;

            // Begin an arbitrary packet frame targeting a port
            dummyClient.beginPacket(targetIP, GIPR_GOOGLEIP_TVPORT_SEND);
            dummyClient.write(0);    // Send 1 byte of junk data
            dummyClient.endPacket(); // Fire!

            // Give the network adapter a few milliseconds to process the physical hardware response
            delay(10);
        }
    }

    GoogleTvRemote::GoogleTvRemote()
    {

        // we are not paried
        is_paired = false;
        API_state = DISCONNECTED;
    }

    void GoogleTvRemote::connectToTV(DiscoveredTv tv, progressCallback callBack)
    {
        tvInit = tv;
        callBackInit = callBack;

        // assume we are not connected
        API_state = STARTUP;
        connectRetries = 0;
    }

    void GoogleTvRemote::loopRemoteConnection()
    {
        if (API_state == DISCONNECTED)
        {
            // do nothing.
            disconnect();
            connectRetries = 0;
            return;
        }
        else if (API_state == STARTUP)
        {
            // cleaup state and conncet to the tv
            disconnect();
            connectRetries++;
            if (connectRetries > 3)
            {
                API_state = DISCONNECTED;
                UtilityFunctions::debugLogf("Tried for %i times cannot connect stopping ... \n", connectRetries - 1);
                return;
            }

            UtilityFunctions::debugLogf("Connecting to TV ....  %s retries:%i \n", tvInit.ip.c_str(), connectRetries);
            makeSSLConnectRemote();
            API_state = CONNECTED_TO_TV; // assume connceted
            return;
        }
        else if (API_state == INIT_WOL)
        {
            // send WOL and go bck to non init status. do not change the retries
            wakeUpTV(tvInit.ip);
            API_state = STARTUP;
            return;
        }

        /// we are in  connceted to tv or connceted to paring

        uint8_t buffer[80];
        int len = -1;

        /// try to read else wee are not connceted
        len = wolfSSL_read(ssl, &buffer, sizeof(buffer));

        if (len <= 0)
        {
            if (API_state == CONNECTED_TO_PAIRING)
            {
                UtilityFunctions::debugLog("ERROR in read from TV remote and we were paired we are disconnecting");
                disconnect();
                // we connected so we are in the paring mode or other mode, reset to connect
                API_state = STARTUP;
                connectRetries = 0;
                return;
            }
            else if (API_state == CONNECTED_TO_TV)
            {
                // ok we need to be in paring mode we are not paired and  this is the initial connecction
                UtilityFunctions::debugLogf("LOOP TV remote read failed on sock %i \n", sockFD);
                disconnect();
                if (!makeSSLConnectPairing())
                {
                    UtilityFunctions::debugLog("Could not connect to TV Paring port - trying WOL \n");
                    disconnect();
                    API_state = INIT_WOL;
                    return;
                }

                // send pairing request
                Pairing_PairingMessage *req = createPairingRequest();
                std::vector<uint8_t> buffer = pack_message(req);

                if (wolfSSL_send(ssl, buffer.data(), buffer.size(), 0) < buffer.size())
                {
                    UtilityFunctions::debugLog("ERROR failed to send pairing request but we connceted - trying again");
                    disconnect();
                    API_state = STARTUP;
                    return;
                }
                else
                {
                    UtilityFunctions::debugLog("[pairing] data sent");
                    printPacket(buffer.data(), buffer.size());
                }
                pb_release(Pairing_PairingRequest_fields, req);

                API_state = CONNECTED_TO_PAIRING;
                connectRetries = 0;
                return;
            }

            UtilityFunctions::debugLog("attemping to read when in DISCONNECTED state shoud not have happend");
            connectRetries = 0;
            return;
        }
        // UtilityFunctions::debugLogf("Read bytes %i from TV \n", len);
        readDataCunks.insert(readDataCunks.end(), buffer, buffer + len);
        // tilityFunctions::debugLog("bytes in buffer");
        // printPacket(readDataCunks.data(), readDataCunks.size());

        // remeber teh first byte is payload size so use that to make sure we have the full packet read
        if (readDataCunks.size() > 0 && readDataCunks[0] == readDataCunks.size() - 1)
        {

            if (API_state == CONNECTED_TO_PAIRING)
            {
                UtilityFunctions::debugLog("[Pairing]: TV sent DATA !!");
                printPacket(readDataCunks.data(), readDataCunks.size());

                // remeber teh first byte is payload size so we ignore it in unpacking
                Pairing_PairingMessage *message = unpack_paring_message(readDataCunks.data() + 1, readDataCunks.size() - 1);
                if (message != NULL)
                {
                    printParingMessage(message);
                    // paring protocol
                    if (message->has_pairing_request_ack)
                    {
                        UtilityFunctions::debugLog("[Pairing]: Pairing request ack received packet:");

                        // pb_release(Pairing_PairingRequest_fields, &message);
                        //  uint8_t *buffer = createParingOptionMsg();
                        //  wolfSSL_send(ssl, buffer, sizeof(buffer),0);
                        //  free(buffer);
                    }
                    else if (message->has_pairing_option)
                    {
                        UtilityFunctions::debugLog("[Pairing]: Pairing option received packet:");

                        // uint8_t *buffer = pairingMessageManager.createPairingConfiguration();
                        // ssl_send((char *)buffer, buffer[0] + 1);
                        // free(buffer);
                    }
                    else if (message->has_pairing_configuration_ack)
                    {
                        UtilityFunctions::debugLog("[Pairing]: Pairing configuration ack received packet\n");
                    }
                    else if (message->has_pairing_secret_ack)
                    {
                        UtilityFunctions::debugLog("[Pairing]: Pairing secret ack received packet:");

                        is_paired = true;
                        API_state = STARTUP;
                        connectRetries = 0;
                        UtilityFunctions::debugLog("[Pairing]: Paired!\n");
                    }
                    else if (message->status == Pairing_PairingMessage_Status_STATUS_OK)
                    {
                        UtilityFunctions::debugLog("[Pairing]: 200 recived for pairing send option packet:");
                        // send pairing option message
                        pb_release(Pairing_PairingRequest_fields, &message);
                        Pairing_PairingMessage *req = createParingOptionMsg();
                        std::vector<uint8_t> buffer = pack_message(req);

                        if (wolfSSL_send(ssl, buffer.data(), buffer.size(), 0) < buffer.size())
                        {
                            UtilityFunctions::debugLog("ERROR failed to send pairing optin msg - disconnecting");
                            disconnect();

                            /// retry three times
                            API_state = STARTUP;
                            connectRetries = 0;
                        }
                        else
                        {
                            UtilityFunctions::debugLog("[pairing] data sent");
                            printPacket(buffer.data(), buffer.size());
                        }
                    }
                    else
                    {
                        UtilityFunctions::debugLog("[Pairing]: Pairing Unkown type packet received:");
                        printPacket(readDataCunks.data(), readDataCunks.size());
                    }

                    // free the message
                    pb_release(Pairing_PairingRequest_fields, message);
                    // reset the buffer
                    readDataCunks.clear();
                    return;
                }
                else
                {
                    // null message received
                    // reset the buffer
                    UtilityFunctions::debugLog("[Pairing]: dropping NULL packet !!");
                    readDataCunks.clear();
                    return;
                }
            }
            else if (API_state == CONNECTED_TO_TV)
            {
                // remote functions
                UtilityFunctions::debugLog("[Remote]: TV sent DATA !!");
                Remote_RemoteMessage *message = unpack_remote_message(readDataCunks.data() + 1, readDataCunks.size() - 1);

                if (message != NULL)
                {

                    // free the message
                    pb_release(Pairing_PairingRequest_fields, message);
                    // reset the buffer
                    readDataCunks.clear();
                    return;
                }
                else
                {
                    // null message received
                    // reset the buffer
                    UtilityFunctions::debugLog("[REMOTE]: dropping NULL packet !!");
                    readDataCunks.clear();
                    return;
                }
            }
            else
            {

                // unkown state
                // drop the message buffer
                UtilityFunctions::debugLog("[Unkown STATE]: dropping packet !!");
                readDataCunks.clear();
                return;
            }
        }
    }

    void GoogleTvRemote::disconnect()
    {

        if (ssl != NULL)
        {
            wolfSSL_shutdown(ssl);
            wolfSSL_free(ssl);
            ssl = NULL;
        }

        if (ctx != NULL)
        {
            wolfSSL_CTX_free(ctx);
            ctx = NULL;
        }

        if (sockFD != -1)
        {
            UtilityFunctions::debugLogf("closing sock %i return code %i \n", sockFD, ::close(sockFD));
            sockFD = -1;
        }
    }

    void GoogleTvRemote::loopRemoteConnection()
    {
        if (!isConnected())
        {
            return;
        }

        uint8_t buffer[256];
        int len = wolfSSL_read(ssl, &buffer, sizeof(buffer));
        if (len <= 0)
        {
            if (isPaired())
            {
                UtilityFunctions::debugLog("ERROR in read from TV remote and we were paired we are disconnecting");
                disconnect();
                return;
            }
            else
            {
                // ok we need to be in paring mode we are not paired and  this is the initial connecction
                disconnect();
                is_paired = false;
                makeSSLConnectPairing(tvInit, callBackInit);

                // send pairing request
                Pairing_PairingRequest *req = createPairingRequest();
                uint8_t *buffer = pack_message(*req);
                if (wolfSSL_send(ssl, buffer, sizeof(buffer), 0) < sizeof(buffer))
                {
                    UtilityFunctions::debugLog("ERROR failed to send pairing request - disconnecting");
                    disconnect();
                }
                free(buffer);
                return;
            }
        }
        readDataCunks.insert(readDataCunks.end(), buffer, buffer + len);

        if (readDataCunks.size() > 0 && readDataCunks[0] == readDataCunks.size() - 1)
        {
            printPacket(readDataCunks.data(), readDataCunks.size());
            if (!is_paired)
            {

                Pairing_PairingMessage *message = unpack_paring_message(readDataCunks.data(), readDataCunks.size());
                if (message != NULL)
                {
                    // paring protocol
                    if (message->which_payload == Pairing_PairingMessage_pairing_request_ack_tag)
                    {
                        UtilityFunctions::debugLog("[DEBUG]: Pairing request ack received packet:");
                        printPacket(readDataCunks.data(), readDataCunks.size());

                        pb_release(Pairing_PairingRequest_fields, &message);
                        Pairing_PairingMessage *buffer = createParingOptionMsg();
                        wolfSSL_send(ssl, buffer, sizeof(buffer),0);
                        free(buffer);
                    }
                    else if (message->pairing_option)
                    {
                        UtilityFunctions::debugLog("[DEBUG]: Pairing option received packet:");
                        printPacket(chunks.data(), chunks.size());
                        // uint8_t *buffer = pairingMessageManager.createPairingConfiguration();
                        // ssl_send((char *)buffer, buffer[0] + 1);
                        // free(buffer);
                    }
                    else if (message->pairing_configuration_ack)
                    {
                        UtilityFunctions::debugLog("[DEBUG]: Pairing configuration ack received packet\n");
                        printPacket(chunks.data(), chunks.size());
                    }
                    else if (message->pairing_secret_ack)
                    {
                        UtilityFunctions::debugLog("[DEBUG]: Pairing secret ack received packet:");
                        printPacket(chunks.data(), chunks.size());
                        isSecure = false;
                        UtilityFunctions::debugLog("[DEBUG]: Paired!\n");
                    }
                    else
                    {
                        UtilityFunctions::debugLog("[DEBUG]: Unkown type packet receivepacket:");
                        printPacket(chunks.data(), chunks.size());
                    }
                }
            }
            else
            {
                Remote_RemoteMessage *message = unpack_remote_message(readDataCunks.data(), readDataCunks.size());
            }
        }
    }

    void GoogleTvRemote::disconnect()
    {
        if (ssl != NULL)
        {
            wolfSSL_free(ssl);
            ssl = NULL;
        }

        if (sockFD != -1)
        {
            close(sockFD);
            sockFD = -1;
        }

        if (ctx != NULL)
        {
            wolfSSL_CTX_free(ctx);
            ctx = NULL;
        }
    }

    bool GoogleTvRemote::createSSLCtx(progressCallback callBack)
    {

        // char *arg = (char *)String("-lng 0 -rsa_sign").c_str();
        // benchmark_test((void *)arg);

        String errMsg = "";
        bool isError = false;

        if (ctx != NULL)
        {
            wolfSSL_CTX_free(ctx);
            ctx = NULL;
        }

        // esp_ShowExtendedSystemInfo();

        WOLFSSL_METHOD *method = NULL;

        int err = wolfSSL_Init();
        errMsg = getWolfsslTxtError(NULL, err, isError);
        if (isError)
        {
            // Initialization failed
            UtilityFunctions::debugLogf("Error in crypto lib init %i:%s \n", err, errMsg.c_str());
            return false;
        }

        method = wolfSSLv23_client_method();
        if (method == NULL)
        {
            ctx = NULL;
            UtilityFunctions::debugLog("unable to get wolfssl client method");
            return false;
        }

        // ### Note 2
        // wolfSSL takes a different approach to certificate verification than OpenSSL
        // does. The default policy for the client is to verify the server, this means
        // that if you don't load CAs to verify the server you'll get a connect error,
        // no signer error to confirm failure (-188).

        // If you want to mimic OpenSSL behavior of having `SSL_connect` succeed even if
        // verifying the server fails and reducing security you can do this by calling:

        ctx = wolfSSL_CTX_new(method);
        if (ctx == NULL)
        {
            UtilityFunctions::debugLog("unable to get ctx");
            return false;
        }

        // do not verify the cert for tv
        wolfSSL_CTX_set_verify(ctx, WOLFSSL_VERIFY_NONE, NULL);

        // now we need to get our certs in the ctx
        // validate we have the certs
        if (!haveSelfCertificate())
        {
            // create new self certs this is a long running process
            if (makeNewSelfCertificate(callBack))
            {
                return false;
            }
        }

        /* Load server certificates into WOLFSSL_CTX */
        String fname = (String(GIPR_CERT_VOLPREFIX) + String(GIPR_CERT_FILE_NAME));
        if ((fopen(fname.c_str(), "rb")) == NULL)
        {
            UtilityFunctions::debugLogf("FAILED to open cert file %s \n", fname);
        }
        err = wolfSSL_CTX_use_certificate_file(ctx, fname.c_str(), SSL_FILETYPE_PEM);
        isError = false;
        errMsg = getWolfsslTxtError(NULL, err, isError);
        if (isError)
        {

            UtilityFunctions::debugLogf("Error in loading cert %i:%s for file %s \n", err, errMsg.c_str(), fname.c_str());
            return false;
        }
        else
        {
            UtilityFunctions::debugLogf("CERT read SUCCESFULLY %s \n", fname.c_str());
        }

        /* Load keys */
        fname = (String(GIPR_CERT_VOLPREFIX) + String(GIPR_PRIKEY_FILE_NAME));
        err = wolfSSL_CTX_use_PrivateKey_file(ctx, fname.c_str(), SSL_FILETYPE_PEM);
        isError = false;
        errMsg = getWolfsslTxtError(NULL, err, isError);
        if (isError)
        {

            UtilityFunctions::debugLogf("Error in loading private key %i:%s for file %s \n", err, errMsg.c_str(), fname.c_str());
            return false;
        }
        else
        {
            UtilityFunctions::debugLogf("Private KEY Read SUCCESFULLY %s \n", fname.c_str());
        }

        wolfSSL_SetIORecv(ctx, SSLReceiveBytes); // Registers system recv()
        wolfSSL_SetIOSend(ctx, SSLSendBytes);    // Registers system send()
        return true;
    }

    bool GoogleTvRemote::makeSSLConnectRemote()
    {
        UtilityFunctions::debugLog("SSL Remote conect - BEGIN");
        bool ret = makeSSLConnectBase(true);
        UtilityFunctions::debugLog("SSL Remote conect - END");
        return ret;
    }

    bool GoogleTvRemote::makeSSLConnectPairing()
    {

        // Note android paring port will NOT repond till a SSL conncet is done on the TV remote port and rejected first
        // thre is a connncet limit for security also on the pairing port
        // so while debugging you will have to go to the android tv remote service app in system apps and delete the program data to reset
        // else the conncet to piaring will just hang
        UtilityFunctions::debugLog("SSL Pairing conect - BEGIN");
        bool ret = makeSSLConnectBase(false);
        UtilityFunctions::debugLog("SSL Pairing conect - END");
        return ret;
    }

    bool GoogleTvRemote::makeSSLConnectBase(bool paring_complete)
    {
        if (tvInit.ip.isEmpty())
        {
            UtilityFunctions::debugLog("NEED to have TV selected first \n");
            return false;
        }

        if (sockFD != -1)
        {
            UtilityFunctions::debugLogf("SSL socket already open sockfd %i \n", sockFD);
            return false;
        }

        createSSLCtx(callBackInit);

        bool socketConnceted = false;
        int port = ((paring_complete) ? GIPR_GOOGLEIP_TVPORT_SEND : GIPR_GOOGLEIP_TVPORT_PAIRING);
        if (!connectTCPHandshake(port, GIPR_TCP_HANDSHAKE_TIMEOUT_MiliSec))
        {
            UtilityFunctions::debugLogf("TCP handshake failed sockFd %i, port %i \n", sockFD, port);
            disconnect();
            return false;
        }

        int err = wolfSSL_Init();
        if (err != WOLFSSL_SUCCESS)
        {
            // Initialization failed
            UtilityFunctions::debugLogf("Error in crypto lib init %i:%s \n", err, wc_GetErrorString(err));
            disconnect();
            return false;
        }

        ssl = wolfSSL_new(ctx);
        if (ssl == NULL)
        {
            UtilityFunctions::debugLog("Failed to create wolfSSL session object");
            disconnect();
            return false;
        }

        UtilityFunctions::debugLog("SSL handshake - BEGIN");
        wolfSSL_set_fd(ssl, sockFD);
        // Explicitly register the standard BSD I/O system callbacks

        // if (paring_complete == false)
        // {
        //     wolfSSL_Debugging_ON();
        // }

        // Complete Non-Blocking SSL/TLS Protocol Handshake Loop
        int ssl_err = 0;
        int ret = 0;
        do
        {
            ssl_err = WOLFSSL_SUCCESS;
            ret = WOLFSSL_SUCCESS;
            ret = wolfSSL_connect(ssl);
            ssl_err = wolfSSL_get_error(ssl, ret);
            if (ret != WOLFSSL_SUCCESS)
            {
                if (ssl_err == WOLFSSL_ERROR_WANT_READ)
                {
                    // Wait until the socket has data available to read
                    // e.g., using poll() or select() on socket_fd for reading
                    waitForSocket(wolfSSL_get_fd(ssl), WOLFSSL_ERROR_WANT_READ, GIPR_TCP_HANDSHAKE_TIMEOUT_MiliSec);
                }
                else if (ssl_err == WOLFSSL_ERROR_WANT_WRITE)
                {
                    // Wait until the socket is ready to transmit data
                    // e.g., using poll() or select() on socket_fd for writing
                    waitForSocket(wolfSSL_get_wfd(ssl), WOLFSSL_ERROR_WANT_WRITE, GIPR_TCP_HANDSHAKE_TIMEOUT_MiliSec);
                }
                else if (ssl_err == WOLFSSL_ERROR_ZERO_RETURN)
                {

                    UtilityFunctions::debugLog("SSL Handshake client closed connecction");
                    disconnect();
                    wolfSSL_Debugging_OFF();
                    return false;
                }
                else
                {
                    UtilityFunctions::debugLogf("SSL Handshake broken downstream: SSL_connect return %i decoded err  %i: %s \n", ret, ssl_err, wc_GetErrorString(ssl_err));
                    disconnect();
                    wolfSSL_Debugging_OFF();
                    return false;
                }
            }

        } while (ret != WOLFSSL_SUCCESS);

        wolfSSL_Debugging_OFF();
        UtilityFunctions::debugLogf("socked fd %i conncted. \n", sockFD);
        UtilityFunctions::debugLog("SSL handshake - END");
        return true;
    }

    bool GoogleTvRemote::connectTCPHandshake(uint16_t port, int32_t timeout_ms)
    {

        sockFD = socket(AF_INET, SOCK_STREAM, IPPROTO_IP);

        if (sockFD < 0)
        {
            UtilityFunctions::debugLogf("SSL socket opening error got id %i \n", sockFD);
            disconnect();
            return false;
        }

        UtilityFunctions::debugLogf("SSL socket new open sockfd %i \n", sockFD);
        int flags = fcntl(sockFD, F_GETFL, 0);
        fcntl(sockFD, F_SETFL, flags | O_NONBLOCK);

        struct sockaddr_storage serveraddr = {};
        struct sockaddr_in *dest_addr = (struct sockaddr_in *)&serveraddr;
        dest_addr->sin_family = AF_INET;
        dest_addr->sin_addr.s_addr = IPAddress(tvInit.ip.c_str());
        dest_addr->sin_port = htons(port);

        // Start non-blocking raw TCP connection
        int res = lwip_connect(sockFD, (struct sockaddr *)&serveraddr, sizeof(serveraddr));
        if (res < 0 && errno != EINPROGRESS)
        {
            UtilityFunctions::debugLog("TCP Connection failed immediately");
            disconnect();
            return false;
        }

        if (!waitForSocket(sockFD, (WOLFSSL_ERROR_WANT_WRITE), timeout_ms))
        {

            UtilityFunctions::debugLogf("TCP Connection async TIMEOUT, Fd %i res %i socket errno: %i  \n", sockFD, res, errno);
            disconnect();
            return false;
        }

        // Verify if connection actually succeeded or if the port was closed
        int sock_err = 0;
        socklen_t len = (socklen_t)sizeof(int);

        res = getsockopt(sockFD, SOL_SOCKET, SO_ERROR, &sock_err, &len);

        if (res < 0)
        {
            UtilityFunctions::debugLogf("TCP Connection async failure 1, Fd %i res %i socket error: %i: %s \n", sockFD, res, errno, strerror(errno));
            disconnect();
            return false;
        }

        if (sock_err != 0)
        {
            UtilityFunctions::debugLogf("TCP Connection async failure 2, Fd %i res %i socket error: %i: %s \n", sockFD, res, sock_err, strerror(sock_err));
            disconnect();
            return false;
        }

        struct timeval tv;
        tv.tv_sec = timeout_ms / 1000;
        tv.tv_usec = 0;
        int enable = 1; // 1 means "true" or "turn on"

        if (setsockopt(sockFD, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv)) < 0)
        {
            UtilityFunctions::debugLogf("TCP Connection set send timeout failed , Fd %i socket error: %i: %s \n", sockFD, errno, strerror(errno));
        }
        if (setsockopt(sockFD, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0)
        {
            UtilityFunctions::debugLogf("TCP Connection set receiv timeout failed , Fd %i  socket error: %i: %s \n", sockFD, errno, strerror(errno));
        }

        if (setsockopt(sockFD, IPPROTO_TCP, TCP_NODELAY, &enable, sizeof(enable)) < 0)
        {

            UtilityFunctions::debugLogf("TCP Connection set TCP No delay failed , Fd %i socket error: %i: %s \n", sockFD, errno, strerror(errno));
        }
        if (setsockopt(sockFD, SOL_SOCKET, SO_KEEPALIVE, &enable, sizeof(enable)) < 0)
        {
            UtilityFunctions::debugLogf("TCP Connection set TCP keepalive failed , Fd %i socket error: %i: %s \n", sockFD, errno, strerror(errno));
        }

        return true;
    }

    // Event handler to capture response events and statusesesp_err_t
    esp_err_t GoogleTvRemote::http_WOL_event_handler(esp_http_client_event_t *evt)
    {
        switch (evt->event_id)
        {
        case HTTP_EVENT_ERROR:
            UtilityFunctions::debugLog("[WOL] HTTP_EVENT_ERROR");
            break;
        case HTTP_EVENT_ON_CONNECTED:
            UtilityFunctions::debugLog("[WOL] HTTP_EVENT_ON_CONNECTED");
            break;
        case HTTP_EVENT_HEADER_SENT:
            UtilityFunctions::debugLog("[WOL] HTTP_EVENT_HEADER_SENT");
            break;
        case HTTP_EVENT_ON_HEADER:
            UtilityFunctions::debugLogf("[WOL] HTTP_EVENT_ON_HEADER, key=%s, value=%s \n", evt->header_key, evt->header_value);
            break;
        case HTTP_EVENT_ON_DATA:
            UtilityFunctions::debugLogf("[WOL] HTTP_EVENT_ON_DATA, len=%d \n", evt->data_len);
            if (!esp_http_client_is_chunked_response(evt->client))
            {
                // Print response data if any comes back from the server
                UtilityFunctions::debugLogf("[WOL] data back from tc %i : %s \n", evt->data_len, (char *)evt->data);
            }
            break;
        case HTTP_EVENT_ON_FINISH:
            UtilityFunctions::debugLog("[WOL] HTTP_EVENT_ON_FINISH");
            break;
        case HTTP_EVENT_DISCONNECTED:
            UtilityFunctions::debugLog("[WOL] HTTP_EVENT_DISCONNECTED");
            break;
        default:
            break;
        }
        return ESP_OK;
    }

    bool GoogleTvRemote::wakeUpTV(String ip)
    {
        bool sucess = false;
        // Configure the client
        String url = "http://" + ip + ":8008/apps/ChromeCast";
        char *urlBuf = new char[url.length() + 1];
        strcpy(urlBuf, url.c_str());

        esp_http_client_config_t config = {
            .url = urlBuf, // Replace with your target URL
            .event_handler = http_WOL_event_handler,
        };

        esp_http_client_handle_t client = esp_http_client_init(&config);

        // Set the HTTP Method to POST
        esp_http_client_set_method(client, HTTP_METHOD_POST);

        // Add mandatory Chromecast security headers
        esp_http_client_set_header(client, "Content-Type", "application/x-www-form-urlencoded");
        esp_http_client_set_header(client, "Origin", "chrome-extension://boadgeojelhgndaghljhdicfkmllpafd");

        // Send a blank payload by explicitly setting NULL fields
        esp_http_client_set_post_field(client, NULL, 0);

        // Execute the POST request
        esp_err_t err = esp_http_client_perform(client);

        if (err == ESP_OK)
        {
            UtilityFunctions::debugLogf("[WOL] HTTP POST Status = %d, content_length = %i \n",
                                        esp_http_client_get_status_code(client),
                                        esp_http_client_get_content_length(client));
            sucess = true;
        }
        else
        {
            UtilityFunctions::debugLogf("HTTP POST request failed: %s \n", esp_err_to_name(err));
        }

        // 6. Clean up resources
        delete (urlBuf);
        esp_http_client_cleanup(client);
        return sucess;
    }

    int GoogleTvRemote::SSLSendBytes(WOLFSSL *ssl, char *msg, int sz, void *ctx)
    {
        int sock = wolfSSL_get_fd(ssl); /* read  file descriptor */

        int sent = send(sock, msg, sz, 0);

        if (sent > 0)
        {
            return sent; // Success: Return bytes written to network interface
        }

        if (errno == EWOULDBLOCK || errno == EAGAIN)
        {
            // [CRITICAL] Outbound kernel buffer full, retry when writable
            return WOLFSSL_CBIO_ERR_WANT_WRITE;
        }

        if (errno == EPIPE || errno == ECONNRESET)
        {
            return WOLFSSL_CBIO_ERR_CONN_CLOSE;
        }

        return WOLFSSL_CBIO_ERR_GENERAL;
    }

    int GoogleTvRemote::SSLReceiveBytes(WOLFSSL *ssl, char *reply, int sz, void *ctx)
    {
        int sock = wolfSSL_get_wfd(ssl); /* write  file descriptor */

        // Call the underlying non-blocking socket layer
        int recvd = recv(sock, reply, sz, 0);

        if (recvd > 0)
        {
            return recvd; // Success: Return number of bytes processed
        }

        if (recvd == 0)
        {
            return WOLFSSL_CBIO_ERR_CONN_CLOSE; // Remote peer disconnected cleanly
        }

        // recvd is -1: Inspect the specific LwIP errno
        if (errno == EWOULDBLOCK || errno == EAGAIN)
        {
            // Inform wolfSSL to yield and poll later without failing
            return WOLFSSL_CBIO_ERR_WANT_READ;
        }

        if (errno == ECONNRESET)
        {
            return WOLFSSL_CBIO_ERR_CONN_RST; // Connection hard-reset by peer
        }

        return WOLFSSL_CBIO_ERR_GENERAL; // Any other fatal socket exception
    }

    bool GoogleTvRemote::waitForSocket(int socket_fd, int condition, int32_t timeout_ms)
    {
        fd_set read_fds;
        fd_set write_fds;
        struct timeval timeout;
        int select_result;

        // Clear and initialize the file descriptor sets
        FD_ZERO(&read_fds);
        FD_ZERO(&write_fds);

        // Set a 60-second timeout
        timeout.tv_sec = timeout_ms / 1000;
        timeout.tv_usec = 0;

        // select() requires the first argument to be the highest fd value plus 1
        int nfds = socket_fd + 1;

        if (condition == WOLFSSL_ERROR_WANT_READ)
        {
            FD_SET(socket_fd, &read_fds);
            select_result = select(nfds, &read_fds, NULL, NULL, NULL);
        }
        else if (condition == WOLFSSL_ERROR_WANT_WRITE)
        {
            FD_SET(socket_fd, &write_fds);
            select_result = select(nfds, NULL, &write_fds, NULL, NULL);
        }
        else if (condition == (WOLFSSL_ERROR_WANT_READ + WOLFSSL_ERROR_WANT_WRITE))
        {
            FD_SET(socket_fd, &read_fds);
            FD_SET(socket_fd, &write_fds);
            select_result = select(nfds, &read_fds, &write_fds, NULL, NULL);
        }
        else
        {
            return false; // Invalid condition
        }

        if (select_result > 0)
        {

            return true;
        }
        else if (select_result == 0)
        {
            UtilityFunctions::debugLogf("Socket fd %i, tims out in TCP process type %i \n", socket_fd, condition);
        }
        else if (select_result < 0)
        {

            UtilityFunctions::debugLogf("Socket fd %i,  errno: %d, %s \n", socket_fd, errno, strerror(errno));
        }
        return false;
    }

    Pairing_PairingMessage *GoogleTvRemote::unpack_paring_message(const uint8_t *buffer, size_t buffer_length)
    {
        // Allocate your generated target structure on the stack
        // (Always zero-initialize with the NanoPB macro to clear junk memory)
        Pairing_PairingMessage *message = new (Pairing_PairingMessage);
        // Create an input stream pointing to your raw data buffer
        pb_istream_t stream = pb_istream_from_buffer(buffer, buffer_length);

        // Unpack/Decode the payload
        if (!pb_decode(&stream, Pairing_PairingMessage_fields, &message))
        {
            // Handle decoding failure
            UtilityFunctions::debugLog("decoding failed");
            return NULL;
        }

        // Clean up any allocated sub-fields (Only needed if you use dynamic callbacks/pointers)
        // pb_release(Remote_Message_fields, &message);

        return message;
    }

    Remote_RemoteMessage *GoogleTvRemote::unpack_remote_message(const uint8_t *buffer, size_t buffer_length)
    {
        // Allocate your generated target structure on the stack
        // (Always zero-initialize with the NanoPB macro to clear junk memory)
        Remote_RemoteMessage *message = new (Remote_RemoteMessage);
        *message = Remote_RemoteMessage_init_zero;

        // Create an input stream pointing to your raw data buffer
        pb_istream_t stream = pb_istream_from_buffer(buffer, buffer_length);

        // Unpack/Decode the payload
        if (!pb_decode(&stream, Remote_RemoteMessage_fields, &message))
        {
            // Handle decoding failure
            UtilityFunctions::debugLog("decoding failed");
            return NULL;
        }

        // (If your fields contain sub-messages or specific payloads)
        // process_payload(message);

        //  Clean up any allocated sub-fields (Only needed if you use dynamic callbacks/pointers)
        // pb_release(Remote_Message_fields, &message);

        return message;
    }

    Pairing_PairingMessage *GoogleTvRemote::createPairingRequest()
    {
        Pairing_PairingRequest *req = new Pairing_PairingRequest();

        req->service_name = "service_name";
        char *buf = new char[UtilityFunctions::loadLocalHostname().length() + 1];

        strcpy(buf, UtilityFunctions::loadLocalHostname().c_str());

        buf[UtilityFunctions::loadLocalHostname().length()] = 0;
        req->client_name = buf;

        size_t paringReq_encoded_size = 0;
        if (!pb_get_encoded_size(&paringReq_encoded_size, Pairing_PairingRequest_fields, req))
        {

            paringReq_encoded_size = 0;
        }

        _Pairing_PairingMessage *message = new Pairing_PairingMessage();

        message->protocol_version = 2;
        message->status = Pairing_PairingMessage_Status_STATUS_OK;
        // message->playload_size = paringReq_encoded_size + 9;

        message->has_pairing_request = true;
        message->pairing_request = *req;

        return message;
    }

    std::vector<uint8_t> GoogleTvRemote::pack_message(Pairing_PairingMessage *msg)
    {
        int size = (strlen(msg->pairing_request.service_name) + strlen(msg->pairing_request.client_name)) + 11;
        std::vector<uint8_t> out_buffer(size);

        pb_ostream_t stream = pb_ostream_from_buffer(out_buffer.data(), size);

        if (!pb_encode(&stream, Pairing_PairingMessage_fields, msg))
        {
            UtilityFunctions::debugLogf("Encoding Pairing_PairingMessage_fields failed: %s encored bytes %i \n", PB_GET_ERROR(&stream), stream.bytes_written);
            out_buffer.clear();
            out_buffer.shrink_to_fit();
            return out_buffer;
        }

        UtilityFunctions::debugLogf("Encoding Pairing_PairingMessage_fields used bytes %i vs message size of %i \n", stream.bytes_written, size);

        out_buffer.resize(stream.bytes_written);

        encodeMessegToSend(out_buffer);

        return out_buffer;
    }

    void GoogleTvRemote::encodeMessegToSend(std::vector<uint8_t> &dataBuffer)
    {
        // we need to add an byte in the front for the payload
        dataBuffer.shrink_to_fit();
        int size = dataBuffer.size();
        UtilityFunctions::debugLogf("In ecoding data buffer size is %i \n", size);
        dataBuffer.resize(size + 1);
        dataBuffer.insert(dataBuffer.begin(), size);
        dataBuffer.resize(size + 1);
    }

    Pairing_PairingMessage *GoogleTvRemote::createParingOptionMsg()
    {

        Pairing_PairingMessage *message = new Pairing_PairingMessage();

        message->status = Pairing_PairingMessage_Status_STATUS_OK;
        message->protocol_version = 2;

        message->has_pairing_option = true;
        message->pairing_option = Pairing_PairingOption_init_default;

        message->pairing_option.preferred_role = Pairing_RoleType_ROLE_TYPE_INPUT;

        message->pairing_option.input_encodings[0].type = Pairing_PairingEncoding_EncodingType_ENCODING_TYPE_HEXADECIMAL;
        message->pairing_option.input_encodings[0].symbol_length = 6;

        message->pairing_option.input_encodings_count = 1;

        // message->playload_size = sizeof(Pairing_PairingOption);

        return message;
    }

    bool GoogleTvRemote::isConnected()
    {
        if (sockFD == -1)
        {
            UtilityFunctions::debugLog("is coonnected false, sockFd = -1");
            return false;
        }

        char buffer;
        // Peek at 1 byte from the network queue instantly
        int res = recv(sockFD, &buffer, 1, MSG_PEEK | MSG_DONTWAIT);

        if (res == 0)
        {
            UtilityFunctions::debugLogf("is connected false, sockFd = %i \n", sockFD);
            disconnect();
            return false; // Remote server disconnected cleanly
        }
        if (res < 0)
        {
            if (errno == EWOULDBLOCK || errno == EAGAIN)
            {
                UtilityFunctions::debugLogf("is connected true, sockFd = %i \n", sockFD);
                return true; // Still connected, no data waiting
            }

            UtilityFunctions::debugLogf("is coonnected false, sockFd = %i \n", sockFD);
            disconnect();
            return false; // Hard connection failure
        }

        UtilityFunctions::debugLogf("is connected true, sockFd = %i \n", sockFD);
        return true; // Still connected, data is waiting to be read
    }

    void GoogleTvRemote::unPair()
    {
        is_paired = false;
    }

    String GoogleTvRemote::getWolfsslTxtError(WOLFSSL *ssl, int error, bool &isError)
    {

        if (ssl == NULL)
        {
            isError = (error != WOLFSSL_SUCCESS);
            return String(wc_GetErrorString(error));
        }
        else
        {
            int decodedError = wolfSSL_get_error(ssl, error);
            if (decodedError == WOLFSSL_SUCCESS)
            {
                isError = false;
                return "";
            }
            // Convert the negative integer (e.g. -132) into descriptive text
            isError = true;
            return String(wc_GetErrorString(decodedError));
        }
    }

    void GoogleTvRemote::printPacket(uint8_t *packet, size_t len)
    {
        String str = "unit8array: [";
        for (size_t i = 0; i < len; i++)
        {
            char hex_buf[6]; // Space for "0xXX "
            snprintf(hex_buf, sizeof(hex_buf), "%i", packet[i]);
            str = str + hex_buf;
            if (i < (len - 1))
            {
                str = str + (",");
            }
        }
        str = str + "] hex: ";

        for (size_t i = 0; i < len; i++)
        {
            char hex_buf[6]; // Space for "0xXX "
            snprintf(hex_buf, sizeof(hex_buf), "%02X", packet[i]);
            str = str + hex_buf;
        }
        UtilityFunctions::debugLog(str);
    }

    void GoogleTvRemote::printParingMessage(Pairing_PairingMessage *msg)
    {
        if (msg == NULL)
        {
            UtilityFunctions::debugLog("NULL paring messge -- end.");
            return;
        }

        UtilityFunctions::debugLogf("Msg protocol version: %i, msg status %i, has has_pairing_request: %i, has_pairing_request_ack: %i, has_pairing_option: %i, has_pairing_configuration: %i, has_pairing_configuration_ack: %i, has_pairing_secret: %i, has_pairing_secret_ack: %i \n", msg->protocol_version, msg->status, msg->has_pairing_request, msg->has_pairing_request_ack, msg->has_pairing_option, msg->has_pairing_configuration, msg->has_pairing_configuration_ack, msg->has_pairing_secret, msg->has_pairing_secret_ack);
    }

    bool GoogleTvRemote::haveSelfCertificate()
    {
        if (!FFat.begin(true))
        {
            UtilityFunctions::debugLog("GoogleTvRemote: An Error has occurred while mounting FFat");
            return NULL;
        }

        UtilityFunctions::debugLog("GoogleTvRemote: Mounted FFat OK");

        // check if we have a cert and provate key on the disk
        File file = FFat.open(GIPR_CERT_FILE_NAME, "r");

        if (file)
        {
            // Extract the file footprint size
            size_t file_size = file.size();
            if (file_size == 0)
            {
                UtilityFunctions::debugLog(STRINGIFY(GIPR_CERT_FILE_NAME + ":file is empty"));
                file.close();
                return false;
            }
        }
        else
        {
            // CERT does not exist
            return false;
        }

        file = FFat.open(GIPR_PRIKEY_FILE_NAME, "r");
        if (file)
        {
            // Extract the file footprint size
            size_t file_size = file.size();
            if (file_size == 0)
            {
                UtilityFunctions::debugLog(STRINGIFY(GIPR_PRIKEY_FILE_NAME + ":file is empty"));
                file.close();
                return false;
            }
        }
        else
        {
            // CERT does not exist so create a new one nd save
            return false;
        }

        return true;
    }

    // make the certs, sign and save on to the FFat partition
    bool GoogleTvRemote::makeNewSelfCertificate(progressCallback callBack)
    {
        // Output scratch buffers (PEM formatting requires extra room for Base64 wrapping)
        // Allocate heavy scratch buffers dynamically onto the heap to protect the stack
        uint8_t *der_buffer = (uint8_t *)malloc(GIPR_DER_BUFFER);
        char *pem_output_buffer = (char *)malloc(GIPR_PEM_BUFFER);
        char error_text_buffer[80];

        WC_RNG *rng = new (WC_RNG);
        RsaKey *key = new (RsaKey);
        RsaNb *nb = new (RsaNb);

        Cert *myCert = new (Cert);
        int der_len = 0;
        int pem_len = 0;

        if (!FFat.begin(true))
        {
            UtilityFunctions::debugLog("Webserver: An Error has occurred while mounting FFat");
            return false;
        }

        // Initialize random number generator and RSA key structure
        // int err = wc_InitRng(rng);
        int err = wc_InitRng_ex(rng, NULL, 0);
        if (err != 0)
        {

            // Convert the negative integer (e.g. -132) into descriptive text
            wolfSSL_ERR_error_string_n(err, error_text_buffer, sizeof(error_text_buffer));
            UtilityFunctions::debugLogf("RNG Init Failed %i:%s \n", err, error_text_buffer);
            // Free memory objects
            free(der_buffer);
            free(pem_output_buffer);
            delete (rng);
            delete (key);
            delete (nb);
            delete (myCert);
            return false;
        }

        // err = wc_InitRsaKey(key, NULL);
        err = wc_InitRsaKey_ex(key, NULL, 0);
        if (err != 0)
        {
            wolfSSL_ERR_error_string_n(err, error_text_buffer, sizeof(error_text_buffer));
            UtilityFunctions::debugLogf("RSA Key Init Failed %i:%s \n", err, error_text_buffer);

            // Free memory objects
            wc_FreeRng(rng);
            free(der_buffer);
            free(pem_output_buffer);
            delete (rng);
            delete (key);
            delete (nb);
            delete (myCert);
            return false;
        }

        err = wc_RsaSetNonBlock(key, nb);
        if (err != 0)
        {

            wolfSSL_ERR_error_string_n(err, error_text_buffer, sizeof(error_text_buffer));
            UtilityFunctions::debugLogf("Key Non Bock feature set failed! %i:%s \n", err, error_text_buffer);

            // Free  memory objects
            wc_FreeRsaKey(key);
            wc_FreeRng(rng);
            free(der_buffer);
            free(pem_output_buffer);
            delete (rng);
            delete (key);
            delete (nb);
            delete (myCert);
            return false;
        }

        err = wc_RsaSetNonBlockTime(key, GIPR_RSA_NONBLOCK_TIME, ESP.getCpuFreqMHz()); // Block Max = 1000 micro seconds = 1 mili sec
        if (err != 0)
        {

            wolfSSL_ERR_error_string_n(err, error_text_buffer, sizeof(error_text_buffer));
            UtilityFunctions::debugLogf("Key Non Block time set failed! %i:%s \n", err, error_text_buffer);

            // Free  memory objects
            wc_FreeRsaKey(key);
            wc_FreeRng(rng);
            free(der_buffer);
            free(pem_output_buffer);
            delete (rng);
            delete (key);
            delete (nb);
            delete (myCert);
            return false;
        }

#ifdef WC_RSA_BLINDING
        err = wc_RsaSetRNG(key, rng);
        if (err != 0)
        {

            wolfSSL_ERR_error_string_n(err, error_text_buffer, sizeof(error_text_buffer));
            UtilityFunctions::debugLogf("Key RNG BINDING et failed! %i:%s \n", err, error_text_buffer);

            // Free  memory objects
            wc_FreeRsaKey(key);
            wc_FreeRng(rng);
            free(der_buffer);
            free(pem_output_buffer);
            delete (rng);
            delete (key);
            delete (nb);
            delete (myCert);
            return false;
        }

#endif

        UtilityFunctions::debugLog("Generating 2048-bit RSA Key pair...");
        int blockCount = 0;

        // disbale watchdog on idle task
        // UtilityFunctions::disableTWDTimeronIdleTaskOnCore(xPortGetCoreID());
        do
        {
            err = wc_MakeRsaKey(key, ((int)GIPR_RSA_KEY_LENGTH), ((long)65537), rng);
            blockCount++;
            if (err == FP_WOULDBLOCK)
            {
                UtilityFunctions::delay(GIPR_DELAY_TO_YEILD_MiliSec);
                if (callBack != NULL)
                {
                    callBack("Creating RSA Key", blockCount);
                }
            }

        } while (err == FP_WOULDBLOCK);

        // enable watchdog on idle task
        // UtilityFunctions::enableTWDTimeronIdleTaskOnCore(xPortGetCoreID());
        if (err != 0)
        {

            wolfSSL_ERR_error_string_n(err, error_text_buffer, sizeof(error_text_buffer));
            UtilityFunctions::debugLogf("Key generation failed! %i:%s \n", err, error_text_buffer);

            // Free  memory objects
            wc_FreeRsaKey(key);
            wc_FreeRng(rng);
            free(der_buffer);
            free(pem_output_buffer);
            delete (rng);
            delete (key);
            delete (nb);
            delete (myCert);
            return false;
        }

        if (callBack != NULL)
        {
            callBack("Creating RSA Key", 100);
        }
        UtilityFunctions::debugLogf("Key generation succeded in %i blocks!  \n", blockCount);

        // // Convert Private Key to DER bytes format
        // der_len = wc_RsaKeyToDer(key, der_buffer, GIPR_DER_BUFFER);
        // if (der_len < 0)
        // {
        //     wolfSSL_ERR_error_string_n(der_len, error_text_buffer, sizeof(error_text_buffer));
        //     UtilityFunctions::debugLogf("Key der buffer len failed, error: %d: %s \n", der_len, error_text_buffer);

        //     // Free memory objects
        //     wc_FreeRsaKey(key);
        //     wc_FreeRng(rng);
        //     free(der_buffer);
        //     free(pem_output_buffer);
        //     delete (rng);
        //     delete (key);
        //     delete (nb);
        //     delete (myCert);
        //     return false;
        // }
        // UtilityFunctions::debugLogf("Key der buffer len %i \n", der_len);
        // // ESP_LOG_BUFFER_HEX_LEVEL("RSA KEY", der_buffer, der_len, ESP_LOG_ERROR);

        // Initialize and populate your istinguished Name details
        wc_InitCert(myCert);
        strncpy(myCert->subject.commonName, UtilityFunctions::loadLocalHostname().c_str(), CTC_NAME_SIZE);
        // strncpy(myCert->subject.country, GIPR_CERT_COUNTRY, CTC_NAME_SIZE);
        // strncpy(myCert->subject.state, GIPR_CERT_STATE, CTC_NAME_SIZE);
        // strncpy(myCert->subject.locality, GIPR_CERT_CITY, CTC_NAME_SIZE);
        // strncpy(myCert->subject.org, GIPR_CERT_ORG, CTC_NAME_SIZE);
        // strncpy(myCert->subject.unit, GIPR_CERT_UNIT, CTC_NAME_SIZE);
        // strncpy(myCert->subject.email, GIPR_CERT_EMAIL, CTC_NAME_SIZE);

        // Set 10-year validity (~3650 days)
        myCert->daysValid = 3650;
        myCert->isCA = 1;
        myCert->basicConstSet = 1;
        myCert->pathLenSet = 1; /* Enable the path length constraint field */
        myCert->pathLen = 0;    /* Maximum number of non-self-issued intermediate CAs that can follow this certificate */
        myCert->sigType = CTC_SHA256wRSA;
        myCert->version = 2;

        // /* Use wolfSSL's max size macro constraint */
        // char myAltNames[255];
        // strcpy(myAltNames,("DNS Name=" + UtilityFunctions::loadLocalHostname()).c_str());

        // /* Safely copy the string buffer and assign the size */
        // XMEMCPY(myCert->altNames, myAltNames, XSTRLEN(myAltNames));
        // myCert->altNamesSz = (word32)XSTRLEN(myAltNames);

        // Build the certificate body ONCE (This step will not return WC_PENDING_E)
        // zero out der buffer;
        memset(der_buffer, 0, GIPR_DER_BUFFER);
        err = wc_MakeCert(myCert, der_buffer, GIPR_DER_BUFFER, key, NULL, rng);
        if (err < 0)
        {

            wolfSSL_ERR_error_string_n(err, error_text_buffer, sizeof(error_text_buffer));
            UtilityFunctions::debugLogf("failed to make x.509 cert body, error: %d: %s \n", der_len, error_text_buffer);

            // Free memory objects
            wc_FreeRsaKey(key);
            wc_FreeRng(rng);
            free(der_buffer);
            free(pem_output_buffer);
            delete (rng);
            delete (key);
            delete (nb);
            delete (myCert);
            return false;
        }

        UtilityFunctions::debugLog("Signing X.509 Certificate...");
        // Generate self-signed certificate bytes (DER format)
        blockCount = 0;
        err = 0;
        do
        {
            err = wc_SignCert(myCert->bodySz, myCert->sigType, der_buffer, GIPR_DER_BUFFER, key, NULL, rng);

            blockCount++;
            if (err == FP_WOULDBLOCK || err == WC_PENDING_E)
            {
                UtilityFunctions::delay(GIPR_DELAY_TO_YEILD_MiliSec);

                if (callBack != NULL)
                {
                    callBack("Creating Signed Cert", blockCount / 2000);
                }
            }

            if ((blockCount & 15) == 0)
            {
                UtilityFunctions::debugLogf("Cert signing .... current block:%i \n", blockCount);
            }
        } while ((err == FP_WOULDBLOCK) || (err == WC_PENDING_E));

        if (err < 0)
        {
            wolfSSL_ERR_error_string_n(err, error_text_buffer, sizeof(error_text_buffer));
            UtilityFunctions::debugLogf("Cert signing failed, error: %d: %s \n", err, error_text_buffer);

            // Free memory objects
            wc_FreeRsaKey(key);
            wc_FreeRng(rng);
            free(der_buffer);
            free(pem_output_buffer);
            delete (rng);
            delete (key);
            delete (nb);
            delete (myCert);
            return false;
        }

        if (callBack != NULL)
        {
            callBack("Creating Signed Cert", 100);
        }

        int cert_len = err;
        UtilityFunctions::debugLogf("Cert signing succeded in %i blocks!  \n", blockCount);

        // Convert and Print Certificate to PEM layout
        // (Replaces openssl_x509_export)
        pem_len = wc_DerToPem(der_buffer, cert_len, (uint8_t *)pem_output_buffer, GIPR_PEM_BUFFER, CA_TYPE);
        if (pem_len > 0)
        {
            UtilityFunctions::debugLog("--- START GENERATED CLIENT.PEM ---");
            UtilityFunctions::debugLog(pem_output_buffer);
            ffat_write_buffer(GIPR_CERT_FILE_NAME, pem_output_buffer, pem_len, "", "");
        }
        else
        {

            wolfSSL_ERR_error_string_n(pem_len, error_text_buffer, sizeof(error_text_buffer));
            UtilityFunctions::debugLogf("Cert PEM generation failed, error: %d: %s \n", pem_len, error_text_buffer);

            // Free memory objects
            wc_FreeRsaKey(key);
            wc_FreeRng(rng);
            free(der_buffer);
            free(pem_output_buffer);
            delete (rng);
            delete (key);
            delete (nb);
            delete (myCert);
            return false;
        }

        // Convert Private Key to DER bytes format
        memset(der_buffer, 0, GIPR_DER_BUFFER);
        der_len = wc_RsaKeyToDer(key, der_buffer, GIPR_DER_BUFFER);

        // Convert and Print Private Key to PEM layout
        // (Replaces openssl_pkey_export)
        memset(pem_output_buffer, 0, sizeof(pem_output_buffer));
        pem_len = wc_DerToPem(der_buffer, der_len, (uint8_t *)pem_output_buffer, GIPR_PEM_BUFFER, PRIVATEKEY_TYPE);
        if (pem_len > 0)
        {

            UtilityFunctions::debugLog(pem_output_buffer);
            UtilityFunctions::debugLog("--- END GENERATED CLIENT.PEM ---\n");
            ffat_write_buffer(GIPR_PRIKEY_FILE_NAME, pem_output_buffer, pem_len, "", "");
        }
        else
        {

            wolfSSL_ERR_error_string_n(pem_len, error_text_buffer, sizeof(error_text_buffer));
            UtilityFunctions::debugLogf("private key PEM generation failed, error: %d: %s \n", pem_len, error_text_buffer);

            // Free memory objects
            wc_FreeRsaKey(key);
            wc_FreeRng(rng);
            free(der_buffer);
            free(pem_output_buffer);
            delete (rng);
            delete (key);
            delete (nb);
            delete (myCert);
            return false;
        }

        // Free stack tracking memory objects
        // Clean up active cryptographic resources safely
        wc_FreeRsaKey(key);
        wc_FreeRng(rng);

        // Wipe and release heap buffers safely
        free(der_buffer);
        free(pem_output_buffer);
        delete (rng);
        delete (key);
        delete (nb);
        delete (myCert);
        return true;
    }

    bool GoogleTvRemote::isPaired()
    {
        return is_paired;
    }

    /**
     * @brief Writes a memory buffer to a file on the FFat partition, overwriting previous contents.
     *
     * @param path           Absolute path to the file (e.g., "/config.bin")
     * @param buffer         Pointer to the data source
     * @param bytes_to_write Number of bytes to copy from the buffer
     * @return FRESULT       FR_OK on success, or FatFs error code on failure
     */
    FRESULT GoogleTvRemote::ffat_write_buffer(const TCHAR *path, const void *buffer, UINT bytes_to_write, String beginMessage, String endMessage)
    {
        FIL file;
        FRESULT res;
        UINT bytes_written = 0;
        UINT bytes_writtenTot = 0;

        // FA_CREATE_ALWAYS: Creates a new file. If it already exists, truncates length to 0.
        // FA_WRITE: Request write-access permissions.
        res = f_open(&file, path, FA_CREATE_ALWAYS | FA_WRITE);
        if (res != FR_OK)
        {
            std::string resStr = "";
#if defined(CONFIG_NIMBLE_USE_MAGIC_ENUM)
            resStr = ((magic_enum::enum_flags_name(res)));
#endif
            UtilityFunctions::debugLogf("File %s write error code %i : %s \n", path, res, resStr.c_str());
            return res;
        }

        // Write buffer data to the file structure
        if (!beginMessage.isEmpty())
        {
            f_write(&file, beginMessage.c_str(), beginMessage.length(), &bytes_written);
        }
        if (res != FR_OK)
        {
            std::string resStr = "";
#if defined(CONFIG_NIMBLE_USE_MAGIC_ENUM)
            resStr = ((magic_enum::enum_flags_name(res)));
#endif
            UtilityFunctions::debugLogf("File %s write error code %i : %s \n", path, res, resStr.c_str());
            f_close(&file); // Ensure file is closed even if write fails
            return res;
        }

        bytes_writtenTot = bytes_writtenTot + bytes_written;
        bytes_written = 0;

        res = f_write(&file, buffer, bytes_to_write, &bytes_written);
        if (res != FR_OK)
        {
            std::string resStr = "";
#if defined(CONFIG_NIMBLE_USE_MAGIC_ENUM)
            resStr = ((magic_enum::enum_flags_name(res)));
#endif
            UtilityFunctions::debugLogf("File %s write filed error code %i : %s \n", path, res, resStr.c_str());
            f_close(&file); // Ensure file is closed even if write fails
            return res;
        }

        bytes_writtenTot = bytes_writtenTot + bytes_written;
        bytes_written = 0;

        // Write buffer data to the file structure
        if (!endMessage.isEmpty())
        {
            f_write(&file, endMessage.c_str(), endMessage.length(), &bytes_written);
        }
        if (res != FR_OK)
        {
            std::string resStr = "";
#if defined(CONFIG_NIMBLE_USE_MAGIC_ENUM)
            resStr = ((magic_enum::enum_flags_name(res)));
#endif
            UtilityFunctions::debugLogf("File %s write error code %i : %s \n", path, res, resStr.c_str());
            f_close(&file); // Ensure file is closed even if write fails
            return res;
        }

        bytes_writtenTot = bytes_writtenTot + bytes_written;
        bytes_written = 0;
        // Check if the drive ran out of space mid-write
        if (bytes_writtenTot < ((bytes_to_write + beginMessage.length() + endMessage.length())))
        {
            UtilityFunctions::debugLogf("File %s ERROR written only  %i when requested %i \n", path, bytes_writtenTot, (bytes_to_write + beginMessage.length() + endMessage.length()));
            f_close(&file);
            return FR_DISK_ERR; // Returns disk error if storage became full
        }

        // Close the file to flush the sector caches onto the underlying flash memory
        res = f_close(&file);
        return res;
    }
}
