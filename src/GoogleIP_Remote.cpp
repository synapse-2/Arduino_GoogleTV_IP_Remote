/* wolfSSL */
/* Always include wolfcrypt/settings.h before any other wolfSSL file.    */
/* Reminder: settings.h pulls in user_settings.h; don't include it here. */
/* undefine Arduino as that gives an error in WOLFSSL */

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

#if defined(CONFIG_NIMBLE_USE_MAGIC_ENUM)
#include "magic_enum/magic_enum.hpp"
#include "magic_enum/magic_enum_iostream.hpp"
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
    }

    bool GoogleTvRemote::connectToTV(DiscoveredTv tv, progressCallback callBack)
    {
        if (ctx == NULL)
        {
            createSSLCtx(callBack);
            return true;
        }

        return true;
    }

    bool GoogleTvRemote::createSSLCtx(progressCallback callBack)
    {
        char error_text_buffer[80];
        if (ctx != NULL)
        {
            UtilityFunctions::debugLog("Wolfssl ctx already exists, exiting");
            return true;
        }

        WOLFSSL_METHOD *method = NULL;

        wolfSSL_Debugging_ON();
        int err = wolfSSL_Init();
        if (err != WOLFSSL_SUCCESS)
        {
            // Initialization failed
            UtilityFunctions::debugLogf("Error in crypto lib init %i:%s \n", err, GoogleIPRemote::GoogleTvRemote::getWolfsslTxtError(err));
            return false;
        }

        
        WOLFSSL_MSG("My Event");
        method = wolfSSLv23_client_method();
        if (method == NULL)
        {
            ctx = NULL;
            UtilityFunctions::debugLog("unable to get wolfssl client method");
            return false;
        }

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
        err = wolfSSL_CTX_use_certificate_file(ctx, GIPR_CERT_FILE_NAME, SSL_FILETYPE_PEM);
        if (err != SSL_SUCCESS)
        {
            wolfSSL_ERR_error_string_n(err, error_text_buffer, sizeof(error_text_buffer));
            UtilityFunctions::debugLogf("Error in loading cert %i:%s \n", err, error_text_buffer);
            return false;
        }

        /* Load keys */
        err = wolfSSL_CTX_use_PrivateKey_file(ctx, GIPR_PRIKEY_FILE_NAME, SSL_FILETYPE_PEM);
        if (err != SSL_SUCCESS)
        {
            wolfSSL_ERR_error_string_n(err, error_text_buffer, sizeof(error_text_buffer));
            UtilityFunctions::debugLogf("Error in loading private key %i:%s \n", err, error_text_buffer);
            return false;
        }

        return true;
    }

    String GoogleTvRemote::getWolfsslTxtError(int error)
    {
        char error_text_buffer[GIPR_WOLFSSL_ERROR_TXT_BUFF];

        // Convert the negative integer (e.g. -132) into descriptive text
        wolfSSL_ERR_error_string_n(error, error_text_buffer, sizeof(error_text_buffer));
        return String(error_text_buffer);
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
        int err = wc_InitRng(rng);
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

        err = wc_InitRsaKey(key, NULL);
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

        UtilityFunctions::debugLog("Generating 2048-bit RSA Key pair...");
        int blockCount = 0;

        // disbale watchdog on idle task
        // UtilityFunctions::disableTWDTimeronIdleTaskOnCore(xPortGetCoreID());
        do
        {
            err = wc_MakeRsaKey(key, GIPR_RSA_KEY_LENGTH, (long)65537, rng);
            blockCount++;
            if (err = FP_WOULDBLOCK)
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
        if (err < 0)
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
        // Convert Private Key to DER bytes format
        der_len = wc_RsaKeyToDer(key, der_buffer, GIPR_DER_BUFFER);
        if (der_len < 0)
        {
            wolfSSL_ERR_error_string_n(der_len, error_text_buffer, sizeof(error_text_buffer));
            UtilityFunctions::debugLogf("Key der buffer len failed, error: %d: %s \n", der_len, error_text_buffer);

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
        UtilityFunctions::debugLogf("Key der buffer len %i \n", der_len);
        // ESP_LOG_BUFFER_HEX_LEVEL("RSA KEY", der_buffer, der_len, ESP_LOG_ERROR);

        // Initialize and populate your istinguished Name details
        wc_InitCert(myCert);
        strncpy(myCert->subject.commonName, UtilityFunctions::loadLocalHostname().c_str(), CTC_NAME_SIZE);
        strncpy(myCert->subject.country, GIPR_CERT_COUNTRY, CTC_NAME_SIZE);
        strncpy(myCert->subject.state, GIPR_CERT_STATE, CTC_NAME_SIZE);
        strncpy(myCert->subject.locality, GIPR_CERT_CITY, CTC_NAME_SIZE);
        strncpy(myCert->subject.org, GIPR_CERT_ORG, CTC_NAME_SIZE);
        strncpy(myCert->subject.unit, GIPR_CERT_UNIT, CTC_NAME_SIZE);
        strncpy(myCert->subject.email, GIPR_CERT_EMAIL, CTC_NAME_SIZE);

        // Set 10-year validity (~3650 days)
        myCert->daysValid = 3650;
        myCert->isCA = 0;
        myCert->sigType = CTC_SHA256wRSA;

        UtilityFunctions::debugLog("Signing X.509 Certificate...");
        // Generate self-signed certificate bytes (DER format)
        blockCount = 0;
        err = 0;
        do
        {
            err = wc_MakeSelfCert(myCert, der_buffer, GIPR_DER_BUFFER, key, rng);

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
            wolfSSL_ERR_error_string_n(der_len, error_text_buffer, sizeof(error_text_buffer));
            UtilityFunctions::debugLogf("Cert signing failed, error: %d: %s \n", der_len, error_text_buffer);

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
        memset(pem_output_buffer, 0, 4096);
        pem_len = wc_DerToPem(der_buffer, cert_len, (uint8_t *)pem_output_buffer, GIPR_PEM_BUFFER, CERT_TYPE);
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