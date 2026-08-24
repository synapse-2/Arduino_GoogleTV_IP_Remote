#include "GoogleIP_Remote.h"
#include <ESPmDNS.h>
#include <WiFi.h>
#include <lwip/etharp.h>
#include <lwip/ip_addr.h>
#include <UtilityFunctions.h>

namespace GoogleIPRemote
{
    std::vector<DiscoveredTv> GoogleTvRemote::scanForTvs()
    {
        std::vector<DiscoveredTv> tvList;

        for (int f = 0; f < 3; f++)
        {
            UtilityFunctions::debugLog("[Discovery] Browsing for _androidtvremote2._tcp services ...");
            // Query mDNS for the specific Android/Google TV remote service service type
            int numServices = MDNS.queryService(ANDRIOD_TV_RMOETE_SERVICE, "tcp");

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
                    if (MDNS.hasTxt(i, ANDROID_BT_NAME))
                    {
                        tv.btMac = MDNS.txt(i, ANDROID_BT_NAME);
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

            numServices = MDNS.queryService(GOOGLE_CROMECAST_SERVICE, "tcp");
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
                            if (MDNS.hasTxt(i, GOOGLE_FRENDLY_NAME))
                            {
                                existingDev.friendlyName = MDNS.txt(i, GOOGLE_FRENDLY_NAME);
                            }

                            if (MDNS.hasTxt(i, GOOGLE_MODEL_NAME))
                            {
                                existingDev.model = MDNS.txt(i, GOOGLE_MODEL_NAME);
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
            dummyClient.beginPacket(targetIP, GOOGLEIP_TVPORT_SEND);
            dummyClient.write(0);    // Send 1 byte of junk data
            dummyClient.endPacket(); // Fire!

            // Give the network adapter a few milliseconds to process the physical hardware response
            delay(10);
        }
    }
}