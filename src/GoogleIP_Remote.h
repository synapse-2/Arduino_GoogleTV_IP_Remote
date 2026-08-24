#pragma once

#include <Arduino.h>
#include <vector>
#include <string>

#define GOOGLEIP_TVPORT_SEND 6466
#define ANDRIOD_TV_RMOETE_SERVICE "androidtvremote2"
#define GOOGLE_CROMECAST_SERVICE "googlecast"
#define GOOGLE_FRENDLY_NAME "fn"
#define ANDROID_BT_NAME "bt"
#define GOOGLE_MODEL_NAME "md"

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

    class GoogleTvRemote
    {
    public:
        GoogleTvRemote();
        ~GoogleTvRemote();

        // get the TV's on the IP network
        static std::vector<DiscoveredTv> scanForTvs();

        // Connection lifecycle
        //bool connect(const char *ipAddress, const char *clientCert, const char *clientKey);
        //void disconnect();
        //bool isConnected();
        //void loop(); // Must be called in main loop to process pings/keepalives

        // Remote input actions
        // bool sendKey(Keycode keycode, Direction direction = Direction_SHORT);
        //bool sendPing();

    protected:
        static String getMacFromIp(const String &ipStr);
        static void forceArpResolution(const String& ipStr);

        const char *_ip;
        unsigned long _lastPingTime;
        const unsigned long _pingInterval = 5000; // Keep-alive interval

        // Helper to abstract Nanopb encoding and socket transmission
        // bool transmitMessage(const RemoteMessage &message);
    };

}