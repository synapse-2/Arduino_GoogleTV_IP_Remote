#include <Arduino.h>
#include <ESPmDNS.h>
#include <vector>
#include "GoogleIP_Remote.h"
#include <Arduino_DebugUtils.h>
#include <UtilityFunctions.h>
#include "WebLogPrint.h"

#include <wolfssl/ssl.h>

// auto matically include wifi manager if wifi is enabled
#ifdef CONFIG_ESP_WIFI_ENABLED
#include <WiFiManager.h>
#include <WiFiType.h>
#endif

#include "magic_enum/magic_enum.hpp"
#include "magic_enum/magic_enum_iostream.hpp"

template <typename E>
auto to_integer(magic_enum::Enum<E> value) -> int
{
  // magic_enum::Enum<E> - C++17 Concept for enum type.
  return static_cast<magic_enum::underlying_type_t<E>>(value);
}

// have the wifi managwer log to the web logger
#ifdef CONFIG_ESP_WIFI_ENABLED
WiFiManager wm = WiFiManager(*(new WebLogPrint()));
uint64_t Wifi_Disconnect_Start_Time = 0;

String getSSID() { return wm.getWiFiSSID(); }
String getPSK() { return wm.getWiFiPass(); }
#endif

void MyRSATask(void *pvParameters)
{
  // Get the handle of the task that created this one
  TaskHandle_t calling_task = (TaskHandle_t)pvParameters;

  // ... rsa operations ...
  GoogleIPRemote::GoogleTvRemote::makeNewSelfCertificate();

  // Send a notification directly back to the calling task
  xTaskNotifyGive(calling_task);

  // Delete the task when finished to free up memory
  vTaskDelete(NULL);
}

void setup()
{

  Serial.begin(250000);
  // Wait for the serial console to be ready. This is a blocking spin-wait
  // that exits once `Serial` becomes available (host opens serial terminal).
  // Exit condition: `Serial` evaluates true.
  while (!Serial)
    ; // wait for serial attach

  UtilityFunctions::debugLog("Initializing google tv ip remote...");
  UtilityFunctions::UtilityFunctionsInit(); // Initialize utility functions

  // Check if the device is in master or slave mode
  // If device is master: initialize cloud/WiFi functionality, otherwise
  // run in BLE-only (slave) mode. Exit from this block when setup
  // completes or after a restart is triggered on failure.
  if (UtilityFunctions::isMaster())
  {

    /**
     * @brief Setup (what happens once when the BluetoothESP32 device wakes up)
     *
     * Plain words: This function runs one time when the BluetoothESP32 device starts. It
     * turns on the console (so we can see messages), sets up WiFi (if we are
     * the boss/master), starts the little web server that helps configure
     * the BluetoothESP32 device, and gets everything ready for the repeating work in
     * `loop()`.
     *
     * Important steps:
     * - Start serial console for debug messages
     * - Redirect ESP logs to the web logger so logs are viewable remotely
     * - Initialize utility code and the command ring buffer
     * - If master: start WiFiManager to connect to WiFi or create an AP
     * - Create the web server so users can interact through a browser
     *
     * Loops: this function does not contain repeated loops except possible
     * short LED blink loops to show activity.
     */

#ifndef CONFIG_ESP_WIFI_ENABLED
    UtilityFunctions::debugLog("WIFI is truned off");
#else

    // set time zone
    setenv("TZ", "CST6CDT,M3.2.0,M11.1.0", 1);
    tzset();

    // reset settings - wipe stored credentials for testing
    //  these are stored by the esp library
    //  wm.resetSettings();

    // Automatically connect using saved credentials,
    // if connection fails, it starts an access point with the specified name (
    // "AutoConnectAP"), if empty will auto generate SSID, if password is blank
    // it will be anonymous AP (wm.autoConnect()) then goes into a blocking loop
    // awaiting configuration and will return success result

    UtilityFunctions::setupWiFiAndConnect();

    esp_log_level_set("*", ESP_LOG_INFO);

    // enable NTP server
    UtilityFunctions::enableNTPTimeServer("pool.ntp.org");

    if (!MDNS.begin("esp32_discovery"))
    {
      UtilityFunctions::ledBlinkRedLong();
      UtilityFunctions::debugLog("Error setting up mDNS responder: RESTARTING");
      UtilityFunctions::ESP32Restart();
    }
#endif
  }


  TaskHandle_t current_task_handle = xTaskGetCurrentTaskHandle();

  // Create the worker task explicitly bound to CPU Core 1
  xTaskCreatePinnedToCore(
      MyRSATask,    // Function pointer to your task code
      "RSA_Worker", // Human-readable string name of the task
      16384,        // Stack depth allocation (16KB)
      (void *)current_task_handle, // Task input parameters block 
      1,                           // Task priority level (Set to 1 or lower)
      NULL,                        // Task handle tracking instance variable pointer
      1                            // Core ID Index Target (0 = CPU 0, 1 = CPU 1)
  );
}

void loop()
{
  UtilityFunctions::debugLog("LOOP TASK Running...");

  // Check if the device is in master or slave mode

  if (UtilityFunctions::isMaster())
  {
    UtilityFunctions::debugLog(" Starting WIFI Connext ");

    for (;;) // infinite loop
    {

      /// do work  handle
      UtilityFunctions::ledBlinkBlue();

      /// do work
      UtilityFunctions::delay(500);
      // other updates such as BLE, arduinoIot, web server etc are to be put here

#ifdef CONFIG_ESP_WIFI_ENABLED
      // put wifi dependent code here for the loop
      // Execute the TV search
      std::vector<GoogleIPRemote::DiscoveredTv> foundTvs = GoogleIPRemote::GoogleTvRemote::scanForTvs();
      // Print the clean summary block
      UtilityFunctions::debugLog("\n===== DISCOVERED GOOGLE TV DEVICES =====");
      for (const auto &tv : foundTvs)
      {
        Serial.printf("Device host Name: %s\n", tv.hostName.c_str());
        Serial.printf("IP Address:  %s\n", tv.ip.c_str());
        Serial.printf("BT MAC Address: %s\n", tv.btMac.c_str());
        Serial.printf("Device friendly Name: %s\n", tv.friendlyName.c_str());
        Serial.printf("Device model: %s\n", tv.model.c_str());
        Serial.printf("Device IP mac: %s\n", tv.ipMac.c_str());
        Serial.println("----------------------------------------");
      }

#endif
      // work done
      UtilityFunctions::ledStop();

      UtilityFunctions::checkResetPressed(); // Check if the reset button has been pressed

#ifdef CONFIG_ESP_WIFI_ENABLED
      UtilityFunctions::rebootIfWiFiDisconnected(); // check for wifi disconet due to router issues
#endif
    }
  }
}
