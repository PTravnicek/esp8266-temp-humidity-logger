#include <Arduino.h>
#include <WiFi.h>
#include <WebServer.h>
#include <LittleFS.h>
#include <SD.h>
#include <SPI.h>
#include <Wire.h>
#include <ArduinoJson.h>
#include <SHT85.h>
#include <RTClib.h>
#include <time.h>
#include <mbedtls/sha256.h>

// Hardware objects (SHT85 I2C default address 0x44)
SHT85 sht(0x44);
RTC_PCF8523 rtc;
bool rtcPresent = false;
bool sensorPresent = false;

// FireBeetle 2 ESP32-S3: onboard LED = GPIO 21 (D13), I2C default SDA=1 SCL=2, SD_CS=9
#define LED_PIN 21
#define SD_CS 9
#define I2C_SDA 1
#define I2C_SCL 2
unsigned long lastHeartbeat = 0;
const unsigned long HEARTBEAT_INTERVAL = 3000; // 3 seconds

// Network objects
WebServer server(80);
IPAddress apIP(192, 168, 4, 1);

// Config structure
struct Config {
  int config_version = 1;
  String device_id;
  String ap_ssid;
  String ap_password = "logger123";
  String auth_hash;
  String auth_salt;
  uint32_t sample_period_s = 3600;
  int32_t log_timezone_offset_min = 0;
  String file_rotation = "monthly";
  bool time_set = false;
  String heating_mode = "off";
} config;

// Session management
struct AuthSession {
  String token;
  unsigned long expires;
};
AuthSession authSessions[10];
int sessionCount = 0;
const unsigned long SESSION_TIMEOUT = 3600000; // 1 hour

// Sampling
unsigned long lastSampleTime = 0;
bool sdPresent = false;
uint32_t writeErrors = 0;

// SHT85 heater state machine (non-blocking)
bool heaterActive = false;           // true while heater is on
unsigned long heaterStartMs = 0;    // when current heating started
unsigned long lastHeaterCycleEndMs = 0;  // when last heating cycle ended

// LittleFS ring-buffer settings (match larger partition; was 256 KB)
#ifndef LFS_RING_MAX_BYTES_DEFAULT
#define LFS_RING_MAX_BYTES_DEFAULT (4 * 1024 * 1024)
#endif
#ifndef LFS_RING_RECORD_LEN_DEFAULT
#define LFS_RING_RECORD_LEN_DEFAULT 96
#endif
const size_t LFS_RING_MAX_BYTES = LFS_RING_MAX_BYTES_DEFAULT;
const size_t LFS_RING_RECORD_LEN = LFS_RING_RECORD_LEN_DEFAULT;

// Helper functions
String getChipId() {
  uint64_t mac = ESP.getEfuseMac();
  char buf[17];
  snprintf(buf, sizeof(buf), "%04x%08x", (uint32_t)(mac >> 32), (uint32_t)mac);
  return String(buf);
}

time_t parseISO8601(const String& iso);

String generateSessionToken() {
  // 128-bit token encoded as 32 hex chars
  uint32_t a = esp_random();
  uint32_t b = esp_random();
  uint32_t c = esp_random();
  uint32_t d = esp_random();
  char buf[33];
  snprintf(buf, sizeof(buf), "%08x%08x%08x%08x", a, b, c, d);
  return String(buf);
}

String bytesToHex(const uint8_t* bytes, size_t len) {
  const char* hex = "0123456789abcdef";
  String out;
  out.reserve(len * 2);
  for (size_t i = 0; i < len; i++) {
    out += hex[(bytes[i] >> 4) & 0x0F];
    out += hex[bytes[i] & 0x0F];
  }
  return out;
}

String hashPasswordLegacy(const String& password, const String& salt) {
  // Legacy (weak) 32-bit hash kept for backward-compat with existing config.json
  String combined = password + salt;
  uint32_t hash = 0;
  for (size_t i = 0; i < combined.length(); i++) {
    hash = ((hash << 5) + hash) + combined.charAt(i);
  }
  return String(hash, HEX);
}

String hashPasswordSHA256(const String& password, const String& salt) {
  String combined = password + salt;
  uint8_t out[32];

  mbedtls_sha256_context ctx;
  mbedtls_sha256_init(&ctx);
  mbedtls_sha256_starts_ret(&ctx, 0 /* is224 */);
  mbedtls_sha256_update_ret(&ctx, (const unsigned char*)combined.c_str(), combined.length());
  mbedtls_sha256_finish_ret(&ctx, out);
  mbedtls_sha256_free(&ctx);

  return bytesToHex(out, sizeof(out));
}

String hashPassword(const String& password, const String& salt) {
  // Default to strong hashing for new configs
  return hashPasswordSHA256(password, salt);
}

String generateSalt() {
  // 64-bit salt encoded as 16 hex chars
  uint32_t a = esp_random();
  uint32_t b = esp_random();
  char buf[17];
  snprintf(buf, sizeof(buf), "%08x%08x", a, b);
  return String(buf);
}

bool verifyPassword(const String& password, const String& hash, const String& salt) {
  if (hash.length() >= 64) {
    String computed = hashPasswordSHA256(password, salt);
    String h = hash;
    computed.toLowerCase();
    h.toLowerCase();
    return computed == h;
  }
  String computed = hashPasswordLegacy(password, salt);
  return computed == hash;
}

String getSessionToken() {
  if (!server.hasHeader("Cookie")) {
    return "";
  }
  String cookie = server.header("Cookie");
  int start = cookie.indexOf("SESSION=");
  if (start == -1) return "";
  start += 8;
  int end = cookie.indexOf(";", start);
  if (end == -1) end = cookie.length();
  return cookie.substring(start, end);
}

bool isAuthenticated() {
  String token = getSessionToken();
  if (token.length() == 0) return false;
  
  unsigned long now = millis();
  for (int i = 0; i < sessionCount; i++) {
    if (authSessions[i].token == token && authSessions[i].expires > now) {
      return true;
    }
  }
  return false;
}

void addSession(const String& token) {
  if (sessionCount >= 10) {
    // Remove oldest session
    for (int i = 0; i < 9; i++) {
      authSessions[i] = authSessions[i + 1];
    }
    sessionCount = 9;
  }
  authSessions[sessionCount].token = token;
  authSessions[sessionCount].expires = millis() + SESSION_TIMEOUT;
  sessionCount++;
}

void removeSession(const String& token) {
  for (int i = 0; i < sessionCount; i++) {
    if (authSessions[i].token == token) {
      for (int j = i; j < sessionCount - 1; j++) {
        authSessions[j] = authSessions[j + 1];
      }
      sessionCount--;
      break;
    }
  }
}

bool requireAuth() {
  if (!isAuthenticated()) {
    server.sendHeader("Location", "/login");
    server.send(302, "text/plain", "");
    return false;
  }
  return true;
}

bool requireApiAuth() {
  if (!isAuthenticated()) {
    server.send(401, "application/json", "{\"error\":\"Unauthorized\"}");
    return false;
  }
  return true;
}

// Config management
bool loadConfig() {
  if (!LittleFS.exists("/config.json")) {
    return false;
  }
  
  File file = LittleFS.open("/config.json", "r");
  if (!file) {
    return false;
  }
  
  String content = file.readString();
  file.close();
  
  DynamicJsonDocument doc(1024);
  DeserializationError error = deserializeJson(doc, content);
  if (error) {
    return false;
  }
  
  config.config_version = doc["config_version"] | 1;
  {
    const char* p;
    p = doc["device_id"].as<const char*>();
    config.device_id = (p && p[0]) ? String(p) : ("LOGGER_" + getChipId());
    p = doc["ap_ssid"].as<const char*>();
    config.ap_ssid = (p && p[0]) ? String(p) : ("LOGGER_" + getChipId());
    p = doc["ap_password"].as<const char*>();
    config.ap_password = (p && p[0]) ? String(p) : "logger123";
    if (config.ap_password.length() < 8 || config.ap_password.length() > 63) {
      config.ap_password = "logger123";
    }
    p = doc["auth_hash"].as<const char*>();
    config.auth_hash = p ? String(p) : "";
    p = doc["auth_salt"].as<const char*>();
    config.auth_salt = p ? String(p) : "";
    p = doc["file_rotation"].as<const char*>();
    config.file_rotation = (p && p[0]) ? String(p) : "monthly";
    p = doc["heating_mode"].as<const char*>();
    config.heating_mode = (p && p[0]) ? String(p) : "off";
  }
  config.sample_period_s = doc["sample_period_s"] | 3600;
  config.log_timezone_offset_min = doc["log_timezone_offset_min"] | 0;
  config.time_set = doc["time_set"] | false;
  
  return true;
}

bool saveConfig() {
  DynamicJsonDocument doc(1024);
  doc["config_version"] = config.config_version;
  doc["device_id"] = config.device_id;
  doc["ap_ssid"] = config.ap_ssid;
  doc["ap_password"] = config.ap_password;
  doc["auth_hash"] = config.auth_hash;
  doc["auth_salt"] = config.auth_salt;
  doc["sample_period_s"] = config.sample_period_s;
  doc["log_timezone_offset_min"] = config.log_timezone_offset_min;
  doc["file_rotation"] = config.file_rotation;
  doc["time_set"] = config.time_set;
  doc["heating_mode"] = config.heating_mode;
  
  File file = LittleFS.open("/config.json", "w");
  if (!file) {
    return false;
  }
  
  serializeJson(doc, file);
  file.close();
  return true;
}

void getDefaultConfig() {
  String chipId = getChipId();
  config.device_id = "LOGGER_" + chipId;
  config.ap_ssid = "LOGGER_" + chipId;
  config.ap_password = "logger123";
  
  // Set default password hash (password: "admin")
  String defaultPassword = "admin";
  config.auth_salt = generateSalt();
  config.auth_hash = hashPassword(defaultPassword, config.auth_salt);
  
  config.sample_period_s = 3600;
  config.log_timezone_offset_min = 0;
  config.file_rotation = "monthly";
  config.time_set = false;
  config.heating_mode = "off";
}

// Time functions
String getISOTimestamp() {
  time_t now = time(nullptr);
  if (now < 946684800) { // Before 2000-01-01, time not set
    return "1970-01-01T00:00:00Z";
  }
  
  struct tm* timeinfo = gmtime(&now);
  int year = timeinfo->tm_year + 1900;
  int month = timeinfo->tm_mon + 1;
  int day = timeinfo->tm_mday;
  int hour = timeinfo->tm_hour;
  int minute = timeinfo->tm_min;
  int second = timeinfo->tm_sec;
  String ts = String(year);
  ts += "-";
  if (month < 10) ts += "0";
  ts += String(month);
  ts += "-";
  if (day < 10) ts += "0";
  ts += String(day);
  ts += "T";
  if (hour < 10) ts += "0";
  ts += String(hour);
  ts += ":";
  if (minute < 10) ts += "0";
  ts += String(minute);
  ts += ":";
  if (second < 10) ts += "0";
  ts += String(second);
  ts += "Z";
  return ts;
}

String getLogFilename() {
  time_t now = time(nullptr);
  struct tm* timeinfo = gmtime(&now);
  char buffer[40];
  snprintf(buffer, sizeof(buffer), "/logs/%04d-%02d.csv",
           timeinfo->tm_year + 1900, timeinfo->tm_mon + 1);
  return String(buffer);
}

String getLogFilenameForMonth(int year, int month) {
  char buffer[40];
  snprintf(buffer, sizeof(buffer), "/logs/%04d-%02d.csv", year, month);
  return String(buffer);
}

void normalizeMonthStart(time_t epoch, int& year, int& month) {
  struct tm* t = gmtime(&epoch);
  year = t->tm_year + 1900;
  month = t->tm_mon + 1;
}

size_t lfsRingHeaderSize() {
  String header = "RB1\n";
  header += "W:00000000\n";
  header += "C:00000000\n";
  header += "H:timestamp,device_id,temperature_c,humidity_rh\n";
  return header.length();
}

size_t lfsRingSlotCount(size_t dataStart) {
  if (LFS_RING_MAX_BYTES <= dataStart + LFS_RING_RECORD_LEN) {
    return 0;
  }
  return (LFS_RING_MAX_BYTES - dataStart) / LFS_RING_RECORD_LEN;
}

void lfsRingWriteHeader(File& file, unsigned long offset, unsigned long count) {
  file.seek(0);
  file.print("RB1\n");
  char buffer[32];
  snprintf(buffer, sizeof(buffer), "W:%08lu\n", offset);
  file.print(buffer);
  snprintf(buffer, sizeof(buffer), "C:%08lu\n", count);
  file.print(buffer);
  file.print("H:timestamp,device_id,temperature_c,humidity_rh\n");
}

bool lfsRingReadHeader(File& file, size_t& dataStart, unsigned long& offset, unsigned long& count, size_t& slots) {
  file.seek(0);
  String magic = file.readStringUntil('\n');
  if (magic != "RB1") {
    return false;
  }

  String offsetLine = file.readStringUntil('\n');
  String countLine = file.readStringUntil('\n');
  String headerLine = file.readStringUntil('\n');

  if (!offsetLine.startsWith("W:") || !countLine.startsWith("C:") || !headerLine.startsWith("H:")) {
    return false;
  }

  offset = offsetLine.substring(2).toInt();
  count = countLine.substring(2).toInt();
  dataStart = magic.length() + 1 + offsetLine.length() + 1 + countLine.length() + 1 + headerLine.length() + 1;
  slots = lfsRingSlotCount(dataStart);
  if (slots == 0 || offset >= slots || count > slots) {
    return false;
  }

  return true;
}

String lfsRingTrimRecord(const char* buf, size_t len) {
  if (len == 0) return "";
  int end = (int)len;
  while (end > 0 && (buf[end - 1] == ' ' || buf[end - 1] == '\n' || buf[end - 1] == '\r' || buf[end - 1] == '\0')) {
    end--;
  }
  if (end <= 0) return "";
  String out = "";
  for (int i = 0; i < end; i++) {
    if (buf[i] == '\0') break;
    out += buf[i];
  }
  return out;
}

bool writeLfsRingRecord(const String& filename, const String& line) {
  File file = LittleFS.open(filename, "r+");
  if (!file) {
    file = LittleFS.open(filename, "w+");
  }
  if (!file) {
    Serial.println("LittleFS file open failed: " + filename);
    return false;
  }

  size_t dataStart = 0;
  unsigned long offset = 0;
  unsigned long count = 0;
  size_t slots = 0;

  if (!lfsRingReadHeader(file, dataStart, offset, count, slots)) {
    file.close();
    file = LittleFS.open(filename, "w+");
    if (!file) {
      Serial.println("LittleFS file reinit failed: " + filename);
      return false;
    }
    lfsRingWriteHeader(file, 0, 0);
    dataStart = lfsRingHeaderSize();
    slots = lfsRingSlotCount(dataStart);
    if (slots == 0) {
      file.close();
      Serial.println("LittleFS ring buffer size too small");
      return false;
    }
    offset = 0;
    count = 0;
  }

  String record = line;
  if (record.endsWith("\n")) {
    record.remove(record.length() - 1);
  }
  if (record.length() > LFS_RING_RECORD_LEN - 1) {
    record = record.substring(0, LFS_RING_RECORD_LEN - 1);
  }
  while (record.length() < LFS_RING_RECORD_LEN - 1) {
    record += " ";
  }
  record += "\n";

  size_t pos = dataStart + (offset * LFS_RING_RECORD_LEN);
  file.seek(pos);
  size_t written = file.print(record);

  if (written != LFS_RING_RECORD_LEN) {
    file.close();
    Serial.println("LittleFS ring write failed");
    return false;
  }

  offset = (offset + 1) % slots;
  if (count < slots) {
    count++;
  }

  lfsRingWriteHeader(file, offset, count);
  file.flush();
  file.close();
  return true;
}

// Data logging
bool writeDataPoint(float temperature, float humidity) {
  String timestamp = getISOTimestamp();
  String filename = getLogFilename();
  String line = timestamp + "," + config.device_id + "," + 
                String(temperature, 2) + "," + String(humidity, 2) + "\n";
  
  Serial.print("Writing to: ");
  Serial.println(filename);
  
  bool lfsSuccess = false;
  bool sdSuccess = false;
  
  // Ensure /logs/ directory exists on LittleFS
  if (!LittleFS.exists("/logs")) {
    LittleFS.mkdir("/logs");
    Serial.println("Created /logs directory on LittleFS");
  }
  
  // Write to LittleFS (primary) using ring-buffer format
  if (writeLfsRingRecord(filename, line)) {
      lfsSuccess = true;
  }
  
  // Write to SD (backup)
  if (sdPresent) {
    // Ensure /logs/ directory exists on SD
    if (!SD.exists("/logs")) {
      SD.mkdir("/logs");
      Serial.println("Created /logs directory on SD");
    }
    
    bool sdExists = SD.exists(filename);
    File sdFile = SD.open(filename, FILE_WRITE);
    if (sdFile) {
      // Seek to end for append (FILE_WRITE may not auto-append on all platforms)
      sdFile.seek(sdFile.size());
      // Write header if file is new
      if (!sdExists) {
        sdFile.print("timestamp,device_id,temperature_c,humidity_rh\n");
      }
      sdFile.print(line);
      sdFile.flush();  // Force write to SD
      sdFile.close();
      sdSuccess = true;
    } else {
      Serial.println("SD file open failed: " + filename);
    }
  }
  
  if (!lfsSuccess && !sdSuccess) {
    writeErrors++;
    Serial.println("BOTH storage writes failed!");
    return false;
  }
  
  return true;
}

size_t estimateSampleBytes() {
  // Fixed ring-buffer record size
  return LFS_RING_RECORD_LEN;
}

// API Handlers
void handleRoot() {
  // Serve index.html without auth - login modal handles authentication
  File file = LittleFS.open("/index.html", "r");
  if (!file) {
    server.send(404, "text/plain", "File not found");
    return;
  }
  server.streamFile(file, "text/html");
  file.close();
}

void handleLogin() {
  if (server.method() == HTTP_GET) {
    // Serve index.html (login modal will show)
    File file = LittleFS.open("/index.html", "r");
    if (!file) {
      server.send(404, "text/plain", "File not found");
      return;
    }
    server.streamFile(file, "text/html");
    file.close();
  } else if (server.method() == HTTP_POST) {
    if (!server.hasArg("password")) {
      server.send(400, "application/json", "{\"error\":\"Missing password\"}");
      return;
    }
    
    String password = server.arg("password");
    if (verifyPassword(password, config.auth_hash, config.auth_salt)) {
      // If the stored hash is legacy (32-bit), transparently upgrade it on successful login.
      if (config.auth_hash.length() < 64) {
        config.auth_salt = generateSalt();
        config.auth_hash = hashPasswordSHA256(password, config.auth_salt);
        saveConfig();
      }

      String token = generateSessionToken();
      addSession(token);
      // Cookie hardening: HttpOnly + SameSite. (No Secure flag because this is usually served over plain HTTP on a local AP.)
      server.sendHeader("Set-Cookie", "SESSION=" + token + "; Path=/; Max-Age=3600; HttpOnly; SameSite=Strict");
      server.send(200, "application/json", "{\"success\":true}");
    } else {
      server.send(401, "application/json", "{\"error\":\"Invalid password\"}");
    }
  }
}

void handleLogout() {
  String token = getSessionToken();
  if (token.length() > 0) {
    removeSession(token);
  }
  server.sendHeader("Set-Cookie", "SESSION=; Path=/; Max-Age=0; HttpOnly; SameSite=Strict");
  server.sendHeader("Location", "/login");
  server.send(302, "text/plain", "");
}

void handleApiConfig() {
  // No auth required - WiFi password is sufficient
  
  if (server.method() == HTTP_GET) {
    DynamicJsonDocument doc(512);
    doc["device_id"] = config.device_id;
    doc["sample_period_s"] = config.sample_period_s;
    doc["log_timezone_offset_min"] = config.log_timezone_offset_min;
    doc["file_rotation"] = config.file_rotation;
    doc["time_set"] = config.time_set;
    doc["heating_mode"] = config.heating_mode;
    
    String response;
    serializeJson(doc, response);
    server.send(200, "application/json", response);
  } else if (server.method() == HTTP_POST) {
    if (!server.hasArg("plain")) {
      server.send(400, "application/json", "{\"error\":\"Invalid request\"}");
      return;
    }
    
    DynamicJsonDocument doc(512);
    DeserializationError error = deserializeJson(doc, server.arg("plain"));
    if (error) {
      server.send(400, "application/json", "{\"error\":\"Invalid JSON\"}");
      return;
    }
    
    if (doc.containsKey("sample_period_s")) {
      uint32_t period = doc["sample_period_s"];
      if (period >= 10 && period <= 604800) { // 10s to 7 days
        config.sample_period_s = period;
      } else {
        server.send(400, "application/json", "{\"error\":\"Invalid sample period\"}");
        return;
      }
    }
    
    if (doc.containsKey("log_timezone_offset_min")) {
      config.log_timezone_offset_min = doc["log_timezone_offset_min"];
    }
    
    if (doc.containsKey("heating_mode")) {
      const char* mode = doc["heating_mode"].as<const char*>();
      if (mode) {
        String m = String(mode);
        if (m == "off" || m == "10s_5min" || m == "1min_1hr" || m == "1min_1day") {
          config.heating_mode = m;
        }
      }
    }
    
    if (saveConfig()) {
      server.send(200, "application/json", "{\"success\":true}");
    } else {
      server.send(500, "application/json", "{\"error\":\"Failed to save config\"}");
    }
  }
}

void handleApiTime() {
  // No auth required - WiFi password is sufficient
  
  if (server.method() == HTTP_GET) {
    time_t now = time(nullptr);
    DynamicJsonDocument doc(256);
    doc["epoch"] = now;
    doc["time_set"] = config.time_set && (now >= 946684800);
    doc["iso"] = getISOTimestamp();
    
    String response;
    serializeJson(doc, response);
    server.send(200, "application/json", response);
  } else if (server.method() == HTTP_POST) {
    if (!server.hasArg("plain")) {
      server.send(400, "application/json", "{\"error\":\"Invalid request\"}");
      return;
    }
    
    DynamicJsonDocument doc(256);
    DeserializationError error = deserializeJson(doc, server.arg("plain"));
    if (error) {
      server.send(400, "application/json", "{\"error\":\"Invalid JSON\"}");
      return;
    }
    
    if (doc.containsKey("epoch")) {
      time_t epoch = doc["epoch"];
      timeval tv = {epoch, 0};
      settimeofday(&tv, nullptr);
      config.time_set = true;
      saveConfig();
      
      // Also set RTC if present
      if (rtcPresent) {
        struct tm* timeinfo = localtime(&epoch);
        rtc.adjust(DateTime(timeinfo->tm_year + 1900, timeinfo->tm_mon + 1, 
                           timeinfo->tm_mday, timeinfo->tm_hour, 
                           timeinfo->tm_min, timeinfo->tm_sec));
      }
      
      server.send(200, "application/json", "{\"success\":true}");
    } else {
      server.send(400, "application/json", "{\"error\":\"Missing epoch\"}");
    }
  }
}

void handleApiStorage() {
  // No auth required - WiFi password is sufficient
  
  size_t lfsTotal = LittleFS.totalBytes();
  size_t lfsUsed = LittleFS.usedBytes();
  size_t bytesPerSample = estimateSampleBytes();
  size_t freeBytes = lfsTotal - lfsUsed;
  size_t capacityBytes = LFS_RING_MAX_BYTES;
  if (capacityBytes > lfsTotal) {
    capacityBytes = lfsTotal;
  }
  if (capacityBytes > freeBytes) {
    capacityBytes = freeBytes;
  }
  unsigned long samplePeriod = config.sample_period_s;
  unsigned long estSamples = 0;
  unsigned long estDuration = 0;
  if (bytesPerSample > 0 && samplePeriod > 0) {
    estSamples = capacityBytes / bytesPerSample;
    estDuration = estSamples * samplePeriod;
  }
  
  DynamicJsonDocument doc(768);
  doc["lfs"]["total"] = lfsTotal;
  doc["lfs"]["used"] = lfsUsed;
  doc["lfs"]["free"] = freeBytes;
  doc["sd"]["present"] = sdPresent;
  doc["write_errors"] = writeErrors;
  doc["sample_period_s"] = samplePeriod;
  doc["retention"]["bytes_per_sample"] = bytesPerSample;
  doc["retention"]["est_samples"] = estSamples;
  doc["retention"]["est_duration_s"] = estDuration;
  
  if (sdPresent) {
    // SD card size info not always available
    doc["sd"]["total"] = 0;
    doc["sd"]["used"] = 0;
    doc["sd"]["free"] = 0;
  } else {
    doc["sd"]["total"] = 0;
    doc["sd"]["used"] = 0;
    doc["sd"]["free"] = 0;
  }
  
  String response;
  serializeJson(doc, response);
  server.send(200, "application/json", response);
}

void handleApiPrune() {
  // No auth required - WiFi password is sufficient
  if (!server.hasArg("days")) {
    server.send(400, "application/json", "{\"error\":\"Missing days parameter\"}");
    return;
  }

  int days = server.arg("days").toInt();
  if (days <= 0) {
    server.send(400, "application/json", "{\"error\":\"Invalid days value\"}");
    return;
  }

  time_t now = time(nullptr);
  if (now < 946684800) { // Before 2000-01-01, time not set
    server.send(400, "application/json", "{\"error\":\"Time not set\"}");
    return;
  }

  time_t cutoff = now - (time_t)days * 86400;

  int deletedSamples = 0;
  int keptSamples = 0;
  int deletedFiles = 0;
  size_t freedBytes = 0;

  auto sendEmpty = [&]() {
    DynamicJsonDocument docEmpty(256);
    docEmpty["deleted_samples"] = 0;
    docEmpty["kept_samples"] = 0;
    docEmpty["deleted_files"] = 0;
    docEmpty["freed_bytes"] = 0;
    String resp;
    serializeJson(docEmpty, resp);
    server.send(200, "application/json", resp);
  };

  File root = LittleFS.open("/logs");
  if (!root || !root.isDirectory()) {
    root.close();
    sendEmpty();
    return;
  }

  File file = root.openNextFile();
  while (file) {
    String fileName = file.name();
    if (!fileName.endsWith(".csv")) {
      file = root.openNextFile();
      continue;
    }
    if (!fileName.startsWith("/")) {
      fileName = "/logs/" + fileName;
    }

    size_t originalSize = file.size();

    // Detect ring-buffer format
    file.seek(0);
    size_t dataStart = 0;
    unsigned long offset = 0;
    unsigned long count = 0;
    size_t slots = 0;
    bool isRing = lfsRingReadHeader(file, dataStart, offset, count, slots);

    String tmpName = fileName + ".tmp";

    if (isRing) {
      // Prune ring-buffer file without corrupting the RB1 format.
      File tmp = LittleFS.open(tmpName, "w+");
      if (!tmp) {
        file.close();
        file = root.openNextFile();
        continue;
      }

      lfsRingWriteHeader(tmp, 0, 0);
      size_t tmpDataStart = lfsRingHeaderSize();
      size_t tmpSlots = lfsRingSlotCount(tmpDataStart);
      if (tmpSlots == 0) {
        tmp.close();
        file.close();
        LittleFS.remove(tmpName);
        file = root.openNextFile();
        continue;
      }

      unsigned long keptInFile = 0;
      unsigned long startIndex = (offset + slots - count) % slots;
      for (unsigned long i = 0; i < count; i++) {
        unsigned long idx = (startIndex + i) % slots;
        size_t pos = dataStart + (idx * LFS_RING_RECORD_LEN);
        file.seek(pos);

        char buf[LFS_RING_RECORD_LEN + 1];
        size_t read = file.readBytes(buf, LFS_RING_RECORD_LEN);
        buf[read] = '\0';

        String line = lfsRingTrimRecord(buf, read);
        if (line.length() == 0) {
          continue;
        }

        int comma1 = line.indexOf(',');
        if (comma1 <= 0) {
          deletedSamples++;
          continue;
        }

        String tsStr = line.substring(0, comma1);
        time_t tsTime = parseISO8601(tsStr);
        if (tsTime != 0 && tsTime >= cutoff) {
          // Format fixed-length record and write to next slot
          String record = line;
          if (record.endsWith("\n")) {
            record.remove(record.length() - 1);
          }
          if (record.length() > LFS_RING_RECORD_LEN - 1) {
            record = record.substring(0, LFS_RING_RECORD_LEN - 1);
          }
          while (record.length() < LFS_RING_RECORD_LEN - 1) {
            record += " ";
          }
          record += "\n";

          size_t wpos = tmpDataStart + (keptInFile * LFS_RING_RECORD_LEN);
          tmp.seek(wpos);
          size_t written = tmp.print(record);
          if (written != LFS_RING_RECORD_LEN) {
            // Stop on write error
            break;
          }

          keptSamples++;
          keptInFile++;
        } else {
          deletedSamples++;
        }

        yield();
      }

      unsigned long newCount = keptInFile;
      unsigned long newOffset = (tmpSlots > 0) ? (newCount % tmpSlots) : 0;
      lfsRingWriteHeader(tmp, newOffset, newCount);
      tmp.flush();
      tmp.close();
      file.close();

      if (newCount == 0) {
        LittleFS.remove(fileName);
        LittleFS.remove(tmpName);
        deletedFiles++;
        freedBytes += originalSize;
      } else {
        size_t newSize = 0;
        File tmpRead = LittleFS.open(tmpName, "r");
        if (tmpRead) {
          newSize = tmpRead.size();
          tmpRead.close();
        }
        LittleFS.remove(fileName);
        LittleFS.rename(tmpName, fileName);
        if (originalSize > newSize) {
          freedBytes += (originalSize - newSize);
        }
      }

      yield();
      file = root.openNextFile();
      continue;
    }

    // Plain CSV pruning (legacy files)
    File tmp = LittleFS.open(tmpName, "w");
    if (!tmp) {
      file.close();
      file = root.openNextFile();
      continue;
    }

    String line = file.readStringUntil('\n');
    if (line.startsWith("timestamp")) {
      tmp.print(line + "\n");
    } else {
      file.seek(0);
    }

    int fileKept = 0;
    while (file.available()) {
      line = file.readStringUntil('\n');
      if (line.length() == 0) break;

      int comma1 = line.indexOf(',');
      if (comma1 <= 0) {
        deletedSamples++;
        continue;
      }

      String tsStr = line.substring(0, comma1);
      time_t tsTime = parseISO8601(tsStr);
      if (tsTime != 0 && tsTime >= cutoff) {
        tmp.print(line + "\n");
        keptSamples++;
        fileKept++;
      } else {
        deletedSamples++;
      }

      yield();
    }

    file.close();
    tmp.flush();
    tmp.close();

    if (fileKept == 0) {
      LittleFS.remove(fileName);
      LittleFS.remove(tmpName);
      deletedFiles++;
      freedBytes += originalSize;
    } else {
      size_t newSize = 0;
      File tmpRead = LittleFS.open(tmpName, "r");
      if (tmpRead) {
        newSize = tmpRead.size();
        tmpRead.close();
      }
      LittleFS.remove(fileName);
      LittleFS.rename(tmpName, fileName);
      if (originalSize > newSize) {
        freedBytes += (originalSize - newSize);
      }
    }

    yield();
    file = root.openNextFile();
  }
  root.close();

  DynamicJsonDocument doc(512);
  doc["deleted_samples"] = deletedSamples;
  doc["kept_samples"] = keptSamples;
  doc["deleted_files"] = deletedFiles;
  doc["freed_bytes"] = freedBytes;

  String response;
  serializeJson(doc, response);
  server.send(200, "application/json", response);
}


static bool isLeapYear(int year) {
  return ((year % 4) == 0 && (year % 100) != 0) || ((year % 400) == 0);
}

static int daysInMonth(int year, int month) {
  static const int mdays[] = {31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31};
  if (month < 1 || month > 12) return 0;
  if (month == 2) return mdays[1] + (isLeapYear(year) ? 1 : 0);
  return mdays[month - 1];
}

static time_t timegmCompat(const struct tm& t) {
  // Convert a UTC tm into Unix epoch seconds (no timezone/DST effects).
  int year = t.tm_year + 1900;
  int month = t.tm_mon + 1;
  int day = t.tm_mday;

  if (year < 1970 || month < 1 || month > 12 || day < 1 || day > 31) return 0;

  int64_t days = 0;
  for (int y = 1970; y < year; y++) {
    days += isLeapYear(y) ? 366 : 365;
  }
  for (int m = 1; m < month; m++) {
    days += daysInMonth(year, m);
  }
  days += (day - 1);

  int64_t seconds = days * 86400LL + (int64_t)t.tm_hour * 3600LL + (int64_t)t.tm_min * 60LL + (int64_t)t.tm_sec;
  if (seconds < 0) return 0;
  return (time_t)seconds;
}

// Parse ISO8601 timestamp to epoch (UTC). Accepts: YYYY-MM-DDTHH:MM:SSZ
time_t parseISO8601(const String& iso) {
  if (iso.length() < 19) return 0;
  if (iso.charAt(4) != '-' || iso.charAt(7) != '-' || iso.charAt(10) != 'T' || iso.charAt(13) != ':' || iso.charAt(16) != ':') {
    return 0;
  }

  int year = iso.substring(0, 4).toInt();
  int month = iso.substring(5, 7).toInt();
  int day = iso.substring(8, 10).toInt();
  int hour = iso.substring(11, 13).toInt();
  int minute = iso.substring(14, 16).toInt();
  int second = iso.substring(17, 19).toInt();

  if (month < 1 || month > 12) return 0;
  if (day < 1 || day > daysInMonth(year, month)) return 0;
  if (hour < 0 || hour > 23) return 0;
  if (minute < 0 || minute > 59) return 0;
  if (second < 0 || second > 59) return 0;

  struct tm timeinfo = {0};
  timeinfo.tm_year = year - 1900;
  timeinfo.tm_mon = month - 1;
  timeinfo.tm_mday = day;
  timeinfo.tm_hour = hour;
  timeinfo.tm_min = minute;
  timeinfo.tm_sec = second;

  return timegmCompat(timeinfo);
}

void handleApiData() {
  // No auth required - WiFi password is sufficient
  
  if (!server.hasArg("from") || !server.hasArg("to")) {
    server.send(400, "application/json", "{\"error\":\"Missing from/to parameters\"}");
    return;
  }
  
  String fromStr = server.arg("from");
  String toStr = server.arg("to");
  
  // Parse ISO8601 timestamps
  time_t fromTime = parseISO8601(fromStr);
  time_t toTime = parseISO8601(toStr);
  
  if (fromTime == 0 || toTime == 0) {
    server.send(400, "application/json", "{\"error\":\"Invalid timestamp format\"}");
    return;
  }
  
  int pointCount = 0;
  const int MAX_POINTS = 20000;

  // Stream JSON to avoid large heap usage
  server.setContentLength(CONTENT_LENGTH_UNKNOWN);
  server.send(200, "application/json", "");
  server.sendContent("{\"points\":[");

  bool firstPoint = true;
  
  // Iterate through log files (ESP32: File openNextFile)
  File dataRoot = LittleFS.open("/logs");
  if (!dataRoot || !dataRoot.isDirectory()) {
    dataRoot.close();
    server.sendContent("]");
    server.sendContent(",\"count\":0}");
    server.sendContent("");
    server.client().stop();
    return;
  }
  File file = dataRoot.openNextFile();
  while (file && pointCount < MAX_POINTS) {
    if (String(file.name()).endsWith(".csv")) {
        size_t dataStart = 0;
        unsigned long offset = 0;
        unsigned long count = 0;
        size_t slots = 0;

        if (lfsRingReadHeader(file, dataStart, offset, count, slots)) {
          unsigned long startIndex = (offset + slots - count) % slots;
          for (unsigned long i = 0; i < count && pointCount < MAX_POINTS; i++) {
            unsigned long idx = (startIndex + i) % slots;
            size_t pos = dataStart + (idx * LFS_RING_RECORD_LEN);
            file.seek(pos);
            char buf[LFS_RING_RECORD_LEN + 1];
            size_t read = file.readBytes(buf, LFS_RING_RECORD_LEN);
            buf[read] = '\0';
            String line = lfsRingTrimRecord(buf, read);
            if (line.length() == 0) {
              continue;
            }

            int comma1 = line.indexOf(',');
            if (comma1 <= 0) continue;
            int comma2 = line.indexOf(',', comma1 + 1);
            int comma3 = line.indexOf(',', comma2 + 1);
            if (comma1 > 0 && comma2 > 0 && comma3 > 0) {
              String tsStr = line.substring(0, comma1);
              String tempStr = line.substring(comma2 + 1, comma3);
              String humStr = line.substring(comma3 + 1);

              time_t tsTime = parseISO8601(tsStr);
              if (tsTime >= fromTime && tsTime <= toTime) {
                if (!firstPoint) {
                  server.sendContent(",");
                }
                firstPoint = false;

                String payload = "[\"" + tsStr + "\"," + tempStr + "," + humStr + "]";
                server.sendContent(payload);
                pointCount++;
              }
            }

            yield();
          }
        } else {
          file.seek(0);
        // Skip header if exists
        String line = file.readStringUntil('\n');
        if (!line.startsWith("timestamp")) {
          // Not a header, rewind
          file.seek(0);
        }
        
        while (file.available() && pointCount < MAX_POINTS) {
          line = file.readStringUntil('\n');
          if (line.length() == 0) break;
          
          // Parse CSV: timestamp,device_id,temperature,humidity
          int comma1 = line.indexOf(',');
          if (comma1 <= 0) continue;
          
          int comma2 = line.indexOf(',', comma1 + 1);
          int comma3 = line.indexOf(',', comma2 + 1);
          
          if (comma1 > 0 && comma2 > 0 && comma3 > 0) {
            String tsStr = line.substring(0, comma1);
            String tempStr = line.substring(comma2 + 1, comma3);
            String humStr = line.substring(comma3 + 1);
            
            // Filter by time range
            time_t tsTime = parseISO8601(tsStr);
            if (tsTime >= fromTime && tsTime <= toTime) {
                if (!firstPoint) {
                  server.sendContent(",");
                }
                firstPoint = false;
                
                String payload = "[\"" + tsStr + "\"," + tempStr + "," + humStr + "]";
                server.sendContent(payload);
              pointCount++;
            }
          }
          
          yield(); // Yield to prevent watchdog
          }
        }
    }
    yield();
    file = dataRoot.openNextFile();
  }
  dataRoot.close();
  
  server.sendContent("]");
  server.sendContent(",\"count\":" + String(pointCount));
  if (pointCount >= MAX_POINTS) {
    server.sendContent(",\"warning\":\"Result truncated to 20000 points\"");
  }
  server.sendContent("}");
  server.sendContent("");
  server.client().stop();
}

void handleApiDownload() {
  // No auth required - WiFi password is sufficient
  
  if (!server.hasArg("from") || !server.hasArg("to")) {
    server.send(400, "text/plain", "Missing from/to parameters");
    return;
  }
  
  // Generate filename
  String filename = config.device_id + "_" + server.arg("from").substring(0, 10) + 
                    "_" + server.arg("to").substring(0, 10) + ".csv";
  
  // Parse time range
  String fromStr = server.arg("from");
  String toStr = server.arg("to");
  time_t fromTime = parseISO8601(fromStr);
  time_t toTime = parseISO8601(toStr);
  
  if (fromTime == 0 || toTime == 0) {
    server.send(400, "text/plain", "Invalid timestamp format");
    return;
  }
  
  server.sendHeader("Content-Type", "text/csv");
  server.sendHeader("Content-Disposition", "attachment; filename=\"" + filename + "\"");
  server.setContentLength(CONTENT_LENGTH_UNKNOWN);
  server.send(200, "text/csv", "");
  
  // Stream CSV data with header
  server.sendContent("timestamp,device_id,temperature_c,humidity_rh\n");
  
  unsigned long sentLines = 0;

  bool useSd = false;
  useSd = sdPresent;

  if (useSd) {
    int startYear = 0, startMonth = 0;
    int endYear = 0, endMonth = 0;
    normalizeMonthStart(fromTime, startYear, startMonth);
    normalizeMonthStart(toTime, endYear, endMonth);

    int year = startYear;
    int month = startMonth;
    while (year < endYear || (year == endYear && month <= endMonth)) {
      String fileName = getLogFilenameForMonth(year, month);
      File file = SD.open(fileName, FILE_READ);
      if (file) {
        String header = file.readStringUntil('\n');
        if (!header.startsWith("timestamp")) {
          file.seek(0);
        }

        while (file.available()) {
          String line = file.readStringUntil('\n');
          if (line.length() == 0) break;

          int comma1 = line.indexOf(',');
          if (comma1 > 0) {
            String tsStr = line.substring(0, comma1);
            time_t tsTime = parseISO8601(tsStr);
            if (tsTime >= fromTime && tsTime <= toTime) {
              server.sendContent(line + "\n");
              sentLines++;
            }
          }

          yield();
        }
        file.close();
      }

      month++;
      if (month > 12) {
        month = 1;
        year++;
      }
      yield();
    }
  } else {
    // LittleFS directory iteration (ESP32: openNextFile)
    File dlRoot = LittleFS.open("/logs");
    if (dlRoot && dlRoot.isDirectory()) {
      File file = dlRoot.openNextFile();
      while (file) {
        if (String(file.name()).endsWith(".csv")) {
          size_t dataStart = 0;
          unsigned long offset = 0;
          unsigned long count = 0;
          size_t slots = 0;

          if (lfsRingReadHeader(file, dataStart, offset, count, slots)) {
            unsigned long startIndex = (offset + slots - count) % slots;
            for (unsigned long i = 0; i < count; i++) {
              unsigned long idx = (startIndex + i) % slots;
              size_t pos = dataStart + (idx * LFS_RING_RECORD_LEN);
              file.seek(pos);
              char buf[LFS_RING_RECORD_LEN + 1];
              size_t read = file.readBytes(buf, LFS_RING_RECORD_LEN);
              buf[read] = '\0';
              String line = lfsRingTrimRecord(buf, read);
              if (line.length() == 0) {
                continue;
              }

              int comma1 = line.indexOf(',');
              if (comma1 > 0) {
                String tsStr = line.substring(0, comma1);
                time_t tsTime = parseISO8601(tsStr);
                if (tsTime >= fromTime && tsTime <= toTime) {
                  server.sendContent(line + "\n");
                  sentLines++;
                }
              }

              yield();
            }
          } else {
            // Skip header
            String header = file.readStringUntil('\n');
            if (!header.startsWith("timestamp")) {
              file.seek(0);
            }
            
            while (file.available()) {
              String line = file.readStringUntil('\n');
              if (line.length() == 0) break;
              
              // Filter by time range
              int comma1 = line.indexOf(',');
              if (comma1 > 0) {
                String tsStr = line.substring(0, comma1);
                time_t tsTime = parseISO8601(tsStr);
                if (tsTime >= fromTime && tsTime <= toTime) {
                  server.sendContent(line + "\n");
                  sentLines++;
                }
              }
              
              yield();
            }
          }
        }
        yield();
        file = dlRoot.openNextFile();
      }
      dlRoot.close();
    }
  }
  
  server.sendContent("");
  server.client().stop();
}

void handleApiFiles() {
  // No auth required - WiFi password is sufficient
  
  DynamicJsonDocument doc(2048);
  JsonArray files = doc.createNestedArray("files");
  
  File root = LittleFS.open("/logs");
  if (root && root.isDirectory()) {
    File file = root.openNextFile();
    while (file) {
      if (String(file.name()).endsWith(".csv")) {
        JsonObject fileObj = files.createNestedObject();
        fileObj["name"] = file.name();
        fileObj["size"] = file.size();
      }
      file = root.openNextFile();
    }
    root.close();
  }
  
  String response;
  serializeJson(doc, response);
  server.send(200, "application/json", response);
}

void handleApiStatus() {
  // Debug endpoint - shows current state
  DynamicJsonDocument doc(1400);
  
  // Sensor: only include readings when sensor is present (no-sensor mode for website test)
  doc["sensor"]["connected"] = sensorPresent;
  if (sensorPresent) {
    if (sht.read(true)) {
      doc["sensor"]["temperature"] = sht.getTemperature();
      doc["sensor"]["humidity"] = sht.getHumidity();
    } else {
      doc["sensor"]["temperature"] = (float)((double)0.0 / 0.0);  // read failed
      doc["sensor"]["humidity"] = (float)((double)0.0 / 0.0);
    }
  }
  // When !sensorPresent, omit temperature/humidity; frontend checks connected
  
  // Time info
  doc["time"]["iso"] = getISOTimestamp();
  doc["time"]["set"] = config.time_set;
  doc["time"]["epoch"] = (long)time(nullptr);
  
  // Config
  doc["config"]["sample_period_s"] = config.sample_period_s;
  doc["config"]["device_id"] = config.device_id;
  
  // Heating (SHT85 built-in heater)
  doc["heating"]["mode"] = config.heating_mode;
  doc["heating"]["on"] = sensorPresent ? sht.isHeaterOn() : false;
  
  // Storage (ESP32: totalBytes/usedBytes)
  doc["storage"]["lfs_used"] = LittleFS.usedBytes();
  doc["storage"]["lfs_total"] = LittleFS.totalBytes();
  doc["storage"]["sd_present"] = sdPresent;
  
  // Log files and ring status (ESP32: openNextFile)
  // Don't use exists() or open() for missing files - ESP32 VFS logs "no permits for creation" on both
  String currentLog = getLogFilename();
  String currentLogBase = currentLog;
  if (currentLog.lastIndexOf('/') >= 0) {
    currentLogBase = currentLog.substring(currentLog.lastIndexOf('/') + 1);
  }
  bool currentLogExists = false;

  JsonArray files = doc.createNestedArray("log_files");
  File root = LittleFS.open("/logs");
  if (root && root.isDirectory()) {
    File file = root.openNextFile();
    while (file) {
      if (String(file.name()).endsWith(".csv")) {
        JsonObject f = files.createNestedObject();
        f["name"] = file.name();
        f["size"] = file.size();
        String fn = file.name();
        if (fn == currentLog || fn.endsWith("/" + currentLogBase) || fn == currentLogBase) {
          currentLogExists = true;
        }
      }
      file = root.openNextFile();
    }
    root.close();
  }

  JsonObject ring = doc.createNestedObject("ring");
  ring["file"] = currentLog;
  if (currentLogExists) {
    File file = LittleFS.open(currentLog, "r");
    if (file) {
      size_t dataStart = 0;
      unsigned long offset = 0;
      unsigned long count = 0;
      size_t slots = 0;
      bool ok = lfsRingReadHeader(file, dataStart, offset, count, slots);
      ring["valid"] = ok;
      if (ok) {
        ring["data_start"] = (unsigned long)dataStart;
        ring["offset"] = offset;
        ring["count"] = count;
        ring["slots"] = (unsigned long)slots;
      }
      file.close();
    } else {
      ring["valid"] = false;
      ring["error"] = "open_failed";
    }
  } else {
    ring["valid"] = false;
    ring["error"] = "missing_file";
  }
  
  String response;
  serializeJson(doc, response);
  server.send(200, "application/json", response);
}

void handleApiTestSD() {
  DynamicJsonDocument doc(512);
  
  if (!sdPresent) {
    doc["success"] = false;
    doc["error"] = "SD card not detected";
    String response;
    serializeJson(doc, response);
    server.send(200, "application/json", response);
    return;
  }
  
  // Try to write a test file
  String testFile = "/sd_test.txt";
  String testData = "FireBeetle2 SD Test - " + getISOTimestamp();
  
  File file = SD.open(testFile, FILE_WRITE);
  if (!file) {
    doc["success"] = false;
    doc["error"] = "Failed to open file for writing";
    String response;
    serializeJson(doc, response);
    server.send(200, "application/json", response);
    return;
  }
  
  file.println(testData);
  file.close();
  
  // Try to read it back
  file = SD.open(testFile, FILE_READ);
  if (!file) {
    doc["success"] = false;
    doc["error"] = "Failed to open file for reading";
    String response;
    serializeJson(doc, response);
    server.send(200, "application/json", response);
    return;
  }
  
  String readBack = file.readStringUntil('\n');
  file.close();
  
  // Delete test file
  SD.remove(testFile);
  
  if (readBack.startsWith("FireBeetle2 SD Test")) {
    doc["success"] = true;
    doc["message"] = "SD card read/write test passed";
  } else {
    doc["success"] = false;
    doc["error"] = "Data verification failed";
  }
  
  String response;
  serializeJson(doc, response);
  server.send(200, "application/json", response);
}

void handleStaticFile() {
  String path = server.uri();
  if (path == "/") path = "/index.html";
  
  // Security: prevent directory traversal
  if (path.indexOf("..") >= 0 || path.indexOf("//") >= 0) {
    server.send(403, "text/plain", "Forbidden");
    return;
  }
  
  // Ensure path starts with / for LittleFS
  if (!path.startsWith("/")) {
    path = "/" + path;
  }
  
  // Determine MIME type
  String contentType = "text/plain";
  if (path.endsWith(".html")) contentType = "text/html";
  else if (path.endsWith(".js")) contentType = "application/javascript";
  else if (path.endsWith(".css")) contentType = "text/css";
  else if (path.endsWith(".json")) contentType = "application/json";
  
  // Static files (js, css) served without auth for login page to work
  File file = LittleFS.open(path, "r");
  if (!file) {
    server.send(404, "text/plain", "File not found");
    return;
  }
  server.streamFile(file, contentType);
  file.close();
}

void handleNotFound() {
  // Try to serve as static file first
  String path = server.uri();
  if (path.endsWith(".js") || path.endsWith(".css") || path.endsWith(".html")) {
    handleStaticFile();
    return;
  }
  // Otherwise redirect to root
  server.sendHeader("Location", "/");
  server.send(302, "text/plain", "");
}

// LED indicator functions (FireBeetle 2: active HIGH)
void ledHeartbeat() {
  digitalWrite(LED_PIN, HIGH);  // LED ON
  delay(50);
  digitalWrite(LED_PIN, LOW);   // LED OFF
}

void ledSampleFlash() {
  for (int i = 0; i < 3; i++) {
    digitalWrite(LED_PIN, HIGH);  // LED ON
    delay(80);
    digitalWrite(LED_PIN, LOW);   // LED OFF
    delay(80);
  }
}

void setup() {
  Serial.begin(115200);
  delay(500);
  
  // Initialize LED indicator (FireBeetle 2: GPIO 21, active HIGH)
  pinMode(LED_PIN, OUTPUT);
  digitalWrite(LED_PIN, LOW);  // LED OFF
  
  Serial.println("\n\nFireBeetle 2 SHT85 Temperature/Humidity Logger");
  Serial.println("================================================");
  
  // Initialize LittleFS; format on corrupt (e.g. first boot or different board)
  if (!LittleFS.begin(false)) {  // false = do not format on first try
    Serial.println("LittleFS mount failed, formatting...");
    if (!LittleFS.begin(true)) {  // true = format then mount
      Serial.println("LittleFS still failed after format!");
      return;
    }
    Serial.println("LittleFS formatted and mounted");
  } else {
    Serial.println("LittleFS mounted");
  }
  
  // Ensure /logs/ directory exists
  if (!LittleFS.exists("/logs")) {
    LittleFS.mkdir("/logs");
    Serial.println("Created /logs directory");
  }
  
  // Initialize SD card (optional) - FireBeetle 2 SD_CS = 9
  if (SD.begin(SD_CS)) {
    sdPresent = true;
    Serial.println("SD card initialized");
  } else {
    Serial.println("SD card not present or failed");
  }
  
  // I2C for SHT85 - FireBeetle 2 default SDA=1, SCL=2
  Wire.begin(I2C_SDA, I2C_SCL);
  // Initialize SHT85 sensor
  if (!sht.begin()) {
    Serial.println("SHT85 sensor not found!");
    sensorPresent = false;
  } else {
    sensorPresent = true;
    Serial.println("SHT85 sensor initialized");
  }
  
  // Load or create config FIRST (before RTC check)
  if (!loadConfig()) {
    Serial.println("Creating default config");
    getDefaultConfig();
    saveConfig();
  }
  Serial.println("Config loaded: " + config.device_id);
  
  // Initialize RTC (optional) - AFTER loading config
  if (rtc.begin()) {
    rtcPresent = true;
    if (rtc.initialized() && !rtc.lostPower()) {
      // Set system time from RTC
      DateTime now = rtc.now();
      time_t rtcTime = now.unixtime();
      timeval tv = {rtcTime, 0};
      settimeofday(&tv, nullptr);
      if (!config.time_set) {
        config.time_set = true;
        saveConfig();  // Save the updated time_set flag
      }
      Serial.println("RTC initialized and time set from RTC");
    } else if (config.time_set) {
      // Config says time was set before, but RTC lost power
      Serial.println("RTC lost power, time needs to be set again");
    }
  }
  
  // Setup WiFi AP (WPA2 requires password length 8-63)
  if (config.ap_password.length() < 8 || config.ap_password.length() > 63) {
    config.ap_password = "logger123";
    saveConfig();
  }
  WiFi.mode(WIFI_AP);
  WiFi.softAPConfig(apIP, apIP, IPAddress(255, 255, 255, 0));
  bool apOk = WiFi.softAP(config.ap_ssid.c_str(), config.ap_password.c_str());
  if (!apOk) {
    Serial.println("ERROR: WiFi AP failed to start. Try power cycle or check password (8-63 chars).");
  }
  Serial.println("AP started: " + config.ap_ssid);
  Serial.println("AP IP: " + apIP.toString());
  
  // Setup web server routes
  server.on("/", handleRoot);
  server.on("/login", handleLogin);
  server.on("/logout", handleLogout);
  server.on("/api/config", handleApiConfig);
  server.on("/api/time", handleApiTime);
  server.on("/api/storage", handleApiStorage);
  server.on("/api/prune", handleApiPrune);
  server.on("/api/data", handleApiData);
  server.on("/api/download", handleApiDownload);
  server.on("/api/files", handleApiFiles);
  server.on("/api/status", handleApiStatus);
  server.on("/api/test-sd", handleApiTestSD);
  
  // Static files
  server.onNotFound([]() {
    String path = server.uri();
    if (path.startsWith("/api/") || path == "/login" || path == "/logout") {
      handleNotFound();
    } else {
      handleStaticFile();
    }
  });
  
  server.begin();
  Serial.println("Web server started");
  
  // Randomness: use esp_random() directly for tokens/salts (no RNG seeding required)

  Serial.println("\nSetup complete!");
  Serial.println("Connect to: " + config.ap_ssid);
  Serial.println("Password: " + config.ap_password);
  Serial.println("Sample interval: " + String(config.sample_period_s) + " seconds");
  Serial.println("Current time: " + getISOTimestamp());
  Serial.println("Time set: " + String(config.time_set ? "YES" : "NO"));
  Serial.println("\nDebug: http://192.168.4.1/api/status");
}

void loop() {
  server.handleClient();
  
  unsigned long now = millis();
  
  // LED heartbeat every 3 seconds
  if (now - lastHeartbeat >= HEARTBEAT_INTERVAL) {
    ledHeartbeat();
    lastHeartbeat = now;
  }
  
  // SHT85 heater state machine (non-blocking): only when sensor present and mode != off
  if (sensorPresent && config.heating_mode != "off") {
    unsigned int durationSec = 10;
    unsigned long intervalMs = 300000UL;   // 5 min
    if (config.heating_mode == "1min_1hr") {
      durationSec = 60;
      intervalMs = 3600000UL;
    } else if (config.heating_mode == "1min_1day") {
      durationSec = 60;
      intervalMs = 86400000UL;
    }
    const unsigned long durationMs = (unsigned long)durationSec * 1000UL;
    
    if (heaterActive) {
      if (now - heaterStartMs >= durationMs) {
        sht.heatOff();
        lastHeaterCycleEndMs = now;
        heaterActive = false;
      }
    } else {
      if (lastHeaterCycleEndMs == 0 || (now - lastHeaterCycleEndMs >= intervalMs)) {
        sht.setHeatTimeout((uint8_t)durationSec);
        if (sht.heatOn()) {
          heaterStartMs = now;
          heaterActive = true;
        } else {
          lastHeaterCycleEndMs = now;  // avoid tight loop on failure
        }
      }
    }
  }
  
  // Non-blocking sampling
  unsigned long intervalMs = (unsigned long)config.sample_period_s * 1000UL;
  
  // Take first sample immediately (lastSampleTime starts at 0)
  // Then sample at configured interval - only when sensor is present
  // Skip sample when heater is on (readings would be invalid)
  if (sensorPresent && (lastSampleTime == 0 || (now - lastSampleTime >= intervalMs))) {
    if (sht.isHeaterOn()) {
      lastSampleTime = now;
    } else if (sht.read(true)) {
      float temperature = sht.getTemperature();
      float humidity = sht.getHumidity();
      
      Serial.print("Sample #");
      Serial.print(lastSampleTime == 0 ? 1 : (now / intervalMs) + 1);
      Serial.print(": ");
      Serial.print(temperature, 2);
      Serial.print("°C, ");
      Serial.print(humidity, 2);
      Serial.print("%RH @ ");
      Serial.println(getISOTimestamp());
      
      if (writeDataPoint(temperature, humidity)) {
        Serial.println("  -> Saved to storage");
        ledSampleFlash();  // Flash rapidly to indicate data saved
      } else {
        Serial.println("  -> ERROR saving!");
      }
      lastSampleTime = now;
      Serial.print("Next sample in ");
      Serial.print(config.sample_period_s);
      Serial.println(" seconds");
    }
  }
  
  yield();
}
