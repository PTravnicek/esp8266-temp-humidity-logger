#include <Arduino.h>
#include <ESP8266WiFi.h>
#include <ESP8266WebServer.h>
#include <LittleFS.h>
#include <SD.h>
#include <SPI.h>
#include <ArduinoJson.h>
#include <Adafruit_Si7021.h>
#include <RTClib.h>
#include <time.h>

// Hardware objects
Adafruit_Si7021 sensor = Adafruit_Si7021();
RTC_PCF8523 rtc;
bool rtcPresent = false;

// LED indicator (GPIO0 = red LED on HUZZAH, active LOW)
#define LED_PIN 0
unsigned long lastHeartbeat = 0;
const unsigned long HEARTBEAT_INTERVAL = 3000; // 3 seconds

// Network objects
ESP8266WebServer server(80);
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

// LittleFS ring-buffer settings
#ifndef LFS_RING_MAX_BYTES_DEFAULT
#define LFS_RING_MAX_BYTES_DEFAULT (256 * 1024)
#endif
#ifndef LFS_RING_RECORD_LEN_DEFAULT
#define LFS_RING_RECORD_LEN_DEFAULT 96
#endif
const size_t LFS_RING_MAX_BYTES = LFS_RING_MAX_BYTES_DEFAULT;
const size_t LFS_RING_RECORD_LEN = LFS_RING_RECORD_LEN_DEFAULT;

// Helper functions
String getChipId() {
  return String(ESP.getChipId(), HEX);
}

time_t parseISO8601(const String& iso);

String generateSessionToken() {
  String token = "";
  for (int i = 0; i < 32; i++) {
    token += String(random(0, 16), HEX);
  }
  return token;
}

String hashPassword(const String& password, const String& salt) {
  // Simple SHA-256 would require additional library
  // For now, use a simple hash (in production, use proper SHA-256)
  String combined = password + salt;
  uint32_t hash = 0;
  for (size_t i = 0; i < combined.length(); i++) {
    hash = ((hash << 5) + hash) + combined.charAt(i);
  }
  return String(hash, HEX);
}

String generateSalt() {
  String salt = "";
  for (int i = 0; i < 16; i++) {
    salt += String(random(0, 16), HEX);
  }
  return salt;
}

bool verifyPassword(const String& password, const String& hash, const String& salt) {
  String computed = hashPassword(password, salt);
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
  config.device_id = doc["device_id"] | ("LOGGER_" + getChipId());
  config.ap_ssid = doc["ap_ssid"] | ("LOGGER_" + getChipId());
  config.ap_password = doc["ap_password"] | "logger123";
  config.auth_hash = doc["auth_hash"] | "";
  config.auth_salt = doc["auth_salt"] | "";
  config.sample_period_s = doc["sample_period_s"] | 3600;
  config.log_timezone_offset_min = doc["log_timezone_offset_min"] | 0;
  config.file_rotation = doc["file_rotation"] | "monthly";
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
      String token = generateSessionToken();
      addSession(token);
      server.sendHeader("Set-Cookie", "SESSION=" + token + "; Path=/; Max-Age=3600");
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
  server.sendHeader("Set-Cookie", "SESSION=; Path=/; Max-Age=0");
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
  
  FSInfo fsInfo;
  LittleFS.info(fsInfo);
  size_t bytesPerSample = estimateSampleBytes();
  size_t freeBytes = fsInfo.totalBytes - fsInfo.usedBytes;
  size_t capacityBytes = LFS_RING_MAX_BYTES;
  if (capacityBytes > fsInfo.totalBytes) {
    capacityBytes = fsInfo.totalBytes;
  }
  unsigned long samplePeriod = config.sample_period_s;
  unsigned long estSamples = 0;
  unsigned long estDuration = 0;
  if (bytesPerSample > 0 && samplePeriod > 0) {
    estSamples = capacityBytes / bytesPerSample;
    estDuration = estSamples * samplePeriod;
  }
  
  DynamicJsonDocument doc(768);
  doc["lfs"]["total"] = fsInfo.totalBytes;
  doc["lfs"]["used"] = fsInfo.usedBytes;
  doc["lfs"]["free"] = freeBytes;
  doc["sd"]["present"] = sdPresent;
  doc["write_errors"] = writeErrors;
  doc["sample_period_s"] = samplePeriod;
  doc["retention"]["bytes_per_sample"] = bytesPerSample;
  doc["retention"]["est_samples"] = estSamples;
  doc["retention"]["est_duration_s"] = estDuration;
  
  if (sdPresent) {
    // ESP8266 SD library doesn't provide card size info easily
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

  Dir dir = LittleFS.openDir("/logs");
  while (dir.next()) {
    if (!dir.fileName().endsWith(".csv")) {
      continue;
    }

    String fileName = dir.fileName();
    size_t originalSize = dir.fileSize();
    File file = dir.openFile("r");
    if (!file) {
      continue;
    }

    String tmpName = fileName + ".tmp";
    File tmp = LittleFS.open(tmpName, "w");
    if (!tmp) {
      file.close();
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
  }

  DynamicJsonDocument doc(512);
  doc["deleted_samples"] = deletedSamples;
  doc["kept_samples"] = keptSamples;
  doc["deleted_files"] = deletedFiles;
  doc["freed_bytes"] = freedBytes;
  
  String response;
  serializeJson(doc, response);
  server.send(200, "application/json", response);
}

// Parse ISO8601 timestamp to epoch (simplified)
time_t parseISO8601(const String& iso) {
  // Format: YYYY-MM-DDTHH:MM:SSZ
  if (iso.length() < 19) return 0;
  
  int year = iso.substring(0, 4).toInt();
  int month = iso.substring(5, 7).toInt();
  int day = iso.substring(8, 10).toInt();
  int hour = iso.substring(11, 13).toInt();
  int minute = iso.substring(14, 16).toInt();
  int second = iso.substring(17, 19).toInt();
  
  struct tm timeinfo = {0};
  timeinfo.tm_year = year - 1900;
  timeinfo.tm_mon = month - 1;
  timeinfo.tm_mday = day;
  timeinfo.tm_hour = hour;
  timeinfo.tm_min = minute;
  timeinfo.tm_sec = second;
  
  return mktime(&timeinfo);
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
  
  // Iterate through log files
  Dir dir = LittleFS.openDir("/logs");
  while (dir.next() && pointCount < MAX_POINTS) {
    if (dir.fileName().endsWith(".csv")) {
      File file = dir.openFile("r");
      if (file) {
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
        file.close();
      }
    }
    yield();
  }
  
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
    // Use LittleFS only (SD doesn't support Dir iteration on ESP8266)
    Dir dir = LittleFS.openDir("/logs");
    while (dir.next()) {
      if (dir.fileName().endsWith(".csv")) {
        File file = dir.openFile("r");
        if (file) {
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
          file.close();
        }
      }
      yield();
    }
  }
  
  server.sendContent("");
  server.client().stop();
}

void handleApiFiles() {
  // No auth required - WiFi password is sufficient
  
  DynamicJsonDocument doc(2048);
  JsonArray files = doc.createNestedArray("files");
  
  // Use LittleFS only (SD doesn't support Dir iteration on ESP8266)
  Dir dir = LittleFS.openDir("/logs");
  while (dir.next()) {
    if (dir.fileName().endsWith(".csv")) {
      JsonObject fileObj = files.createNestedObject();
      fileObj["name"] = dir.fileName();
      fileObj["size"] = dir.fileSize();
    }
  }
  
  String response;
  serializeJson(doc, response);
  server.send(200, "application/json", response);
}

void handleApiStatus() {
  // Debug endpoint - shows current state
  DynamicJsonDocument doc(1400);
  
  // Current sensor readings
  float temperature = sensor.readTemperature();
  float humidity = sensor.readHumidity();
  doc["sensor"]["temperature"] = temperature;
  doc["sensor"]["humidity"] = humidity;
  
  // Time info
  doc["time"]["iso"] = getISOTimestamp();
  doc["time"]["set"] = config.time_set;
  doc["time"]["epoch"] = (long)time(nullptr);
  
  // Config
  doc["config"]["sample_period_s"] = config.sample_period_s;
  doc["config"]["device_id"] = config.device_id;
  
  // Storage
  FSInfo fsInfo;
  LittleFS.info(fsInfo);
  doc["storage"]["lfs_used"] = fsInfo.usedBytes;
  doc["storage"]["lfs_total"] = fsInfo.totalBytes;
  doc["storage"]["sd_present"] = sdPresent;
  
  // Log files
  JsonArray files = doc.createNestedArray("log_files");
  Dir dir = LittleFS.openDir("/logs");
  while (dir.next()) {
    JsonObject f = files.createNestedObject();
    f["name"] = dir.fileName();
    f["size"] = dir.fileSize();
  }

  // Ring buffer status for current log file (LittleFS)
  String currentLog = getLogFilename();
  JsonObject ring = doc.createNestedObject("ring");
  ring["file"] = currentLog;
  if (LittleFS.exists(currentLog)) {
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
  String testData = "ESP8266 SD Test - " + getISOTimestamp();
  
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
  
  if (readBack.startsWith("ESP8266 SD Test")) {
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

// LED indicator functions
void ledHeartbeat() {
  // Single short flash
  digitalWrite(LED_PIN, LOW);  // LED ON (active low)
  delay(50);
  digitalWrite(LED_PIN, HIGH); // LED OFF
}

void ledSampleFlash() {
  // Rapid triple flash to indicate data saved
  for (int i = 0; i < 3; i++) {
    digitalWrite(LED_PIN, LOW);  // LED ON
    delay(80);
    digitalWrite(LED_PIN, HIGH); // LED OFF
    delay(80);
  }
}

void setup() {
  Serial.begin(115200);
  delay(1000);
  
  // Initialize LED indicator
  pinMode(LED_PIN, OUTPUT);
  digitalWrite(LED_PIN, HIGH); // LED OFF (active low)
  
  Serial.println("\n\nESP8266 Temperature/Humidity Logger");
  Serial.println("====================================");
  
  // Initialize LittleFS
  if (!LittleFS.begin()) {
    Serial.println("LittleFS mount failed!");
    return;
  }
  Serial.println("LittleFS mounted");
  
  // Ensure /logs/ directory exists
  if (!LittleFS.exists("/logs")) {
    LittleFS.mkdir("/logs");
    Serial.println("Created /logs directory");
  }
  
  // Initialize SD card (optional)
  if (SD.begin(SS)) {
    sdPresent = true;
    Serial.println("SD card initialized");
  } else {
    Serial.println("SD card not present or failed");
  }
  
  // Initialize sensor
  if (!sensor.begin()) {
    Serial.println("Si7021 sensor not found!");
  } else {
    Serial.println("Si7021 sensor initialized");
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
  
  // Setup WiFi AP
  WiFi.mode(WIFI_AP);
  WiFi.softAPConfig(apIP, apIP, IPAddress(255, 255, 255, 0));
  WiFi.softAP(config.ap_ssid.c_str(), config.ap_password.c_str());
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
  
  // Initialize random seed
  randomSeed(analogRead(0));
  
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
  
  // Non-blocking sampling
  unsigned long intervalMs = (unsigned long)config.sample_period_s * 1000UL;
  
  // Take first sample immediately (lastSampleTime starts at 0)
  // Then sample at configured interval
  if (lastSampleTime == 0 || (now - lastSampleTime >= intervalMs)) {
    float temperature = sensor.readTemperature();
    float humidity = sensor.readHumidity();
    
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
  
  yield();
}
