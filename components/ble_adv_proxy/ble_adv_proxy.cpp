#include "ble_adv_proxy.h"
#include "esphome/core/log.h"
#include "esphome/core/application.h"
#include <esp_err.h>
#include <esp_bt.h>
#include <esp_bt_device.h>
#include <algorithm>
#include <cstdio>

#ifdef ESP_PWR_LVL_P20
#define MAX_TX_POWER ESP_PWR_LVL_P20
#elif ESP_PWR_LVL_P18
#define MAX_TX_POWER ESP_PWR_LVL_P18
#elif ESP_PWR_LVL_P15
#define MAX_TX_POWER ESP_PWR_LVL_P15
#elif ESP_PWR_LVL_P12
#define MAX_TX_POWER ESP_PWR_LVL_P12
#else
#define MAX_TX_POWER ESP_PWR_LVL_P9
#endif

namespace esphome {
namespace ble_adv_proxy {

static constexpr const char *TAG = "ble_adv_proxy";
static constexpr const char *ADV_RECV_EVENT = "esphome.ble_adv.raw_adv";
static constexpr const char *SETUP_SVC_V0 = "setup_svc_v0";
static constexpr const char *CONF_IGN_ADVS = "ignored_advs";
static constexpr const char *CONF_IGN_CIDS = "ignored_cids";
static constexpr const char *CONF_IGN_MACS = "ignored_macs";
static constexpr const char *CONF_IGN_DURATION = "ignored_duration";
static constexpr const char *ADV_SVC_V0 = "adv_svc";  // legacy name / service
static constexpr const char *ADV_SVC_V1 = "adv_svc_v1";
static constexpr const char *CONF_RAW = "raw";
static constexpr const char *CONF_ORIGIN = "orig";
static constexpr const char *CONF_DURATION = "duration";
static constexpr const char *CONF_REPEAT = "repeat";

static constexpr const uint8_t REPEAT_NB = 3;
static constexpr const uint32_t MIN_ADV = 0x20;    // 20ms, BLE minimum
static constexpr const uint32_t MAX_ADV = 0x4000;  // 10.24s, BLE maximum
static constexpr const uint8_t MIN_VIABLE_PACKET_LEN = 5;
static constexpr const uint8_t AD_TYPE_MANUFACTURER_DATA = 0xFF;
static constexpr const size_t STATS_TOP_N = 5;

// Company ID of the first Manufacturer Specific Data AD structure, if any
static bool first_mfr_cid(const uint8_t *buf, size_t end, uint16_t &cid) {
  size_t pos = 0;
  while (pos + 1 < end) {
    const uint8_t len = buf[pos];
    if (len == 0 || pos + 1 + len > end) {
      return false;
    }
    if (buf[pos + 1] == AD_TYPE_MANUFACTURER_DATA && len >= 3) {
      cid = uint16_t(buf[pos + 2]) | (uint16_t(buf[pos + 3]) << 8);
      return true;
    }
    pos += 1 + len;
  }
  return false;
}

BleAdvParam::BleAdvParam(const std::string &hex_string, uint32_t duration)
    : duration_(duration), len_(std::min(MAX_PACKET_LEN, hex_string.size() / 2)) {
  esphome::parse_hex(hex_string, this->buf_, this->len_);
}

BleAdvParam::BleAdvParam(const uint8_t *buf, size_t len, const esp_bd_addr_t &orig, uint32_t duration)
    : duration_(duration), len_(std::min(MAX_PACKET_LEN, len)) {
  std::copy(buf, buf + this->len_, this->buf_);
  std::copy(orig, orig + ESP_BD_ADDR_LEN, this->orig_);
}

void BleAdvProxy::setup() {
  this->register_service(&BleAdvProxy::on_setup_v0, SETUP_SVC_V0, {CONF_IGN_DURATION, CONF_IGN_CIDS, CONF_IGN_MACS});
  this->register_service(&BleAdvProxy::on_advertise_v0, ADV_SVC_V0, {CONF_RAW, CONF_DURATION});
  this->register_service(&BleAdvProxy::on_advertise_v1, ADV_SVC_V1,
                         {CONF_RAW, CONF_DURATION, CONF_REPEAT, CONF_IGN_ADVS, CONF_IGN_DURATION});
  this->scan_result_lock_ = xSemaphoreCreateMutex();
  this->fwd_sources_.reserve(STATS_MAX_SOURCES);  // no reallocation in the hot path
  if (this->sensor_name_->state.empty()) {
    this->sensor_name_->state = App.get_name();
  }
  this->sensor_name_->publish_state(this->sensor_name_->state);
}

void BleAdvProxy::dump_config() {
  ESP_LOGCONFIG(TAG, "BleAdvProxy '%s'", this->sensor_name_->state.c_str());
  ESP_LOGCONFIG(TAG, "  Use Max TxPower: %s", this->use_max_tx_power_ ? "True" : "False");
  if (this->adv_interval_ms_ > 0) {
    ESP_LOGCONFIG(TAG, "  Advertising interval: fixed %ums", (unsigned) this->adv_interval_ms_);
  } else {
    ESP_LOGCONFIG(TAG, "  Advertising interval: per command (legacy)");
  }
  ESP_LOGCONFIG(TAG, "  Static filter: %u company IDs, %u MACs", (unsigned) this->static_ign_cids_.size(),
                (unsigned) this->static_ign_macs_.size());
  for (auto cid : this->static_ign_cids_) {
    ESP_LOGCONFIG(TAG, "    Ignored CID: 0x%04X", cid);
  }
  ESP_LOGCONFIG(TAG, "  Stats interval: %ums", (unsigned) this->stats_interval_ms_);
}

void BleAdvProxy::add_static_ignored_mac(const std::string &mac) {
  unsigned int b[ESP_BD_ADDR_LEN];
  if (sscanf(mac.c_str(), "%x:%x:%x:%x:%x:%x", &b[0], &b[1], &b[2], &b[3], &b[4], &b[5]) != ESP_BD_ADDR_LEN) {
    ESP_LOGE(TAG, "Invalid MAC in ignored_macs: %s", mac.c_str());
    return;
  }
  std::array<uint8_t, ESP_BD_ADDR_LEN> addr{};
  for (size_t i = 0; i < ESP_BD_ADDR_LEN; ++i) {
    addr[i] = uint8_t(b[i]);
  }
  this->static_ign_macs_.push_back(addr);
}

// Cheap check run on every scanned packet: MAC compare, then walk the AD structures
// looking for Manufacturer Specific Data (0xFF) whose company ID is ignored.
bool BleAdvProxy::is_statically_ignored_(const esp32_ble::BLEScanResult &sr) const {
  for (const auto &mac : this->static_ign_macs_) {
    if (std::equal(mac.begin(), mac.end(), sr.bda)) {
      return true;
    }
  }
  if (this->static_ign_cids_.empty()) {
    return false;
  }
  const size_t end = sr.adv_data_len;
  size_t pos = 0;
  while (pos + 1 < end) {
    const uint8_t len = sr.ble_adv[pos];  // length of [type + data]
    if (len == 0 || pos + 1 + len > end) {
      break;  // malformed / padding: stop parsing
    }
    if (sr.ble_adv[pos + 1] == AD_TYPE_MANUFACTURER_DATA && len >= 3) {
      const uint16_t cid = uint16_t(sr.ble_adv[pos + 2]) | (uint16_t(sr.ble_adv[pos + 3]) << 8);
      if (std::find(this->static_ign_cids_.begin(), this->static_ign_cids_.end(), cid) !=
          this->static_ign_cids_.end()) {
        return true;
      }
    }
    pos += 1 + len;
  }
  return false;
}

void BleAdvProxy::on_setup_v0(float ign_duration, std::vector<float> ignored_cids,
                              std::vector<std::string> ignored_macs) {
  this->dupe_ignore_duration_ = ign_duration;
  this->dupe_packets_.clear();
  this->ign_cids_.clear();
  for (auto &ign_cid : ignored_cids) {
    this->ign_cids_.emplace_back(uint16_t(ign_cid));
  }
  ESP_LOGI(TAG, "SETUP - %d Company IDs Permanently ignored.", this->ign_cids_.size());
  this->ign_macs_.clear();
  std::swap(ignored_macs, this->ign_macs_);
  ESP_LOGI(TAG, "SETUP - %d MACs Permanently ignored.", this->ign_macs_.size());
  this->setup_done_ = true;
}

void BleAdvProxy::on_advertise_v0(std::string raw, float duration) {
  this->on_advertise_v1(raw, duration / REPEAT_NB, REPEAT_NB, {raw}, this->dupe_ignore_duration_);
}

void BleAdvProxy::on_advertise_v1(std::string raw, float duration, float repeat, std::vector<std::string> ignored_advs,
                                  float ign_duration) {
  this->setup_done_ = true;  // Flag setup done as best effort
  uint8_t int_repeat = uint8_t(repeat);
  uint32_t int_duration = uint32_t(duration);
  uint32_t int_ign_duration = uint32_t(ign_duration);
  ESP_LOGD(TAG, "send adv - %s, duration %ldms, repeat: %d", raw.c_str(), int_duration, int_repeat);
  for (uint8_t i = 0; i < int_repeat; ++i) {
    this->send_packets_.emplace_back(raw, int_duration);
  }
  // Prevent ignored packets from being re sent to HA host in case received
  for (auto &ignored_adv : ignored_advs) {
    // ESP_LOGD(TAG, "Ignoring ADV for %lds: %s", int_ign_duration / 1000, ignored_adv.c_str());
    this->check_add_dupe_packet(BleAdvParam(ignored_adv, millis() + int_ign_duration));
  }
}

bool BleAdvProxy::check_add_dupe_packet(BleAdvParam &&packet) {
  // Check the recently received advs
  auto idx = std::find_if(this->dupe_packets_.begin(), this->dupe_packets_.end(), [&](BleAdvParam &p) {
    return (p.len_ <= packet.len_) && std::equal(p.buf_, p.buf_ + p.len_, packet.buf_);
  });
  if (idx != this->dupe_packets_.end()) {
    if (idx->duration_ > 0) {
      idx->duration_ = packet.duration_;  // Existing Packet with specified deletion time: Update the deletion time
    }
    return false;
  }
  this->dupe_packets_.emplace_back(std::move(packet));
  return true;
}

std::string get_str_mac(const uint8_t *mac) {
  return str_snprintf("%02X:%02X:%02X:%02X:%02X:%02X", 17, mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

void BleAdvProxy::on_raw_recv(const BleAdvParam &param, const std::string &str_mac) {
  std::string raw = esphome::format_hex(param.buf_, param.len_);
  ESP_LOGD(TAG, "[%s] recv raw - %s", str_mac.c_str(), raw.c_str());
  if (!this->is_connected() || !this->setup_done_) {
    ESP_LOGD(TAG, "Connection to HA not ready, received adv ignored.");
    return;
  }
  this->record_forwarded_(param);
  this->fire_homeassistant_event(ADV_RECV_EVENT, {{CONF_RAW, std::move(raw)}, {CONF_ORIGIN, std::move(str_mac)}});
}

// Group forwarded packets by company ID when present (phones rotate MACs), else by MAC
void BleAdvProxy::record_forwarded_(const BleAdvParam &param) {
  this->stats_forwarded_++;
  if (this->stats_interval_ms_ == 0) {
    return;
  }
  uint16_t cid = 0;
  const bool has_cid = first_mfr_cid(param.buf_, param.len_, cid);
  for (auto &s : this->fwd_sources_) {
    const bool same = has_cid ? (s.has_cid && s.cid == cid)
                              : (!s.has_cid && std::equal(s.mac.begin(), s.mac.end(), param.orig_));
    if (same) {
      s.count++;
      std::copy(param.orig_, param.orig_ + ESP_BD_ADDR_LEN, s.mac.begin());
      return;
    }
  }
  if (this->fwd_sources_.size() >= STATS_MAX_SOURCES) {
    this->stats_untracked_++;
    return;
  }
  FwdSource s{};
  std::copy(param.orig_, param.orig_ + ESP_BD_ADDR_LEN, s.mac.begin());
  s.head_len = uint8_t(std::min(s.head.size(), param.len_));
  std::copy(param.buf_, param.buf_ + s.head_len, s.head.begin());
  s.cid = cid;
  s.has_cid = has_cid;
  s.count = 1;
  this->fwd_sources_.push_back(s);
}

void BleAdvProxy::report_stats_() {
  const uint32_t static_dropped = this->static_ignored_count_.exchange(0, std::memory_order_relaxed);
  ESP_LOGI(TAG, "Last %us: forwarded %u | static-filtered %u | HA-filtered %u | dupes %u",
           (unsigned) (this->stats_interval_ms_ / 1000), (unsigned) this->stats_forwarded_, (unsigned) static_dropped,
           (unsigned) this->stats_ha_ignored_, (unsigned) this->stats_dupes_);
  if (!this->fwd_sources_.empty()) {
    const size_t n = std::min(STATS_TOP_N, this->fwd_sources_.size());
    std::partial_sort(this->fwd_sources_.begin(), this->fwd_sources_.begin() + n, this->fwd_sources_.end(),
                      [](const FwdSource &a, const FwdSource &b) { return a.count > b.count; });
    for (size_t i = 0; i < n; ++i) {
      const FwdSource &s = this->fwd_sources_[i];
      const std::string mac = get_str_mac(s.mac.data());
      if (s.has_cid) {
        ESP_LOGI(TAG, "  #%u cid=0x%04X x%u (last MAC %s)", (unsigned) (i + 1), s.cid, (unsigned) s.count,
                 mac.c_str());
      } else {
        const std::string head = esphome::format_hex(s.head.data(), s.head_len);
        ESP_LOGI(TAG, "  #%u MAC %s x%u (no mfr data, starts %s)", (unsigned) (i + 1), mac.c_str(),
                 (unsigned) s.count, head.c_str());
      }
    }
    if (this->stats_untracked_ > 0) {
      ESP_LOGI(TAG, "  + %u from further sources", (unsigned) this->stats_untracked_);
    }
  }
  this->stats_forwarded_ = 0;
  this->stats_ha_ignored_ = 0;
  this->stats_dupes_ = 0;
  this->stats_untracked_ = 0;
  this->fwd_sources_.clear();
}

void BleAdvProxy::setup_max_tx_power() {
  if (this->max_tx_power_setup_done_ || !this->use_max_tx_power_) {
    return;
  }

  esp_power_level_t lev_init = esp_ble_tx_power_get(ESP_BLE_PWR_TYPE_ADV);
  ESP_LOGD(TAG, "Advertising TX Power enum value (NOT dBm) before max setup: %d", lev_init);

  if (lev_init != MAX_TX_POWER) {
    ESP_LOGI(TAG, "Advertising TX Power setup attempt to: %d", MAX_TX_POWER);
    esp_ble_tx_power_set(ESP_BLE_PWR_TYPE_ADV, MAX_TX_POWER);
    esp_power_level_t lev_final = esp_ble_tx_power_get(ESP_BLE_PWR_TYPE_ADV);
    ESP_LOGI(TAG, "Advertising TX Power enum value (NOT dBm) after max setup: %d", lev_final);
  } else {
    ESP_LOGI(TAG, "Advertising TX Power already at max: %d", MAX_TX_POWER);
  }

  this->max_tx_power_setup_done_ = true;
}

void BleAdvProxy::loop() {
  if (!this->get_parent()->is_active()) {
    // esp32_ble::ESP32BLE not ready: do not process any action
    return;
  }

  if (!this->is_connected() && this->setup_done_) {
    ESP_LOGI(TAG, "HA Connection lost.");
    this->setup_done_ = false;
  }

  // Cleanup expired packets
  this->dupe_packets_.remove_if([&](BleAdvParam &p) { return p.duration_ > 0 && p.duration_ < millis(); });

  // Periodic traffic report (visible at INFO log level)
  const uint32_t now = millis();
  if (this->stats_interval_ms_ > 0 && now - this->last_filter_log_ >= this->stats_interval_ms_) {
    this->last_filter_log_ = now;
    this->report_stats_();
  }

  // swap packet list to further process it outside of the lock
  std::list<esp32_ble::BLEScanResult> new_packets;
  if (xSemaphoreTake(this->scan_result_lock_, 5L / portTICK_PERIOD_MS)) {
    std::swap(this->recv_packets_, new_packets);
    xSemaphoreGive(this->scan_result_lock_);
  } else {
    ESP_LOGW(TAG, "loop - failed to take lock");
  }

  // handle new packets, exclude if one of the following is true:
  // - len is too small
  // - company ID is part of ignored company ids
  // - mac is part of ignored macs
  // - is dupe of previously received
  for (auto &sr : new_packets) {
    uint16_t cid = (sr.ble_adv[3] << 8) + sr.ble_adv[2];
    std::string str_mac = get_str_mac(sr.bda);
    if (std::find(this->ign_cids_.begin(), this->ign_cids_.end(), cid) != this->ign_cids_.end() ||
        std::find(this->ign_macs_.begin(), this->ign_macs_.end(), str_mac) != this->ign_macs_.end()) {
      this->stats_ha_ignored_++;
      continue;
    }
    if (!this->check_add_dupe_packet(
            BleAdvParam(sr.ble_adv, sr.adv_data_len, sr.bda, millis() + this->dupe_ignore_duration_))) {
      this->stats_dupes_++;
      continue;
    }
    this->on_raw_recv(this->dupe_packets_.back(), str_mac);
  }

  // Process advertising
  if (this->adv_stop_time_ == 0) {
    // No packet is being advertised, advertise the front one
    if (!this->send_packets_.empty()) {
      BleAdvParam &packet = this->send_packets_.front();
      this->setup_max_tx_power();
      ESP_ERROR_CHECK_WITHOUT_ABORT(esp_ble_gap_config_adv_data_raw(packet.buf_, packet.len_));
      // BLE advertising interval unit is 0.625ms (x1.6 per ms). Fixed interval if configured, else legacy
      // behaviour (interval ~= repetition duration, i.e. ~1 copy per repetition). Computed in 32 bits and
      // clamped: the legacy uint8_t cast overflowed for durations above ~159ms.
      const uint32_t req_ms = this->adv_interval_ms_ > 0 ? this->adv_interval_ms_ : packet.duration_;
      const uint16_t adv_time = uint16_t(std::clamp<uint32_t>((req_ms * 16) / 10, MIN_ADV, MAX_ADV));
      this->adv_params_.adv_int_min = adv_time;
      this->adv_params_.adv_int_max = adv_time;
      ESP_ERROR_CHECK_WITHOUT_ABORT(esp_ble_gap_start_advertising(&(this->adv_params_)));
      this->adv_stop_time_ = millis() + packet.duration_;
    }
  } else {
    // Packet is being advertised, stop advertising and remove packet
    if (millis() > this->adv_stop_time_) {
      ESP_ERROR_CHECK_WITHOUT_ABORT(esp_ble_gap_stop_advertising());
      this->adv_stop_time_ = 0;
      this->send_packets_.pop_front();
    }
  }
}

// We let the configuration of the scanning to esp32_ble_tracker, towards with stop / start
// We only gather directly the raw events
void BleAdvProxy::gap_scan_event_handler(const esp32_ble::BLEScanResult &sr) {
  if (sr.adv_data_len <= MAX_PACKET_LEN && sr.adv_data_len >= MIN_VIABLE_PACKET_LEN) {
    // Drop statically ignored packets before any lock, copy or allocation
    if (this->is_statically_ignored_(sr)) {
      this->static_ignored_count_.fetch_add(1, std::memory_order_relaxed);
      return;
    }
    if (xSemaphoreTake(this->scan_result_lock_, 5L / portTICK_PERIOD_MS)) {
      this->recv_packets_.emplace_back(sr);
      xSemaphoreGive(this->scan_result_lock_);
    } else {
      ESP_LOGW(TAG, "evt - failed to take lock");
    }
  }
}

}  // namespace ble_adv_proxy
}  // namespace esphome
