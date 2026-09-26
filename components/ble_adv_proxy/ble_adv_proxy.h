#pragma once

#include "esphome/core/component.h"
#include "esphome/core/version.h"
#include "esphome/components/esp32_ble/ble.h"
#include "esphome/components/api/custom_api_device.h"
#include "esphome/components/text_sensor/text_sensor.h"

#include <freertos/semphr.h>
#include <esp_gap_ble_api.h>
#include <array>
#include <atomic>
#include <list>
#include <vector>

namespace esphome {

namespace ble_adv_proxy {

static constexpr size_t MAX_PACKET_LEN = 31;

class BleAdvParam {
 public:
  BleAdvParam(const std::string &hex_string, uint32_t duration);
  BleAdvParam(const uint8_t *buf, size_t len, const esp_bd_addr_t &orig, uint32_t duration);
  BleAdvParam(BleAdvParam &&) = default;
  BleAdvParam &operator=(BleAdvParam &&) = default;

  uint32_t duration_{100};
  uint8_t buf_[MAX_PACKET_LEN]{0};
  size_t len_{0};
  esp_bd_addr_t orig_{0};
};

/**
  BleAdvProxy:
 */
#if ESPHOME_VERSION_CODE >= VERSION_CODE(2026, 4, 0)
class BleAdvProxy : public Component, public Parented<esp32_ble::ESP32BLE>, public api::CustomAPIDevice {
#else
class BleAdvProxy : public Component,
                    public esp32_ble::GAPScanEventHandler,
                    public Parented<esp32_ble::ESP32BLE>,
                    public api::CustomAPIDevice {
#endif
 public:
  // component handling
  void setup() override;
  void loop() override;
  void dump_config() override;

  // Scanner registration
#if ESPHOME_VERSION_CODE >= VERSION_CODE(2026, 4, 0)
  void gap_scan_event_handler(const esp32_ble::BLEScanResult &scan_result);
#else
  void gap_scan_event_handler(const esp32_ble::BLEScanResult &scan_result) override;
#endif

  void set_use_max_tx_power(bool use_max_tx_power) { this->use_max_tx_power_ = use_max_tx_power; }
  // Fixed BLE advertising interval in ms for every repetition (0 = legacy: interval follows the command's
  // repetition duration, giving ~1 copy per repetition)
  void set_adv_interval(uint32_t interval_ms) { this->adv_interval_ms_ = interval_ms; }
  // Static filters from YAML: applied in the scan handler, before any copy / lock / HA forwarding
  void add_static_ignored_cid(uint16_t cid) { this->static_ign_cids_.push_back(cid); }
  void add_static_ignored_mac(const std::string &mac);
  // Traffic report period in ms (0 disables the report)
  void set_stats_interval(uint32_t interval_ms) { this->stats_interval_ms_ = interval_ms; }
  void set_sensor_name(text_sensor::TextSensor *sens, const std::string &adapter_name) {
    this->sensor_name_ = sens;
    this->sensor_name_->state = adapter_name;
  }
  void on_setup_v0(float ign_duration, std::vector<float> ignored_cids, std::vector<std::string> ignored_macs);
  void on_advertise_v0(std::string raw, float duration);
  void on_advertise_v1(std::string raw, float duration, float repeat, std::vector<std::string> ignored_advs,
                       float ign_duration);
  void on_raw_recv(const BleAdvParam &param, const std::string &str_mac);
  bool check_add_dupe_packet(BleAdvParam &&packet);

 protected:
  /**
    Performing RAW ADV
   */
  std::list<BleAdvParam> send_packets_;
  uint32_t adv_stop_time_ = 0;

  esp_ble_adv_params_t adv_params_ = {
      .adv_int_min = 0x20,
      .adv_int_max = 0x20,
      .adv_type = ADV_TYPE_IND,
      .own_addr_type = BLE_ADDR_TYPE_PUBLIC,
      .peer_addr = {0x00},
      .peer_addr_type = BLE_ADDR_TYPE_PUBLIC,
      .channel_map = ADV_CHNL_ALL,
      .adv_filter_policy = ADV_FILTER_ALLOW_SCAN_ANY_CON_ANY,
  };

  bool use_max_tx_power_ = false;
  uint32_t adv_interval_ms_ = 0;
  bool max_tx_power_setup_done_ = false;
  void setup_max_tx_power();

  /**
    Listening to ADV
   */
  SemaphoreHandle_t scan_result_lock_;
  uint32_t dupe_ignore_duration_ = 20000;
  std::list<esp32_ble::BLEScanResult> recv_packets_;
  std::list<BleAdvParam> dupe_packets_;
  std::vector<std::string> ign_macs_;
  std::vector<uint16_t> ign_cids_;

  /**
    Static filtering (YAML), independent from the HA provided lists above
   */
  bool is_statically_ignored_(const esp32_ble::BLEScanResult &sr) const;
  std::vector<uint16_t> static_ign_cids_;
  std::vector<std::array<uint8_t, ESP_BD_ADDR_LEN>> static_ign_macs_;
  std::atomic<uint32_t> static_ignored_count_{0};
  uint32_t last_filter_log_ = 0;

  /**
    Traffic stats (all updated from loop() context, except static_ignored_count_)
   */
  struct FwdSource {
    std::array<uint8_t, ESP_BD_ADDR_LEN> mac;  // last MAC seen for this source
    std::array<uint8_t, 6> head;               // first payload bytes, to identify sources without mfr data
    uint8_t head_len;
    uint16_t cid;
    bool has_cid;
    uint32_t count;
  };
  static constexpr size_t STATS_MAX_SOURCES = 16;
  void record_forwarded_(const BleAdvParam &param);
  void report_stats_();
  uint32_t stats_interval_ms_ = 60000;
  uint32_t stats_forwarded_ = 0;
  uint32_t stats_ha_ignored_ = 0;
  uint32_t stats_dupes_ = 0;
  uint32_t stats_untracked_ = 0;  // forwarded from sources beyond STATS_MAX_SOURCES
  std::vector<FwdSource> fwd_sources_;

  /*
  API Discovery
  */
  bool setup_done_ = false;
  text_sensor::TextSensor *sensor_name_ = nullptr;
};

}  // namespace ble_adv_proxy
}  // namespace esphome
