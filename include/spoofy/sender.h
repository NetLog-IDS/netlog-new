#ifndef _SENDER_H_
#define _SENDER_H_

#include <rdkafkacpp.h>
#include <tins/tins.h>

#include <atomic>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <memory>
#include <string_view>
#include <thread>

namespace fs = std::filesystem;

namespace spoofy {

class SendingStrategy {
   public:
    virtual ~SendingStrategy() {}  // implement this in cpp file or all hell breaks loose
    virtual void send(std::string &form_id, std::string &p) = 0;
};

/**
 * @brief Context for sending and receiving packets with different strategies
 */
class Sender {
   public:
    Sender(std::unique_ptr<SendingStrategy> sender = nullptr);
    ~Sender();

    void send_packet(std::string &form_id, std::string &p);

    void set_sender(std::unique_ptr<SendingStrategy> send_strategy);

   private:
    std::unique_ptr<SendingStrategy> sender_;
};

class DeliveryReportCb : public RdKafka::DeliveryReportCb {
   public:
    void dr_cb(RdKafka::Message &message);
};

class StatsEventCb : public RdKafka::EventCb {
   public:
    std::ofstream log_file_;
    StatsEventCb() {
        fs::create_directories(dir_path_);

        log_file_.open(file_path_, std::ios::out | std::ios::app);

        // log_file_.open("kafka_metrics.csv", std::ios::out | std::ios::app);
        if (!log_file_.is_open()) {
            std::cerr << "Failed to open metrics log file!\n";
            exit(1);
        }
        try {
            fs::permissions(file_path_, fs::perms::owner_all | fs::perms::group_all | fs::perms::others_all,
                            fs::perm_options::replace);
        } catch (const fs::filesystem_error &e) {
            std::cerr << "Failed to set permissions: " << e.what() << "\n";
        }
    }

    ~StatsEventCb() {
        if (log_file_.is_open()) {
            log_file_.close();
        }
    }

    void event_cb(RdKafka::Event &event);

    void processStats(const std::string &stats_str);

   private:
    int64_t last_txmsgs_{0};
    int64_t last_txmsg_bytes_{0};
    int64_t start_timestamp_ms_{-1};
    int64_t last_timestamp_ms_{0};

    const std::string dir_path_ = "/app/utils/eval/throughput";
    const std::string file_path_ = dir_path_ + "/prod_netlog_throughput_log.csv";
};

/**
 * @brief Sends packet to Apache Kafka using librdkafka
 * @code
 *     auto pkt = Tins::EthernetII(eth.src_addr(), eth.dst_addr()) /
 *         Tins::IP(ip.src_addr(), ip.dst_addr()) /
 *         Tins::UDP(udp.sport(), udp.dport());
 *     SendingContext sc(std::make_unique<KafkaSender>("Broker Name", "Topic name");
 *     sc.send(pkt)
 * @endcode
 */
class KafkaSender : public SendingStrategy {
   public:
    KafkaSender(const char *brokers, std::string topic);
    ~KafkaSender();

   private:
    virtual void send(std::string &form_id, std::string &packet);

    StatsEventCb stats_event_cb_;
    DeliveryReportCb dr_cb_;
    RdKafka::Producer *producer_;
    std::string brokers_;
    std::string topic_;
};

}  // namespace spoofy
#endif  // _SENDER_H_