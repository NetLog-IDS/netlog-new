#ifndef _SENDER_H_
#define _SENDER_H_

#include <tins/tins.h>

#include <memory>
#include <string_view>
// maybe #include <librdkafka/rdkafkacpp.h>
#include <rdkafkacpp.h>

namespace spoofy {

class SendingStrategy {
   public:
    virtual ~SendingStrategy() {}  // implement this in cpp file or all hell breaks loose
    virtual void send(Tins::Packet &p) = 0;
};

/**
 * @brief Context for sending and receiving packets with different strategies
 */
class Sender {
   public:
    Sender(std::unique_ptr<SendingStrategy> sender = nullptr);
    ~Sender();

    void send_packet(Tins::Packet &p);

    void set_sender(std::unique_ptr<SendingStrategy> send_strategy);

   private:
    std::unique_ptr<SendingStrategy> sender_;
};

/**
 * @brief Sends packets using libtins, on specified interface
 * @code
 *     auto pkt = Tins::EthernetII(eth.src_addr(), eth.dst_addr()) /
 *         Tins::IP(ip.src_addr(), ip.dst_addr()) /
 *         Tins::UDP(udp.sport(), udp.dport());
 *     SendingContext sc(std::make_unique<NetworkSender>("eth0");
 *     sc.send(pkt)
 * @endcode
 */
class NetworkSender : public SendingStrategy {
   public:
    NetworkSender(const char *interface);

   private:
    virtual void send(Tins::Packet &pdu);

    Tins::NetworkInterface interface_;
    Tins::PacketSender packet_sender_;
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
class ExampleDeliveryReportCb : public RdKafka::DeliveryReportCb {
   public:
    void dr_cb(RdKafka::Message &message);
};
class KafkaSender : public SendingStrategy {
   public:
    KafkaSender(const char *brokers, std::string topic);
    ~KafkaSender();

   private:
    virtual void send(Tins::Packet &pdu);
    std::string jsonify(Tins::Packet &pdu);

    ExampleDeliveryReportCb ex_dr_cb_;
    RdKafka::Producer *producer_;
    std::string brokers_;
    std::string topic_;
};

}  // namespace spoofy
#endif  // _SENDER_H_