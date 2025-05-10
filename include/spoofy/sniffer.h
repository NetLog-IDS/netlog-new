#ifndef _SNIFFER_H_
#define _SNIFFER_H_
#include <rapidjson/document.h>
#include <tins/tins.h>

#include <atomic>
#include <memory>

#include "spoofy/utils/queue.h"

namespace spoofy {

enum class SnifferType { Sniffer, FileSniffer };

/**
 * @class PacketSniffer
 *
 * @brief Responsible for setting up and running the packet capture process via
 * the libtins library.
 * */
class PacketSniffer {
   public:
    PacketSniffer(SnifferType st, const char *iface, const char *capture_filter);
    PacketSniffer() = delete;

    void run(std::vector<std::tuple<std::string, rapidjson::Document, std::string>> &raw_packetq,
             std::atomic_bool &running);

   private:
    //    bool callback(const Tins::Packet &packet, ThreadSafeQueue<Tins::Packet> &packetq, bool &running);
    void setup(SnifferType st, const char *iface, const char *capture_filter);

    std::string jsonify(Tins::Packet &pdu);

    SnifferType sniffer_type_;
    std::unique_ptr<Tins::BaseSniffer> sniffer_;
};
}  // namespace spoofy
#endif  // _SNIFFER_H_
