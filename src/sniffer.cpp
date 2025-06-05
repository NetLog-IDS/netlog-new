#include "spoofy/sniffer.h"

#include <rapidjson/document.h>

#include <exception>
#include <functional>
#include <iostream>
#include <mutex>
#include <thread>

#include "shared.hpp"
#include "spoofy/jsonbuilder.h"
namespace spoofy {

/**
 * @brief Class constructor.
 * @param[in] st Type of Sniffer used in the packet capture process.
 * @param[in] iface Name of interface on which to run the capture. Can be a
 * file path, if using the file sniffer.
 * @param[in] capture_filter Type of packet to capture, contains PCAP filter
 * @returns PacketSniffer object
 * */
PacketSniffer::PacketSniffer(SnifferType st, const char* iface, const char* capture_filter) : sniffer_type_(st) {
    setup(st, iface, capture_filter);
}

/**
 * @brief Setup function. Used to initialize all the sniffer parameters.
 * @param[in] st Type of Sniffer used in the packet capture process.
 * @param[in] iface Name of interface on which to run the capture. Can be a
 * file path, if using the file sniffer.
 * @param[in] capture_filter Type of packet to capture, contains PCAP filter
 * */
void PacketSniffer::setup(SnifferType st, const char* iface, const char* capture_filter) {
    Tins::SnifferConfiguration config;
    config.set_immediate_mode(true);
    config.set_promisc_mode(true);
    config.set_filter(capture_filter);

    try {
        if (st == SnifferType::FileSniffer) {
            sniffer_ = std::make_unique<Tins::FileSniffer>(iface, config);
        } else {
            sniffer_ = std::make_unique<Tins::Sniffer>(iface, config);
        }
    } catch (const Tins::pcap_error& e) {
        throw std::runtime_error(e.what());
    } catch (const std::exception& e) {
        throw std::runtime_error(e.what());
    }
}

/**
 * @brief Callback function. This gets called each time a packet is captured.
 * @param[in] packet Captured packet.
 * @param[in] packetq Queue used to store the captured packets.
 * @param[in] running Boolean used to manage running state, and end the capture
 * when needed.
 * */
/* bool PacketSniffer::callback(const Tins::Packet &packet, ThreadSafeQueue<Tins::Packet> &packetq, bool &running) {
    packetq.push(packet);
    return running;
} */

/**
 * @brief Run function. Used to bind values provided via the API to the callback
 * function.
 * @param[in] packetq Queue used to store the captured packets.
 * @param[in] running Boolean used to manage running state, and end the capture
 * when needed.
 * */
void PacketSniffer::run(std::vector<std::tuple<std::string, rapidjson::Document, std::string>>& packetq,
                        std::atomic_bool& running) {
    sniffer_->sniff_loop([this, &pq = packetq, &running](Tins::Packet& packet) -> bool {
        try {
            std::string pkt_str = jsonify(packet);

            rapidjson::Document document;
            document.Parse(pkt_str.c_str());

            if (document.HasParseError()) {
                return true;
            }

            if (!document.HasMember("layers") || !document["layers"].HasMember("transport") ||
                !document["layers"].HasMember("network")) {
                return true;
            }

            std::string flow_id = std::string(document["layers"]["network"]["src"].GetString()) + "-" +
                                  document["layers"]["network"]["dst"].GetString() + "-" +
                                  std::to_string(document["layers"]["transport"]["src_port"].GetInt()) + "-" +
                                  std::to_string(document["layers"]["transport"]["dst_port"].GetInt()) + "-" +
                                  document["layers"]["transport"]["type"].GetString();

            std::lock_guard<std::mutex> lock(packet_mutex);
            pq.push_back({flow_id, std::move(document), pkt_str});
        } catch (const std::exception& e) {
            std::cerr << "[Sniffer] Packet parse error: " << e.what() << std::endl;
        } catch (...) {
            std::cerr << "[Sniffer] Unknown packet exception!" << std::endl;
        }

        return running.load();
    });
}

std::string PacketSniffer::jsonify(Tins::Packet& pdu) {
    rapidjson::StringBuffer sb;
    JsonBuilder jb(std::make_unique<TinsJsonBuilder>(&pdu, std::make_unique<JsonWriter>(sb)));
    jb.build_json();

    return sb.GetString();
}

}  // namespace spoofy
