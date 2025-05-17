#include "spoofy/app.h"

#include <rapidjson/document.h>

#include <atomic>
#include <cerrno>
#include <chrono>
#include <csignal>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <ctime>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <memory>
#include <mutex>
#include <optional>
#include <sstream>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

#include "shared.hpp"
#include "spoofy/jsonbuilder.h"
#include "spoofy/sender.h"
#include "spoofy/sniffer.h"
#include "spoofy/utils/rand.h"

namespace fs = std::filesystem;

namespace spoofy {

struct ApplicationContext {
    ApplicationContext(int argc, char *argv[]) : arg_parser(argc, argv) {}

    cclap::ArgParser arg_parser;
    struct CliArgs {
        SnifferType sniffer_type;
        std::string capture_filter;
        std::string interface_name;
        std::optional<std::string> broker;
        std::optional<std::string> topic;
        std::optional<std::string> network_sending_interface;
        std::optional<bool> is_replay;
    } args;

    ThreadSafeQueue<Tins::Packet> raw_packetq;
    ThreadSafeQueue<std::pair<std::string, std::string>> packetq;
    std::vector<std::tuple<std::string, rapidjson::Document, std::string>> json_packets;
};

std::unique_ptr<Sender> setupSender(ApplicationContext *ctx) {
    auto sender = std::make_unique<Sender>();
    if (ctx->args.broker) {
        sender->set_sender(std::make_unique<KafkaSender>(ctx->args.broker.value().c_str(), ctx->args.topic.value()));
    }
    return sender;
}

/**
 * @brief Class constructor.
 * @param[in] argc Number of application input arguments
 * @param[in] argv List of command line arguments
 * @return Application object
 * */
Application::Application(int argc, char *argv[]) : ctx_(std::make_unique<ApplicationContext>(argc, argv)) { setup(); }

Application::~Application() = default;

void Application::setup() {
    std::cout << "[INFO] Setting up application..." << std::endl;
    // get sniffer type (read from file or live capture)
    ctx_->args.sniffer_type = ctx_->arg_parser.find_switch("l") || ctx_->arg_parser.find_switch("live")
                                  ? SnifferType::Sniffer
                                  : SnifferType::FileSniffer;

    // get specified interface name, or default network interface
    const auto &interface_found = ctx_->arg_parser.find_flag("i");
    ctx_->args.interface_name = [&interface_found] {
        if (!interface_found) {
            Tins::NetworkInterface ni = Tins::NetworkInterface::default_interface();
            const std::string interface_name(ni.name());
            std::cout << "[INFO] Network interface not specified, using default.\n";
            return interface_name;
        }
        return std::string(interface_found.value()[0].data());
    }();

    // get capture flags or empty string if not specified
    const auto &filter_found = ctx_->arg_parser.find_flag("f");
    ctx_->args.capture_filter = [&filter_found] {
        std::string res = "";
        if (!filter_found) {
            return res;
        }

        for (auto &s : filter_found.value()) {
            res.append(s);
            res.append(" ");
        }
        res.pop_back();
        return res;
    }();

    // get sender command line arguments
    const auto &senderfound = ctx_->arg_parser.find_flag("sender");
    if (!senderfound) {
        throw std::runtime_error("[ERROR - CLI args] Sender not specified.");
    }

    // set network sending interface optional - used in network sender
    ctx_->args.network_sending_interface = std::invoke([this, &senderfound]() -> std::optional<std::string> {
        if (!(senderfound.value()[0] == "network")) {
            return std::nullopt;
        }

        const auto &sinterface_found = ctx_->arg_parser.find_flag("network-sending-interface");
        if (!sinterface_found) {
            return std::nullopt;  // don't throw, if no interface is provided we will use the one from the capture
        }
        return std::make_optional<std::string>(sinterface_found.value()[0]);
    });

    // set broker optional - used for kafka sender
    ctx_->args.broker = std::invoke([this, &senderfound]() -> std::optional<std::string> {
        if (!(senderfound.value()[0] == "kafka")) {
            return std::nullopt;
        }

        const auto &broker_found = ctx_->arg_parser.find_flag("broker");
        if (!broker_found) {
            throw std::runtime_error("[ERROR - CLI args] Kafka broker not specified");
        }
        return std::make_optional<std::string>(broker_found.value()[0]);
    });

    // set topic optional - used for kafka sender
    ctx_->args.topic = std::invoke([this]() -> std::optional<std::string> {
        if (!ctx_->args.broker) {
            return std::nullopt;
        }

        const auto &topic_found = ctx_->arg_parser.find_flag("topic");
        if (!topic_found) {
            throw std::runtime_error("[ERROR - CLI args] Kafka topic not specified");
        }
        std::optional<std::string> res = std::make_optional<std::string>();
        res.value() = topic_found.value()[0];
        return res;
    });

    // replay mode (optional)
    ctx_->args.is_replay = ctx_->arg_parser.find_switch("replay");

    std::cout << "Sniffer Type: " << (ctx_->args.sniffer_type == SnifferType::Sniffer ? "Live" : "File") << std::endl;
    std::cout << "Capture Filter: " << ctx_->args.capture_filter << std::endl;
    std::cout << "Interface Name: " << ctx_->args.interface_name << std::endl;
    std::cout << "Sender: " << senderfound.value()[0] << std::endl;
    if (ctx_->args.broker) {
        std::cout << "Kafka Broker: " << ctx_->args.broker.value() << std::endl;
        std::cout << "Kafka Topic: " << ctx_->args.topic.value() << std::endl;
    }
    if (ctx_->args.is_replay.has_value() && ctx_->args.is_replay.value()) {
        std::cout << "Replay mode is ON." << std::endl;
    }
}

std::atomic<bool> stop_flag(false);
std::atomic_bool running(true);
std::mutex packet_mutex;

void signalHandler(int signal) {
    std::cout << "\n[INFO] Caught signal " << signal << ", stopping capture..." << std::endl;
    stop_flag.store(true);
}

/**
 * @brief Contains the high-level application logic.
 * */
void Application::start() {
    // Register signal handlers for SIGINT (Ctrl+C) and SIGTERM
    std::signal(SIGINT, signalHandler);
    std::signal(SIGTERM, signalHandler);

    std::atomic<int> total_packets_sent{0};

    try {
        // Start capturing packets and store them in a queue
        std::thread sniffer([this]() {
            PacketSniffer ps(ctx_->args.sniffer_type, ctx_->args.interface_name.data(),
                             ctx_->args.capture_filter.data());
            auto start_time = std::chrono::high_resolution_clock::now();

            std::cout << "[INFO] Starting capture..." << std::endl;
            ps.run(ctx_->json_packets, running);  // Capturing packets

            auto end_time = std::chrono::high_resolution_clock::now();
            std::chrono::duration<double, std::milli> duration = end_time - start_time;

            running.store(false);  // stop running after sniffing all packets
            std::cout << "[Sniffer] Packet captured and serialized to JSON in " << duration.count() << " ms"
                      << std::endl;
        });
        sniffer.join();
        auto sender = setupSender(ctx_.get());

        // std::thread kafka_producer([&]() {
        //     while (running || !ctx_->json_packets.empty()) {
        //         std::lock_guard<std::mutex> lock(packet_mutex);
        //         if (!ctx_->json_packets.empty()) {
        //             auto packet = std::move(ctx_->json_packets.back());
        //             ctx_->json_packets.pop_back();
        //             auto &doc = std::get<1>(packet);
        //             auto flow_id = std::get<0>(packet);

        //             if (!doc.HasMember("timestamp")) continue;

        //             int64_t sniff_now = std::chrono::duration_cast<std::chrono::microseconds>(
        //                                     std::chrono::system_clock::now().time_since_epoch())
        //                                     .count();
        //             std::string sniff_str = std::to_string(sniff_now);
        //             doc["sniff_time"].SetString(sniff_str.c_str(), doc.GetAllocator());

        //             // Serialize the modified rapidjson::Document back to a string
        //             rapidjson::StringBuffer buffer;
        //             rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
        //             doc.Accept(writer);
        //             std::string updated_pkt_str = buffer.GetString();

        //             sender->send_packet(flow_id, updated_pkt_str);
        //             total_packets_sent.fetch_add(1);
        //         }
        //     }
        // });

        // kafka_producer.join();
        // std::cout << "Total packets sent: " << total_packets_sent.load() << std::endl;

        std::thread kafka_producer([&]() {
            int iteration = 1;

            std::cout << "[INFO] Starting Kafka producer..." << std::endl;

            while (running || !stop_flag.load()) {
                bool is_replay = ctx_->args.is_replay.has_value() && ctx_->args.is_replay.value();
                auto start = std::chrono::high_resolution_clock::now();

                for (auto &packet : ctx_->json_packets) {
                    // parse the tuple
                    auto &doc = std::get<1>(packet);
                    auto flow_id = std::get<0>(packet);

                    if (!doc.HasMember("timestamp")) continue;

                    int64_t sniff_now = std::chrono::duration_cast<std::chrono::microseconds>(
                                            std::chrono::system_clock::now().time_since_epoch())
                                            .count();
                    std::string sniff_str = std::to_string(sniff_now);
                    doc["sniff_time"].SetString(sniff_str.c_str(), doc.GetAllocator());

                    // Serialize the modified rapidjson::Document back to a string
                    rapidjson::StringBuffer buffer;
                    rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
                    doc.Accept(writer);
                    std::string updated_pkt_str = buffer.GetString();

                    sender->send_packet(flow_id, updated_pkt_str);
                    total_packets_sent.fetch_add(1);
                }

                auto end = std::chrono::high_resolution_clock::now();
                std::chrono::duration<double, std::milli> elapsed = end - start;
                std::cout << "[Replay #" << iteration << "] Done. Elapsed time: " << elapsed.count() << " ms"
                          << std::endl;

                ++iteration;
                if (iteration == 51 || !is_replay) break;
            }
        });

        // sniffer.join();
        kafka_producer.join();
        std::cout << "Total packets sent: " << total_packets_sent.load() << std::endl;
    } catch (const std::exception &e) {
        std::cerr << "[ERROR] " << e.what() << std::endl;
        throw std::runtime_error(e.what());
        return;
    }

    if (ctx_->args.sniffer_type == SnifferType::FileSniffer) {
        std::cout << "[INFO] Read packets from capture file: " << ctx_->args.interface_name << std::endl;
    }
}

std::string Application::jsonify(Tins::Packet &pdu) {
    rapidjson::StringBuffer sb;
    JsonBuilder jb(std::make_unique<TinsJsonBuilder>(&pdu, std::make_unique<JsonWriter>(sb)));
    jb.build_json();

    return sb.GetString();
}

void Application::start_live() {
    auto sender = setupSender(ctx_.get());

    try {
        // Start capturing packets and store them in a queue
        std::thread sniffer([&]() {
            PacketSniffer ps(ctx_->args.sniffer_type, ctx_->args.interface_name.data(),
                             ctx_->args.capture_filter.data());
            ps.run(ctx_->json_packets, running);
            running.store(false);  // stop running after sniffing all packets
        });

        std::atomic<int> total_packets_sent{0};
        // Consume the packets stored in the queue and send them to Apache Kafka
        std::thread kafka_producer([&]() {
            while (running || !ctx_->json_packets.empty()) {
                std::lock_guard<std::mutex> lock(packet_mutex);
                if (!ctx_->json_packets.empty()) {
                    auto pkt = std::move(ctx_->json_packets.back());
                    ctx_->json_packets.pop_back();

                    sender->send_packet(std::get<0>(pkt), std::get<2>(pkt));
                    total_packets_sent.fetch_add(1);
                }
            }
        });

        if (ctx_->args.sniffer_type == SnifferType::Sniffer) {
            // Listen for user input to stop live capture
            std::cout << "[INFO] Live capture started on interface: " << ctx_->args.interface_name << std::endl;
            std::thread wait_for_key([&]() {
                std::cout << "Press [ENTER] to stop capture" << std::endl;
                std::cin.get();

                running.store(false);
            });
            wait_for_key.join();
        }
        sniffer.join();
        kafka_producer.join();
        std::cout << "Total packets sent: " << total_packets_sent.load() << std::endl;
    } catch (const std::exception &e) {
        std::cerr << "[ERROR] " << e.what() << std::endl;
        throw std::runtime_error(e.what());
        return;
    }
}

}  // namespace spoofy
