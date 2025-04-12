#include "spoofy/app.h"

#include <rapidjson/document.h>

#include <atomic>
#include <csignal>
#include <iostream>
#include <memory>
#include <optional>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

#include "spoofy/jsonbuilder.h"
#include "spoofy/sender.h"
#include "spoofy/sniffer.h"
#include "spoofy/utils/rand.h"

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
    } args;

    ThreadSafeQueue<Tins::Packet> raw_packetq;
    ThreadSafeQueue<std::pair<std::string, std::string>> packetq;
    std::vector<Tins::Packet> edited_packets;
};

// send the network packet with the designated sender, depending on provided cmdline arguments
static void send_packet(ApplicationContext *ctx, std::pair<std::string, std::string> &pkt) {
    Sender s;
    if (ctx->args.broker) {
        s.set_sender(std::make_unique<KafkaSender>(ctx->args.broker.value().c_str(), ctx->args.topic.value()));
    }
    //  else {
    //     if (ctx->args.network_sending_interface) {
    //         s.set_sender(std::make_unique<NetworkSender>(ctx->args.network_sending_interface.value().c_str()));
    //     } else {
    //         s.set_sender(std::make_unique<NetworkSender>(""));
    //     }
    // }
    s.send_packet(pkt.first, pkt.second);
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

    std::cout << "Sniffer Type: " << (ctx_->args.sniffer_type == SnifferType::Sniffer ? "Live" : "File") << std::endl;
    std::cout << "Capture Filter: " << ctx_->args.capture_filter << std::endl;
    std::cout << "Interface Name: " << ctx_->args.interface_name << std::endl;
    std::cout << "Sender: " << senderfound.value()[0] << std::endl;
    if (ctx_->args.broker) {
        std::cout << "Kafka Broker: " << ctx_->args.broker.value() << std::endl;
        std::cout << "Kafka Topic: " << ctx_->args.topic.value() << std::endl;
    }
}

std::atomic_bool running(true);  // Global flag for stopping all threads

void signalHandler(int signal) {
    std::cout << "\n[INFO] Caught signal " << signal << ", stopping capture..." << std::endl;
    running.store(false);
}

/**
 * @brief Contains the high-level application logic.
 * */
void Application::start() {
    // Register signal handlers for SIGINT (Ctrl+C) and SIGTERM
    std::signal(SIGINT, signalHandler);
    std::signal(SIGTERM, signalHandler);

    try {
        // Start capturing packets and store them in a queue
        std::thread sniffer([this]() {
            PacketSniffer ps(ctx_->args.sniffer_type, ctx_->args.interface_name.data(),
                             ctx_->args.capture_filter.data());
            auto start_time = std::chrono::high_resolution_clock::now();

            ps.run(ctx_->raw_packetq, running);  // Capturing packets

            while (!ctx_->raw_packetq.empty()) {
                auto pkt = ctx_->raw_packetq.pop();
                std::string pkt_str = jsonify(pkt);

                rapidjson::Document document;
                document.Parse(pkt_str.c_str());

                std::string form_id = std::string(document["layers"]["network"]["src"].GetString()) + "-" +
                                      document["layers"]["network"]["dst"].GetString() + "-" +
                                      std::to_string(document["layers"]["transport"]["src_port"].GetInt()) + "-" +
                                      std::to_string(document["layers"]["transport"]["dst_port"].GetInt()) + "-" +
                                      document["layers"]["transport"]["type"].GetString();

                ctx_->packetq.push({form_id, pkt_str});  // Pre-serialize here
            }

            auto end_time = std::chrono::high_resolution_clock::now();
            std::chrono::duration<double, std::milli> duration = end_time - start_time;

            running.store(false);  // stop running after sniffing all packets
            std::cout << "[INFO] Stopping capture..." << std::endl;
            std::cout << "[Sniffer] Packet captured and serialized to JSON in " << duration.count() << " ms"
                      << std::endl;
        });

        // Create multiple Kafka producer threads
        const int num_producers = std::thread::hardware_concurrency();  // Adjust as needed
        std::cout << "[INFO] Creating " << num_producers << " producer threads..." << std::endl;
        std::vector<std::thread> producers;

        for (int i = 0; i < num_producers; ++i) {
            producers.emplace_back([this]() {
                while (running.load() || !ctx_->packetq.empty()) {
                    std::pair<std::string, std::string> pkt;
                    if (ctx_->packetq.try_pop(pkt)) {
                        send_packet(ctx_.get(), pkt);
                    } else {
                        // Check exit condition if pop fails (queue empty)
                        if (!running.load() && ctx_->packetq.empty()) {
                            break;
                        }
                    }
                }
            });
        }

        // Consume the packets stored in the queue and send them to Apache Kafka
        // std::vector<Tins::Packet> buffer;
        // const size_t BATCH_SIZE = 50;  // Adjust batch size based on throughput needs
        // const int MAX_WAIT_TIME = 10;  // Milliseconds

        // std::thread kafka_producer([this, &buffer]() {
        //     auto last_flush = std::chrono::steady_clock::now();

        //     while (running.load() || !ctx_->packetq.empty()) {
        //         if (!ctx_->packetq.empty()) {
        //             buffer.push_back(ctx_->packetq.pop());  // Collect packets in buffer
        //         }

        //         auto now = std::chrono::steady_clock::now();
        //         auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(now - last_flush).count();

        //         if (buffer.size() >= BATCH_SIZE || elapsed >= MAX_WAIT_TIME) {
        //             for (auto &pkt : buffer) {
        //                 send_packet(ctx_.get(), pkt);  // Send all at once
        //             }
        //             buffer.clear();
        //             last_flush = std::chrono::steady_clock::now();
        //         }
        //     }
        // });

        // std::thread kafka_producer([this]() {
        //     // while (running.load() || !ctx_->packetq.empty()) {
        //     //     if (!ctx_->packetq.empty()) {
        //     //         auto dequeue_start = std::chrono::high_resolution_clock::now();

        //     //         Tins::Packet pkt(ctx_->packetq.pop());  // Fetch packet
        //     //         ctx_->edited_packets.push_back(pkt);

        //     //         auto process_start = std::chrono::high_resolution_clock::now();
        //     //         send_packet(ctx_.get(), pkt);  // Send to Kafka
        //     //         auto process_end = std::chrono::high_resolution_clock::now();

        //     //         std::chrono::duration<double, std::milli> dequeue_duration = process_start - dequeue_start;
        //     //         std::chrono::duration<double, std::milli> send_duration = process_end - process_start;

        //     //         // std::cout << "[Kafka Producer] Packet dequeued in " << dequeue_duration.count() << " ms,
        //     sent
        //     //         in
        //     //         // "
        //     //         //           << send_duration.count() << " ms" << std::endl;
        //     //     }
        //     // }
        //     while (running.load() || !ctx_->packetq.empty()) {
        //         std::pair<std::string, std::string> pkt;
        //         if (ctx_->packetq.try_pop(pkt)) {
        //             send_packet(ctx_.get(), pkt);
        //         } else {
        //             // Check exit condition if pop fails (queue empty)
        //             if (!running.load() && ctx_->packetq.empty()) {
        //                 break;
        //             }
        //         }
        //         // if (!ctx_->packetq.empty()) {
        //         //     Tins::Packet pkt(ctx_->packetq.pop());
        //         //     send_packet(ctx_.get(), pkt);
        //         // }
        //     }
        // });

        sniffer.join();
        for (auto &producer : producers) {
            producer.join();
        }
        // kafka_producer.join();
    } catch (const std::exception &e) {
        std::cerr << "[ERROR] " << e.what() << std::endl;
        throw std::runtime_error(e.what());
        return;
    }

    if (ctx_->args.sniffer_type == SnifferType::FileSniffer) {
        std::cout << "[INFO] Read packets from capture file: " << ctx_->args.interface_name << std::endl;
    }

    // std::cout << "[INFO] Work is done! Processed " << ctx_->edited_packets.size() << " packets" << std::endl;
}

std::string Application::jsonify(Tins::Packet &pdu) {
    rapidjson::StringBuffer sb;
    JsonBuilder jb(std::make_unique<TinsJsonBuilder>(&pdu, std::make_unique<JsonWriter>(sb)));
    jb.build_json();

    return sb.GetString();
}

}  // namespace spoofy
