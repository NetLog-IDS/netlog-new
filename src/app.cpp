#include "spoofy/app.h"

#include <atomic>
#include <iostream>
#include <memory>
#include <optional>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

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
        std::optional<std::array<std::string, 2>> topics;
        std::optional<std::string> network_sending_interface;
    } args;

    ThreadSafeQueue<Tins::Packet> packetq;
    std::vector<Tins::Packet> edited_packets;
};

// send the network packet with the designated sender, depending on provided cmdline arguments
static void send_packet(ApplicationContext *ctx, Tins::Packet &pkt) {
    Sender s;
    if (ctx->args.broker) {
        s.set_sender(std::make_unique<KafkaSender>(ctx->args.broker.value().c_str(), ctx->args.topics.value()));
    } else {
        if (ctx->args.network_sending_interface) {
            s.set_sender(std::make_unique<NetworkSender>(ctx->args.network_sending_interface.value().c_str()));
        } else {
            s.set_sender(std::make_unique<NetworkSender>(""));
        }
    }
    s.send_packet(pkt);
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
    ctx_->args.topics = std::invoke([this]() -> std::optional<std::array<std::string, 2>> {
        if (!ctx_->args.broker) {
            return std::nullopt;
        }

        const auto &topic_found = ctx_->arg_parser.find_flag("topic");
        if (!topic_found) {
            throw std::runtime_error("[ERROR - CLI args] Kafka topic not specified");
        }
        std::optional<std::array<std::string, 2>> res = std::make_optional<std::array<std::string, 2>>();
        res.value()[0] = topic_found.value()[0];
        res.value()[1] = topic_found.value()[1];
        return res;
    });
    std::cout << "found topics" << ctx_->args.topics.value()[0] << ctx_->args.topics.value()[1];
}

/**
 * @brief Contains the high-level application logic.
 * */
void Application::start() {
    std::atomic_bool running(true);

    try {
        // Start capturing packets and store them in a queue
        std::thread sniffer([this, &running]() {
            PacketSniffer ps(ctx_->args.sniffer_type, ctx_->args.interface_name.data(),
                             ctx_->args.capture_filter.data());
            // PacketSniffer ps(st, iface.data(), filter.data());
            ps.run(ctx_->packetq, running);
            running.store(false);  // stop running after sniffing all packets
        });

        // Consume the packets stored in the queue and send them to Apache Kafka
        std::thread kafka_producer([this, &running]() {
            while (running || !ctx_->packetq.empty()) {
                if (!ctx_->packetq.empty()) {
                    Tins::Packet pkt(ctx_->packetq.pop());
                    ctx_->edited_packets.push_back(pkt);  // push them into a container just in case

                    send_packet(ctx_.get(), pkt);
                }
            }
        });

        if (ctx_->args.sniffer_type == SnifferType::Sniffer) {
            // Listen for user input to stop live capture
            std::cout << "[INFO] Live capture started on interface: " << ctx_->args.interface_name << std::endl;
            std::thread wait_for_key([&running]() {
                std::cout << "Press key to stop capture";
                std::cin.get();

                running.store(false);
            });
            wait_for_key.join();
        }
        sniffer.join();
        kafka_producer.join();
    } catch (const std::exception &e) {
        throw std::runtime_error(e.what());
        return;
    }

    if (ctx_->args.sniffer_type == SnifferType::FileSniffer) {
        std::cout << "[INFO] Read packets from capture file: " << ctx_->args.interface_name << std::endl;
    }

    std::cout << "[INFO] Work is done! Processed " << ctx_->edited_packets.size() << " packets.\n"
              << "Press any key to exit...\n";
    std::cin.get();
}

}  // namespace spoofy
