#include "spoofy/sender.h"

#include <rapidjson/document.h>

#include <iostream>

#include "spoofy/jsonbuilder.h"

namespace spoofy {

// Context
Sender::Sender(std::unique_ptr<SendingStrategy> sender) : sender_(std::move(sender)) {}
Sender::~Sender() = default;
void Sender::send_packet(std::string &flow_id, std::string &p) { sender_->send(flow_id, p); }
void Sender::set_sender(std::unique_ptr<SendingStrategy> sending_strategy) { sender_ = std::move(sending_strategy); }

// Sending packets over the network
// NetworkSender::NetworkSender(const char *interface)
//     : interface_(interface), packet_sender_(std::move(Tins::PacketSender(interface_))) {}
// void NetworkSender::send(Tins::Packet &pdu) { packet_sender_.send(*pdu.pdu()); }

void ExampleDeliveryReportCb::dr_cb(RdKafka::Message &message) {
    /* If message.err() is non-zero the message delivery failed permanently
     * for the message. */
    // if (message.err())
    //     std::cerr << "% Message delivery failed: " << message.errstr() << std::endl;
    // else
    //     std::cerr << "% Message delivered to topic " << message.topic_name() << " [" << message.partition()
    //               << "] at offset " << message.offset() << std::endl;
}

KafkaSender::KafkaSender(const char *brokers, std::string topic) : brokers_(brokers), topic_(topic) {
    /*
     * Create configuration object
     */
    RdKafka::Conf *conf = RdKafka::Conf::create(RdKafka::Conf::CONF_GLOBAL);

    std::string errstr;

    /* Set bootstrap broker(s) as a comma-separated list of
     * host or host:port (default port 9092).
     * librdkafka will use the bootstrap brokers to acquire the full
     * set of brokers from the cluster. */
    if (conf->set("bootstrap.servers", brokers_, errstr) != RdKafka::Conf::CONF_OK) {
        std::cerr << errstr << "\n";
        exit(1);
    }

    if (conf->set("partitioner", "murmur2", errstr) != RdKafka::Conf::CONF_OK) {
        std::cerr << errstr << std::endl;
        exit(1);
    }

    // if (conf->set("queue.buffering.max.messages", "100000", errstr) != RdKafka::Conf::CONF_OK) {
    //    std::cerr << errstr << std::endl;
    //    exit(1);
    // }

    // // Message count per batch for efficiency
    // if (conf->set("batch.num.messages", "10000", errstr) != RdKafka::Conf::CONF_OK) {
    //     std::cerr << errstr << std::endl;
    //     exit(1);
    // }

    // // Time to wait before sending a batch (milliseconds)
    // if (conf->set("linger.ms", "1000", errstr) != RdKafka::Conf::CONF_OK) {
    //     std::cerr << errstr << std::endl;
    //     exit(1);
    // }

    // // Compression can improve throughput
    // if (conf->set("compression.codec", "snappy", errstr) != RdKafka::Conf::CONF_OK) {
    //     std::cerr << errstr << std::endl;
    //     exit(1);
    // }

    // // Delivery report callback (reduce frequency)
    // if (conf->set("delivery.report.only.error", "true", errstr) != RdKafka::Conf::CONF_OK) {
    //     std::cerr << errstr << std::endl;
    //     exit(1);
    // }

    // // Socket buffer sizes
    // if (conf->set("socket.send.buffer.bytes", "1048576", errstr) != RdKafka::Conf::CONF_OK) {
    //     std::cerr << errstr << std::endl;
    //     exit(1);
    // }

    // Configuration Print
    std::cout << "Kafka Configuration:" << std::endl;
    std::cout << "  bootstrap.servers: " << brokers_ << std::endl;
    std::cout << "  queue.buffering.max.messages: 100000" << std::endl;
    std::cout << "  batch.num.messages: 10000" << std::endl;
    std::cout << "  linger.ms: 1000" << std::endl;
    std::cout << "  compression.codec: snappy" << std::endl;
    std::cout << "  socket.send.buffer.bytes: 1048576" << std::endl;
    std::cout << "  delivery.report.only.error: true" << std::endl << '\n';

    /* Set the delivery report callback.
     * This callback will be called once per message to inform
     * the application if delivery succeeded or failed.
     * See dr_msg_cb() above.
     * The callback is only triggered from ::poll() and ::flush().
     *
     * IMPORTANT:
     * Make sure the DeliveryReport instance outlives the Producer object,
     * either by putting it on the heap or as in this case as a stack variable
     * that will NOT go out of scope for the duration of the Producer object.
     */
    // if (conf->set("dr_cb", &ex_dr_cb_, errstr) != RdKafka::Conf::CONF_OK) {
    //     std::cerr << errstr << "\n";
    //     exit(1);
    // }

    /*
     * Create producer instance.
     */
    producer_ = RdKafka::Producer::create(conf, errstr);
    if (!producer_) {
        std::cerr << "Failed to create producer: " << errstr << "\n";
        exit(1);
    }

    delete conf;
}

KafkaSender::~KafkaSender() {
    /* Wait for final messages to be delivered or fail.
     * flush() is an abstraction over poll() which
     * waits for all messages to be delivered.
     */
    // std::cerr << "% Flushing final messages..." << "\n";
    producer_->flush(10 * 1000 /* wait for max 10 seconds */);

    int outq_len = producer_->outq_len();
    if (outq_len > 0) {
        std::cerr << "% " << outq_len << " message(s) were not delivered" << "\n";
    }

    delete producer_;
}

void KafkaSender::send(std::string &flow_id, std::string &packet) {
    // std::string packet = jsonify(pdu);
    // std::cout << packet << ",\n";

    /*
     * Send/Produce message.
     * This is an asynchronous call, on success it will only
     * enqueue the message on the internal producer queue.
     * The actual delivery attempts to the broker are handled
     * by background threads.
     * The previously registered delivery report callback
     * is used to signal back to the application when the message
     * has been delivered (or failed permanently after retries).
     */

    // rapidjson::Document document;
    // document.Parse(packet.c_str());

    // std::string flow_id = std::string(document["layers"]["network"]["src"].GetString()) + "-" +
    //                       document["layers"]["network"]["dst"].GetString() + "-" +
    //                       std::to_string(document["layers"]["transport"]["src_port"].GetInt()) + "-" +
    //                       std::to_string(document["layers"]["transport"]["dst_port"].GetInt()) + "-" +
    //                       document["layers"]["frame"]["protocols"].GetString();

retry:
    RdKafka::ErrorCode err = producer_->produce(topic_, /* Topic name */
                                                /* Any Partition: the builtin partitioner will be
                                                 * used to assign the message to a topic based
                                                 * on the message keandom partition y, or rif
                                                 * the key is not set. */
                                                RdKafka::Topic::PARTITION_UA,        /* Make a copy of the value */
                                                RdKafka::Producer::RK_MSG_COPY,      /* Copy payload */
                                                const_cast<char *>(packet.c_str()),  // Value
                                                packet.size(),                       // len
                                                flow_id.c_str(),                     /* Key */
                                                flow_id.size(),                      /* key_len */
                                                0,    /* Timestamp (defaults to current time) */
                                                NULL, /* Message headers, if any */
                                                NULL  /* Per-message opaque value passed to delivery report */
    );

    if (err != RdKafka::ERR_NO_ERROR) {
        std::cerr << "% Failed to produce to topic " << topic_ << ": " << RdKafka::err2str(err) << "\n";

        if (err == RdKafka::ERR__QUEUE_FULL) {
            /* If the internal queue is full, wait for
             * messages to be delivered and then retry.
             * The internal queue represents both
             * messages to be sent and messages that have
             * been sent or failed, awaiting their
             * delivery report callback to be called.
             *
             * The internal queue is limited by the
             * configuration property
             * queue.buffering.max.messages */
            producer_->poll(1000 /*block for max 1000ms*/);
            goto retry;
        }
    }

    /* A producer application should continually serve
     * the delivery report queue by calling poll()
     * at frequent intervals.
     * Either put the poll call in your main loop, or in a
     * dedicated thread, or call it after every produce() call.
     * Just make sure that poll() is still called
     * during periods where you are not producing any messages
     * to make sure previously produced messages have their
     * delivery report callback served (and any other callbacks
     * you register). */
    producer_->poll(0);
}

// std::string KafkaSender::jsonify(Tins::Packet &pdu) {
//     rapidjson::StringBuffer sb;
//     JsonBuilder jb(std::make_unique<TinsJsonBuilder>(&pdu, std::make_unique<JsonWriter>(sb)));
//     jb.build_json();

//     return sb.GetString();
// }

}  // namespace spoofy
