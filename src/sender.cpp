#include "spoofy/sender.h"

#include <iostream>

#include "spoofy/jsonbuilder.h"

namespace spoofy {

// Context
Sender::Sender(std::unique_ptr<SendingStrategy> sender) : sender_(std::move(sender)) {}
Sender::~Sender() = default;
void Sender::send_packet(Tins::Packet &p) { sender_->send(p); }
void Sender::set_sender(std::unique_ptr<SendingStrategy> sending_strategy) { sender_ = std::move(sending_strategy); }

// Sending packets over the network
NetworkSender::NetworkSender(const char *interface)
    : interface_(interface), packet_sender_(std::move(Tins::PacketSender(interface_))) {}
void NetworkSender::send(Tins::Packet &pdu) { packet_sender_.send(*pdu.pdu()); }

void ExampleDeliveryReportCb::dr_cb(RdKafka::Message &message) {
    /* If message.err() is non-zero the message delivery failed permanently
     * for the message. */
    if (message.err())
        std::cerr << "% Message delivery failed: " << message.errstr() << std::endl;
    else
        std::cerr << "% Message delivered to topic " << message.topic_name() << " [" << message.partition()
                  << "] at offset " << message.offset() << std::endl;
}

KafkaSender::KafkaSender(const char *brokers, std::array<std::string, 2> topics) : brokers_(brokers), topics_(topics) {
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
        std::cerr << errstr << std::endl;
        exit(1);
    }

    // NOTE: are these needed?
    /* signal(SIGINT, sigterm);
    signal(SIGTERM, sigterm); */

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
    if (conf->set("dr_cb", &ex_dr_cb_, errstr) != RdKafka::Conf::CONF_OK) {
        std::cerr << errstr << std::endl;
        exit(1);
    }

    /*
     * Create producer instance.
     */
    producer1_ = RdKafka::Producer::create(conf, errstr);
    if (!producer1_) {
        std::cerr << "Failed to create producer: " << errstr << std::endl;
        exit(1);
    }
    /* producer2_ = RdKafka::Producer::create(conf, errstr);
    if (!producer2_) {
        std::cerr << "Failed to create producer: " << errstr << std::endl;
        exit(1);
    } */

    delete conf;
}

KafkaSender::~KafkaSender() {
    /* Wait for final messages to be delivered or fail.
     * flush() is an abstraction over poll() which
     * waits for all messages to be delivered.
     */
    std::cerr << "% Flushing final messages..." << std::endl;
    producer1_->flush(10 * 1000 /* wait for max 10 seconds */);
    // producer2_->flush(10 * 1000 /* wait for max 10 seconds */);

    int outq_len = producer1_->outq_len();
    if (outq_len > 0) {
        std::cerr << "% " << outq_len << " message(s) were not delivered" << std::endl;
    }

    /* int outq_len1 = producer2_->outq_len();
    if (outq_len1 > 0) {
        std::cerr << "% " << outq_len1 << " message(s) were not delivered" << std::endl;
    } */

    delete producer1_;
    //    delete producer2_;
}

// Sending packets to Apache Kafka
// i think this should send the json string
void KafkaSender::send(Tins::Packet &pdu) {
    std::string packet = jsonify(pdu);
    std::cout << packet << "\n";

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
retry:
    RdKafka::ErrorCode err = producer1_->produce(
        /* Topic name */
        topics_[0],
        /* Any Partition: the builtin partitioner will be
         * used to assign the message to a topic based
         * on the message key, or random partition if
         * the key is not set. */
        RdKafka::Topic::PARTITION_UA,
        /* Make a copy of the value */
        RdKafka::Producer::RK_MSG_COPY /* Copy payload */,
        /* Value */
        const_cast<char *>(packet.c_str()), packet.size(),
        /* Key */
        NULL, 0,
        /* Timestamp (defaults to current time) */
        0,
        /* Message headers, if any */
        NULL,
        /* Per-message opaque value passed to
         * delivery report */
        NULL);

    if (err != RdKafka::ERR_NO_ERROR) {
        std::cerr << "% Failed to produce to topic " << topics_[0] << ": " << RdKafka::err2str(err) << std::endl;

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
            producer1_->poll(1000 /*block for max 1000ms*/);
            goto retry;
        }
    } else {
        std::cerr << "% Enqueued message (" << packet.size() << " bytes) "
                  << "for topic " << topics_[0] << std::endl;
    }

    // retry2:
    //     RdKafka::ErrorCode err2 = producer2_->produce(
    //             /* Topic name */
    //             topics_[1],
    //             /* Any Partition: the builtin partitioner will be
    //          * used to assign the message to a topic based
    //          * on the message key, or random partition if
    //          * the key is not set. */
    //             RdKafka::Topic::PARTITION_UA,
    //             /* Make a copy of the value */
    //             RdKafka::Producer::RK_MSG_COPY /* Copy payload */,
    //             /* Value */
    //             const_cast<char *>(packet.c_str()), packet.size(),
    //             /* Key */
    //             NULL, 0,
    //             /* Timestamp (defaults to current time) */
    //             0,
    //             /* Message headers, if any */
    //             NULL,
    //             /* Per-message opaque value passed to
    //          * delivery report */
    //             NULL);
    //
    //     if (err2 != RdKafka::ERR_NO_ERROR) {
    //         std::cerr << "% Failed to produce to topic " << topics_[1] << ": "
    //             << RdKafka::err2str(err) << std::endl;
    //
    //         if (err2 == RdKafka::ERR__QUEUE_FULL) {
    //             /* If the internal queue is full, wait for
    //          * messages to be delivered and then retry.
    //          * The internal queue represents both
    //          * messages to be sent and messages that have
    //          * been sent or failed, awaiting their
    //          * delivery report callback to be called.
    //          *
    //          * The internal queue is limited by the
    //          * configuration property
    //          * queue.buffering.max.messages */
    //             producer2_->poll(1000 /*block for max 1000ms*/);
    //             goto retry2;
    //         }
    //
    //     } else {
    //         std::cerr << "% Enqueued message (" << packet.size() << " bytes) "
    //             << "for topic " << topics_[1] << std::endl;
    //     }

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
    producer1_->poll(0);
    // producer2_->poll(0);
}

std::string KafkaSender::jsonify(Tins::Packet &pdu) {
    //    return R"({ "glossary": { "title": "example glossary", "GlossDiv": { "title": "S", "GlossList": {
    //    "GlossEntry": { "ID": "SGML", "SortAs": "SGML", "GlossTerm": "Standard Generalized Markup Language",
    //    "Acronym": "SGML", "Abbrev": "ISO 8879:1986", "GlossDef": { "para": "A meta-markup language, used to create
    //    markup languages such as DocBook.", "GlossSeeAlso": ["GML", "XML"] }, "GlossSee": "markup" } } } } })";
    rapidjson::StringBuffer sb;
    JsonBuilder jb(std::make_unique<TinsJsonBuilder>(&pdu, std::make_unique<JsonWriter>(sb)));
    jb.build_json();

    return sb.GetString();
}

}  // namespace spoofy
