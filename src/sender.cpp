#include "spoofy/sender.h"

#include <rapidjson/document.h>

#include <fstream>
#include <iostream>
#include <sstream>
#include <thread>

#include "spoofy/jsonbuilder.h"

namespace {
constexpr const char *LINGER_MS = "120";                         // default: 0 ms
constexpr const char *BATCH_SIZE = "10000000";                   // default: 16384 byte
constexpr const char *QUEUE_BUFFERING_MAX_KBYTES = "1000000";    // default: 1048576 KB (1 GB)
constexpr const char *QUEUE_BUFFERING_MAX_MESSAGES = "1000000";  // default: 100000 msgs
constexpr const char *COMPRESSION_CODEC = "lz4";                 // default: none
constexpr const char *PARTITIONER = "consistent_random";         // default: consistent_random
constexpr const char *BATCH_NUM_MESSAGES = "100000";             // default: 10000
constexpr const char *STATISTICS_INTERVAL_MS = "1000";           // 1s
}  // namespace
namespace spoofy {

// Context
Sender::Sender(std::unique_ptr<SendingStrategy> sender) : sender_(std::move(sender)) {}
Sender::~Sender() = default;
void Sender::send_packet(std::string &flow_id, std::string &p) { sender_->send(flow_id, p); }
void Sender::set_sender(std::unique_ptr<SendingStrategy> sending_strategy) { sender_ = std::move(sending_strategy); }

void DeliveryReportCb::dr_cb(RdKafka::Message &message) {
    if (message.err()) std::cerr << "% Message delivery failed: " << message.errstr() << std::endl;
}

void StatsEventCb::event_cb(RdKafka::Event &event) {
    if (event.type() == RdKafka::Event::EVENT_STATS) {
        processStats(event.str());
    }
}

void StatsEventCb::processStats(const std::string &stats_str) {
    try {
        // std::cout << stats_str << std::endl;
        rapidjson::Document stats;
        stats.Parse(stats_str.c_str());

        // --- Get current timestamp ---
        auto now_time = std::chrono::system_clock::now();
        int64_t now_ms = std::chrono::duration_cast<std::chrono::milliseconds>(now_time.time_since_epoch()).count();

        if (start_timestamp_ms_ < 0) {
            start_timestamp_ms_ = now_ms;
            last_timestamp_ms_ = now_ms;
        }

        int64_t elapsed_ms = now_ms - start_timestamp_ms_;
        int64_t elapsed_sec = elapsed_ms / 1000;

        // --- Throughput ---
        int64_t current_txmsgs = stats["txmsgs"].GetInt64();

        int64_t msg_diff = current_txmsgs - last_txmsgs_;
        int64_t time_diff_ms = now_ms - last_timestamp_ms_;

        double msg_throughput = time_diff_ms > 0 ? (msg_diff * 1000.0) / time_diff_ms : 0.0;
        last_txmsgs_ = current_txmsgs;
        last_timestamp_ms_ = now_ms;

        // --- Latency ---
        double total_int_latency = 0.0;
        int64_t total_int_cnt = 0;

        const auto &brokers = stats["brokers"];
        for (auto itr = brokers.MemberBegin(); itr != brokers.MemberEnd(); ++itr) {
            const auto &broker = itr->value;

            auto &int_latency = broker["int_latency"];
            total_int_latency += int_latency["avg"].GetDouble() * int_latency["cnt"].GetInt64();
            total_int_cnt += int_latency["cnt"].GetInt64();
        }

        double avg_int_latency_ms = total_int_cnt > 0 ? total_int_latency / total_int_cnt : 0.0;

        // --- Write to CSV ---
        log_file_ << elapsed_sec << "," << msg_throughput << "," << avg_int_latency_ms << "\n";
        log_file_.flush();  // Ensure data is written immediately

    } catch (const std::exception &e) {
        std::cerr << "Failed to parse stats: " << e.what() << std::endl;
    }
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
    std::cout << "Kafka Configuration:" << std::endl;
    if (conf->set("bootstrap.servers", brokers_, errstr) != RdKafka::Conf::CONF_OK) {
        std::cerr << errstr << "\n";
        exit(1);
    } else {
        std::cout << "  bootstrap.servers: " << brokers_ << std::endl;
    }

    if (conf->set("linger.ms", LINGER_MS, errstr) != RdKafka::Conf::CONF_OK) {
        std::cerr << errstr << "\n";
        exit(1);
    } else {
        std::cout << "  linger.ms: " << LINGER_MS << std::endl;
    }

    if (conf->set("queue.buffering.max.ms", LINGER_MS, errstr) != RdKafka::Conf::CONF_OK) {
        std::cerr << errstr << "\n";
        exit(1);
    } else {
        std::cout << "  queue.buffering.max.ms: " << LINGER_MS << std::endl;
    }

    if (conf->set("batch.size", BATCH_SIZE, errstr) != RdKafka::Conf::CONF_OK) {
        std::cerr << errstr << "\n";
        exit(1);
    } else {
        std::cout << "  batch.size: " << BATCH_SIZE << std::endl;
    }

    if (conf->set("queue.buffering.max.kbytes", QUEUE_BUFFERING_MAX_KBYTES, errstr) != RdKafka::Conf::CONF_OK) {
        std::cerr << errstr << "\n";
        exit(1);
    } else {
        std::cout << "  queue.buffering.max.kbytes: " << QUEUE_BUFFERING_MAX_KBYTES << std::endl;
    }

    if (conf->set("queue.buffering.max.messages", QUEUE_BUFFERING_MAX_MESSAGES, errstr) != RdKafka::Conf::CONF_OK) {
        std::cerr << errstr << "\n";
        exit(1);
    } else {
        std::cout << "  queue.buffering.max.messages: " << QUEUE_BUFFERING_MAX_MESSAGES << std::endl;
    }

    if (conf->set("batch.num.messages", BATCH_NUM_MESSAGES, errstr) != RdKafka::Conf::CONF_OK) {
        std::cerr << errstr << "\n";
        exit(1);
    } else {
        std::cout << "  batch.num.messages: " << BATCH_NUM_MESSAGES << std::endl;
    }

    if (conf->set("compression.codec", COMPRESSION_CODEC, errstr) != RdKafka::Conf::CONF_OK) {
        std::cerr << errstr << "\n";
        exit(1);
    } else {
        std::cout << "  compression.codec: " << COMPRESSION_CODEC << std::endl;
    }

    if (conf->set("partitioner", PARTITIONER, errstr) != RdKafka::Conf::CONF_OK) {
        std::cerr << errstr << "\n";
        exit(1);
    } else {
        std::cout << "  partitioner: " << PARTITIONER << std::endl;
    }

    if (conf->set("statistics.interval.ms", STATISTICS_INTERVAL_MS, errstr) != RdKafka::Conf::CONF_OK) {
        std::cerr << errstr << "\n";
        exit(1);
    } else {
        std::cout << "  statistics.interval.ms: " << STATISTICS_INTERVAL_MS << std::endl << std::endl;
    }

    if (conf->set("event_cb", &stats_event_cb_, errstr) != RdKafka::Conf::CONF_OK) {
        std::cerr << errstr.c_str() << "\n";
        exit(1);
    } else {
        // Write CSV header
        stats_event_cb_.log_file_ << "timestamp,throughput,latency,linger.ms,batch.size,compression.codec," << LINGER_MS
                                  << "," << BATCH_SIZE << "," << COMPRESSION_CODEC << "\n";
    }

    if (conf->set("dr_cb", &dr_cb_, errstr) != RdKafka::Conf::CONF_OK) {
        std::cerr << errstr.c_str() << "\n";
        exit(1);
    }

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
            producer_->poll(100 /*block for max 1000ms*/);
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
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

}  // namespace spoofy
