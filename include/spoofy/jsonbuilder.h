#include <rapidjson/writer.h>
#include <tins/tins.h>

#include <string>

namespace spoofy {

using JsonWriter = rapidjson::Writer<rapidjson::StringBuffer>;

class IJsonBuilder {
   public:
    virtual ~IJsonBuilder() {}
    virtual void build_json() = 0;  // this can be void, as the data will be stored in the rapidjson string buffer
};

/**
 * @brief Context for sending and receiving packets with different strategies
 */
class JsonBuilder {
   public:
    JsonBuilder(std::unique_ptr<IJsonBuilder> builder = nullptr);
    ~JsonBuilder();

    void build_json();

    void set_builder(std::unique_ptr<IJsonBuilder> builder);

   private:
    std::unique_ptr<IJsonBuilder> builder_;
};

// Build Json string from Tins::PDU
class TinsJsonBuilder : public IJsonBuilder {
   public:
    TinsJsonBuilder(Tins::Packet *pdu, std::unique_ptr<JsonWriter> writer);

    TinsJsonBuilder() = delete;
    TinsJsonBuilder(const TinsJsonBuilder &) = delete;
    TinsJsonBuilder &operator=(const TinsJsonBuilder &) = delete;

    void build_json();

   private:
    const struct PacketAdapter {
        const Tins::Packet *orig_packet;
        const Tins::EthernetII *eth;
        const Tins::IP *ip;
        const Tins::IPv6 *ipv6;
        const Tins::TCP *tcp;
        const Tins::UDP *udp;
        const Tins::RawPDU *raw;
    } packet_adapter_;
    std::unique_ptr<JsonWriter> writer_;

    void add_id_packet();
    void add_timestamp();
    void add_frame_metadata();
    void add_datalink();
    void add_network();
    void add_transport();
};

}  // namespace spoofy
