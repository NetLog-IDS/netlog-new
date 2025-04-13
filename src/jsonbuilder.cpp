#include "spoofy/jsonbuilder.h"

#include <tins/tins.h>

#include <algorithm>
#include <atomic>
#include <memory>

#include "spoofy/utils/uuid_v4.h"

namespace spoofy {

static std::atomic<uint32_t> packet_num_ = 0;

static UUIDv4::UUIDGenerator<std::mt19937_64> uuidGenerator = UUIDv4::UUIDGenerator<std::mt19937_64>();
static UUIDv4::UUID publisherId = uuidGenerator.getUUID();

// Context
JsonBuilder::JsonBuilder(std::unique_ptr<IJsonBuilder> builder) : builder_(std::move(builder)) {}
JsonBuilder::~JsonBuilder() = default;
void JsonBuilder::build_json() { builder_->build_json(); }  // might not work as expected
void JsonBuilder::set_builder(std::unique_ptr<IJsonBuilder> builder) { builder_ = std::move(builder); }

TinsJsonBuilder::TinsJsonBuilder(Tins::Packet* packet, std::unique_ptr<JsonWriter> writer)
    : packet_adapter_([&] {
          PacketAdapter res{0};

          res.orig_packet = packet;
          res.eth = packet->pdu()->find_pdu<Tins::EthernetII>();
          res.ip = packet->pdu()->find_pdu<Tins::IP>();
          res.ipv6 = packet->pdu()->find_pdu<Tins::IPv6>();
          res.tcp = packet->pdu()->find_pdu<Tins::TCP>();
          res.udp = packet->pdu()->find_pdu<Tins::UDP>();
          res.raw = packet->pdu()->find_pdu<Tins::RawPDU>();

          return res;
      }()),
      writer_(std::move(writer)) {}

void TinsJsonBuilder::build_json() {
    packet_num_++;

    writer_->StartObject();

    add_id_packet();
    add_timestamp();

    writer_->Key("publisher_id");
    writer_->String(publisherId.str().c_str());

    writer_->Key("order");
    writer_->Int(packet_num_);

    writer_->Key("sniff_time");
    writer_->String(std::to_string(std::chrono::duration_cast<std::chrono::microseconds>(
                                       std::chrono::system_clock::now().time_since_epoch())
                                       .count())
                        .c_str());

    writer_->Key("layers");
    writer_->StartObject();

    add_network();
    add_transport();

    // layers
    writer_->EndObject();

    // timestamp
    writer_->EndObject();
}

void TinsJsonBuilder::add_id_packet() {
    writer_->Key("id");

    UUIDv4::UUIDGenerator<std::mt19937_64> uuidGenerator;
    UUIDv4::UUID uuid = uuidGenerator.getUUID();

    writer_->String(uuid.str().c_str());
}

void TinsJsonBuilder::add_timestamp() {
    writer_->Key("timestamp");

    // get timestamp from tins pdu
    std::chrono::microseconds us = packet_adapter_.orig_packet->timestamp();

    // cast timestamp to c_str and pass it to rapidjson write function
    std::string micro = std::to_string(us.count());
    writer_->String(micro.c_str());
}

void TinsJsonBuilder::add_network() {
    if (packet_adapter_.ip) {
        writer_->Key("network");
        writer_->StartObject();

        writer_->Key("version");
        writer_->Uint(packet_adapter_.ip->version());

        writer_->Key("src");
        writer_->String(packet_adapter_.ip->src_addr().to_string().c_str());

        writer_->Key("dst");
        writer_->String(packet_adapter_.ip->dst_addr().to_string().c_str());

        writer_->EndObject();
    }
}

void TinsJsonBuilder::add_transport() {
    if (packet_adapter_.tcp) {
        writer_->Key("transport");
        writer_->StartObject();

        writer_->Key("type");
        writer_->String("tcp");

        writer_->Key("window");
        writer_->Uint(packet_adapter_.tcp->window());

        writer_->Key("src_port");
        writer_->Uint(packet_adapter_.tcp->sport());

        writer_->Key("dst_port");
        writer_->Uint(packet_adapter_.tcp->dport());

        writer_->Key("flags");
        writer_->Uint(packet_adapter_.tcp->flags());

        writer_->Key("header_length");
        writer_->Uint(packet_adapter_.tcp->header_size());

        if (packet_adapter_.raw) {
            writer_->Key("payload_length");
            writer_->Uint(packet_adapter_.tcp->inner_pdu()->size());
        } else {
            writer_->Key("payload_length");
            writer_->Uint(0);
        }

        writer_->Key("seq");
        writer_->Uint(packet_adapter_.tcp->seq());

        writer_->Key("ack");
        writer_->Uint(packet_adapter_.tcp->ack_seq());

        writer_->EndObject();
    }

    if (packet_adapter_.udp) {
        writer_->Key("transport");
        writer_->StartObject();

        writer_->Key("type");
        writer_->String("udp");

        writer_->Key("window");
        writer_->Uint(0);

        writer_->Key("src_port");
        writer_->Uint(packet_adapter_.udp->sport());

        writer_->Key("dst_port");
        writer_->Uint(packet_adapter_.udp->dport());

        writer_->Key("flags");
        writer_->Uint(0);

        uint32_t header_size = packet_adapter_.udp->header_size();
        writer_->Key("header_length");
        writer_->Uint(header_size);

        const Tins::RawPDU raw = packet_adapter_.udp->rfind_pdu<Tins::RawPDU>();
        const Tins::RawPDU::payload_type& payload = raw.payload();

        writer_->Key("payload_length");
        writer_->Uint(payload.size());

        writer_->Key("seq");
        writer_->Uint(0);

        writer_->Key("ack");
        writer_->Uint(0);

        writer_->EndObject();
    }
}

}  // namespace spoofy
