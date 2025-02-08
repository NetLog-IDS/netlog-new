#include "spoofy/jsonbuilder.h"

#include <algorithm>
#include <memory>

#include "spoofy/utils/uuid_v4.h"

namespace spoofy {

static uint32_t packet_num_;

// Context
JsonBuilder::JsonBuilder(std::unique_ptr<IJsonBuilder> builder) : builder_(std::move(builder)) {}
JsonBuilder::~JsonBuilder() = default;
void JsonBuilder::build_json() { builder_->build_json(); }  // might not work as expected
void JsonBuilder::set_builder(std::unique_ptr<IJsonBuilder> builder) { builder_ = std::move(builder); }

TinsJsonBuilder::TinsJsonBuilder(Tins::Packet *packet, std::unique_ptr<JsonWriter> writer)
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

    writer_->Key("layers");
    writer_->StartObject();

    add_frame_metadata();
    add_datalink();
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

void TinsJsonBuilder::add_frame_metadata() {
    writer_->Key("frame");
    writer_->StartObject();

    // get timestamp from tins pdu
    std::chrono::microseconds us = packet_adapter_.orig_packet->timestamp();

    // cast timestamp to c_str and pass it to rapidjson write function
    std::string micro = std::to_string(us.count());
    writer_->Key("time");
    writer_->String(micro.c_str());

    // frame number
    writer_->Key("number");
    writer_->Uint(packet_num_);

    // frame length
    // frame protocols
    uint32_t frame_length = 0;
    std::string protocols = "";
    if (packet_adapter_.eth) {
        protocols += "eth";

        frame_length += packet_adapter_.eth->header_size() + packet_adapter_.eth->trailer_size();

        if (packet_adapter_.ip) {
            // calc len as above, u know where
            protocols += ":ip";
            frame_length += packet_adapter_.ip->tot_len();
        }

        if (packet_adapter_.ipv6) {
            protocols += ":ipv6";
            frame_length += 40 + packet_adapter_.ipv6->payload_length();
        }

        if (packet_adapter_.tcp) {
            protocols += ":tcp";
            frame_length += packet_adapter_.tcp->header_size();
        }

        if (packet_adapter_.udp) {
            protocols += ":udp";
            frame_length += packet_adapter_.udp->header_size();
        }
    }

    writer_->Key("length");
    writer_->Uint(frame_length);

    writer_->Key("protocols");
    writer_->String(protocols.c_str());

    writer_->EndObject();
}

void TinsJsonBuilder::add_datalink() {
    writer_->Key("data_link");
    writer_->StartObject();

    writer_->Key("dst");
    writer_->String(packet_adapter_.eth->src_addr().to_string().c_str());

    writer_->Key("src");
    writer_->String(packet_adapter_.eth->dst_addr().to_string().c_str());

    writer_->Key("type");
    writer_->Uint(packet_adapter_.eth->payload_type());

    writer_->Key("header_size");
    writer_->Uint(packet_adapter_.eth->header_size());

    writer_->Key("trailer_size");
    writer_->Uint(packet_adapter_.eth->trailer_size());

    writer_->EndObject();
}

void TinsJsonBuilder::add_network() {
    // TODO: make API for adding network layer data
    if (packet_adapter_.ip) {
        writer_->Key("network");
        writer_->StartObject();

        writer_->Key("version");
        writer_->Uint(packet_adapter_.ip->version());

        writer_->Key("hdr_len");
        writer_->Uint(packet_adapter_.ip->head_len());

        writer_->Key("tos");
        writer_->Uint(packet_adapter_.ip->tos());

        writer_->Key("len");
        writer_->Uint(packet_adapter_.ip->tot_len());

        writer_->Key("id");
        writer_->Uint(packet_adapter_.ip->id());

        // flags here
        uint8_t flags = packet_adapter_.ip->flags();
        writer_->Key("flags");
        writer_->Uint(flags);

        // bit 0 is mf, bit 1 is df, bit 2 is rb
        writer_->Key("flags_rb");
        writer_->Uint((flags >> 2) & 1);
        writer_->Key("flags_df");
        writer_->Uint((flags >> 1) & 1);
        writer_->Key("flags_mf");
        writer_->Uint(flags & 1);

        writer_->Key("frag_offset");
        writer_->Uint(packet_adapter_.ip->fragment_offset());

        writer_->Key("ttl");
        writer_->Uint(packet_adapter_.ip->ttl());

        writer_->Key("proto");
        writer_->Uint(packet_adapter_.ip->protocol());

        writer_->Key("checksum");
        writer_->Uint(packet_adapter_.ip->checksum());

        writer_->Key("src");
        writer_->String(packet_adapter_.ip->src_addr().to_string().c_str());

        writer_->Key("dst");
        writer_->String(packet_adapter_.ip->dst_addr().to_string().c_str());

        writer_->EndObject();
    }

    if (packet_adapter_.ipv6) {
        writer_->Key("network");
        writer_->StartObject();

        writer_->Key("version");
        writer_->Uint(packet_adapter_.ipv6->version());

        writer_->Key("tclass");
        writer_->Uint(packet_adapter_.ipv6->traffic_class());

        writer_->Key("flow");
        writer_->Uint(packet_adapter_.ipv6->flow_label());

        writer_->Key("plen");
        writer_->Uint(packet_adapter_.ipv6->payload_length());

        writer_->Key("nxt");
        writer_->Uint(packet_adapter_.ipv6->next_header());

        writer_->Key("hlim");
        writer_->Uint(packet_adapter_.ipv6->hop_limit());

        writer_->Key("src");
        writer_->String(packet_adapter_.ipv6->src_addr().to_string().c_str());

        writer_->Key("dst");
        writer_->String(packet_adapter_.ipv6->dst_addr().to_string().c_str());

        writer_->EndObject();
    }
}

void TinsJsonBuilder::add_transport() {
    if (packet_adapter_.tcp) {
        writer_->Key("transport");
        writer_->StartObject();

        writer_->Key("type");
        writer_->String("tcp");

        writer_->Key("src_port");
        writer_->Uint(packet_adapter_.tcp->sport());

        writer_->Key("dst_port");
        writer_->Uint(packet_adapter_.tcp->dport());

        writer_->Key("seq");
        writer_->Uint(packet_adapter_.tcp->seq());

        writer_->Key("ack");
        writer_->Uint(packet_adapter_.tcp->ack_seq());

        writer_->Key("dataofs");
        writer_->Uint(packet_adapter_.tcp->data_offset());

        writer_->Key("flags");
        writer_->Uint(packet_adapter_.tcp->flags());

        writer_->Key("window");
        writer_->Uint(packet_adapter_.tcp->window());

        writer_->Key("checksum");
        writer_->Uint(packet_adapter_.tcp->checksum());

        writer_->Key("header_length");
        writer_->Uint(packet_adapter_.tcp->header_size());

        if (packet_adapter_.raw) {
            writer_->Key("payload_length");
            writer_->Uint(packet_adapter_.tcp->inner_pdu()->size());
        } else {
            writer_->Key("payload_length");
            writer_->Uint(0);
        }

        writer_->EndObject();
    }

    if (packet_adapter_.udp) {
        writer_->Key("transport");
        writer_->StartObject();

        writer_->Key("type");
        writer_->String("udp");

        writer_->Key("src_port");
        writer_->Uint(packet_adapter_.udp->sport());

        writer_->Key("dst_port");
        writer_->Uint(packet_adapter_.udp->dport());

        uint32_t header_size = packet_adapter_.udp->header_size();
        writer_->Key("header_length");
        writer_->Uint(header_size);

        writer_->Key("payload_length");
        writer_->Uint(packet_adapter_.udp->length() - header_size);

        writer_->Key("checksum");
        writer_->Uint(packet_adapter_.udp->checksum());

        writer_->EndObject();
    }
}

}  // namespace spoofy
