#include "spoofy/jsonbuilder.h"

#include <algorithm>
#include <memory>

namespace spoofy {

static uint32_t packet_num_;

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

    add_timestamp();

    writer_->Key("layers");
    writer_->StartObject();

    add_frame_metadata();
    add_datalink();
    add_network();

    // layers
    writer_->EndObject();

    // timestamp
    writer_->EndObject();
}

void TinsJsonBuilder::add_timestamp() {
    writer_->Key("timestamp");

    // get microsecond timestamp and convert it to ms
    // get timestamp from tins pdu
    std::chrono::microseconds us = packet_adapter_.orig_packet->timestamp();
    // us /= 1000  ;

    // cast timestamp to c_str and pass it to rapidjson write function
    std::string micro = std::to_string(us.count());
    writer_->String(micro.c_str());
}

void TinsJsonBuilder::add_frame_metadata() {
    writer_->Key("frame");
    writer_->StartObject();

    // get microsecond timestamp and convert it to ms
    // get timestamp from tins pdu
    std::chrono::microseconds us = packet_adapter_.orig_packet->timestamp();

    // cast timestamp to c_str and pass it to rapidjson write function
    std::string micro = std::to_string(us.count());
    writer_->Key("frame_frame_time");
    writer_->String(micro.c_str());

    // frame number
    writer_->Key("frame_frame_number");
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
            protocols += packet_adapter_.raw ? ":payload" : "";
        }

        if (packet_adapter_.udp) {
            protocols += ":udp";
            protocols += packet_adapter_.raw ? ":payload" : "";
        }
    }

    writer_->Key("frame_frame_length");
    writer_->Uint(frame_length);
    writer_->Key("frame_frame_protocols");
    writer_->String(protocols.c_str());

    writer_->EndObject();
}

void TinsJsonBuilder::add_datalink() {
    writer_->Key("eth");
    writer_->StartObject();

    writer_->Key("eth_eth_dst");
    writer_->String(packet_adapter_.eth->src_addr().to_string().c_str());

    writer_->Key("eth_eth_src");
    writer_->String(packet_adapter_.eth->dst_addr().to_string().c_str());

    writer_->Key("eth_eth_type");
    writer_->Uint(packet_adapter_.eth->payload_type());

    writer_->Key("eth_eth_header_size");
    writer_->Uint(packet_adapter_.eth->header_size());

    writer_->Key("eth_eth_trailer_size");
    writer_->Uint(packet_adapter_.eth->trailer_size());

    writer_->EndObject();
}

void TinsJsonBuilder::add_network() {
    // TODO: make API for adding network layer data
    if (packet_adapter_.ip) {
        // maybe we need to account for ipv6
        writer_->Key("ip");
        writer_->StartObject();

        writer_->Key("ip_ip_version");
        writer_->Uint(packet_adapter_.ip->version());
        writer_->Key("ip_ip_hdr_len");
        writer_->Uint(packet_adapter_.ip->head_len());
        writer_->Key("ip_ip_tos");
        writer_->Uint(packet_adapter_.ip->tos());
        writer_->Key("ip_ip_len");
        writer_->Uint(packet_adapter_.ip->tot_len());
        writer_->Key("ip_ip_id");
        writer_->Uint(packet_adapter_.ip->id());

        // flags here
        uint8_t flags = packet_adapter_.ip->flags();
        writer_->Key("ip_ip_flags");
        writer_->Uint(flags);

        // bit 0 is mf, bit 1 is df, bit 2 is rb
        writer_->Key("ip_ip_flags_rb");
        writer_->Uint((flags >> 2) & 1);
        writer_->Key("ip_ip_flags_df");
        writer_->Uint((flags >> 1) & 1);
        writer_->Key("ip_ip_flags_mf");
        writer_->Uint(flags & 1);

        writer_->Key("ip_ip_frag_offset");
        writer_->Uint(packet_adapter_.ip->fragment_offset());
        writer_->Key("ip_ip_ttl");
        writer_->Uint(packet_adapter_.ip->ttl());
        writer_->Key("ip_ip_proto");
        writer_->Uint(packet_adapter_.ip->protocol());
        writer_->Key("ip_ip_checksum");
        writer_->Uint(packet_adapter_.ip->checksum());
        writer_->Key("ip_ip_src");
        writer_->String(packet_adapter_.ip->src_addr().to_string().c_str());
        writer_->Key("ip_ip_dst");
        writer_->String(packet_adapter_.ip->dst_addr().to_string().c_str());

        writer_->EndObject();
    }

    if (packet_adapter_.ipv6) {
        // ipv6
        writer_->Key("ipv6");
        writer_->StartObject();

        writer_->Key("ipv6_ipv6_version");
        writer_->Uint(packet_adapter_.ipv6->version());
        writer_->Key("ipv6_ipv6_tclass");
        writer_->Uint(packet_adapter_.ipv6->traffic_class());
        writer_->Key("ipv6_ipv6_flow");
        writer_->Uint(packet_adapter_.ipv6->flow_label());
        writer_->Key("ipv6_ipv6_plen");
        writer_->Uint(packet_adapter_.ipv6->payload_length());
        writer_->Key("ipv6_ipv6_nxt");
        writer_->Uint(packet_adapter_.ipv6->next_header());
        writer_->Key("ipv6_ipv6_hlim");
        writer_->Uint(packet_adapter_.ipv6->hop_limit());
        writer_->Key("ipv6_ipv6_src");
        writer_->String(packet_adapter_.ipv6->src_addr().to_string().c_str());
        writer_->Key("ipv6_ipv6_dst");
        writer_->String(packet_adapter_.ipv6->dst_addr().to_string().c_str());

        writer_->EndObject();
    }
}

}  // namespace spoofy
