#include "spoofy/spoofer.h"

#include <charconv>
#include <string_view>
#include <thread>

namespace spoofy {

DelaySpoofer::DelaySpoofer(std::vector<std::string_view> delays) {
    for (std::string_view delay : delays) {
        uint32_t d{};
        auto [ptr, ec]{std::from_chars(delay.data(), delay.data() + delay.size(), d)};
        if (ec == std::errc()) {
            delays_.push_back(d);
        } else if (ec == std::errc::invalid_argument) {
            throw std::runtime_error("[ERROR] Delay value is not a number.");
        } else if (ec == std::errc::result_out_of_range) {
            throw std::runtime_error("[ERROR] Delay value is out of range.");
        }
    }
}

IncrementalDelaySpoofer::IncrementalDelaySpoofer(std::vector<std::string_view> delays) : DelaySpoofer(delays), it_(0) {}
void IncrementalDelaySpoofer::spoof() {
    if (it_ == delays_.size()) {
        std::this_thread::sleep_for(std::chrono::milliseconds(delays_[it_]));
        it_ = 0;
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(delays_[it_++]));
}

DecrementalDelaySpoofer::DecrementalDelaySpoofer(std::vector<std::string_view> delays)
    : DelaySpoofer(delays), it_(delays_.size()) {}
void DecrementalDelaySpoofer::spoof() {
    if (it_ == 0) {
        std::this_thread::sleep_for(std::chrono::milliseconds(delays_[it_]));
        it_ = delays_.size();
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(delays_[it_--]));
}

RandomDelaySpoofer::RandomDelaySpoofer(std::vector<std::string_view> delays)
    : DelaySpoofer(delays), rng_(std::make_unique<RandomNumberGenerator>(0, delays_.size())) {}
void RandomDelaySpoofer::spoof() { std::this_thread::sleep_for(std::chrono::milliseconds(rng_->next_rand())); }

}  // namespace spoofy
