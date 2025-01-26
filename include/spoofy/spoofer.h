#ifndef _SPOOFER_H_
#define _SPOOFER_H_

#include <iterator>
#include <memory>
#include <vector>

#include "spoofy/utils/rand.h"

namespace spoofy {

class SpoofingStrategy {
   public:
    virtual ~SpoofingStrategy() {}
    virtual void spoof() = 0;
};

class Spoofer {
   public:
    Spoofer(std::unique_ptr<SpoofingStrategy> spoofer);
    ~Spoofer();

    void spoof();

    void set_spoofer(std::unique_ptr<SpoofingStrategy> ss);

   private:
    std::unique_ptr<SpoofingStrategy> spoofer_;
};

// Base class for a spoofer that adds delay to the packet
class DelaySpoofer : public SpoofingStrategy {
   public:
    DelaySpoofer(std::vector<std::string_view> delays);

   protected:
    std::vector<uint32_t> delays_;
};

// Follows the list of delays incrementally, starting from the smallest delay first
class IncrementalDelaySpoofer : public DelaySpoofer {
   public:
    IncrementalDelaySpoofer(std::vector<std::string_view> delays);
    virtual void spoof();

   private:
    size_t it_;
};

// Follows the list of delays decrementally, starting from the highest delay first
class DecrementalDelaySpoofer : public DelaySpoofer {
   public:
    DecrementalDelaySpoofer(std::vector<std::string_view> delays);
    virtual void spoof();

   private:
    size_t it_;
};

// Randomly picks from the list of delays
class RandomDelaySpoofer : public DelaySpoofer {
   public:
    RandomDelaySpoofer(std::vector<std::string_view> delays);
    virtual void spoof();

   private:
    std::unique_ptr<RandomNumberGenerator> rng_;
};

}  // namespace spoofy

#endif  // _SPOOFER_H_
