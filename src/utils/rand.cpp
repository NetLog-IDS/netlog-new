#include "spoofy/utils/rand.h"

namespace spoofy {

RandomNumberGenerator::RandomNumberGenerator(size_t min, size_t max)
    : generator_(std::random_device{}()), distribution_(min, max) {}

size_t RandomNumberGenerator::next_rand() { return distribution_(generator_); }

}  // namespace spoofy
