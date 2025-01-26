#ifndef _RAND_H_
#define _RAND_H_

#include <random>

namespace spoofy {

class RandomNumberGenerator {
   public:
    RandomNumberGenerator(size_t min, size_t max);
    size_t next_rand();

   private:
    std::mt19937 generator_;
    std::uniform_int_distribution<size_t> distribution_;
};

}  // namespace spoofy

#endif  // _RAND_H_
