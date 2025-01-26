#ifndef _QUEUE_H_
#define _QUEUE_H_

#include <condition_variable>
#include <mutex>
#include <queue>

namespace spoofy {

/**
 * @class ThreadSafeQueue
 * @brief Wrapper over std::queue, trying to be thread-safe.
 *
 * @note
 * Inspired by
 * https://www.justsoftwaresolutions.co.uk/threading/implementing-a-thread-safe-queue-using-condition-variables.html.
 * */
template <typename T>
class ThreadSafeQueue {
   public:
    void push(const T &element) {
        {
            std::scoped_lock lock(mutex_);
            queue_.push(element);
        }

        condition_var_.notify_one();
    }

    T pop() {
        std::unique_lock<std::mutex> lock(mutex_);

        if (queue_.empty()) {
            condition_var_.wait(lock);
        }

        T value = queue_.front();
        queue_.pop();

        return value;
    }

    bool empty() {
        std::scoped_lock lock(mutex_);
        return queue_.empty();
    }

    bool try_pop(T &element) {
        std::scoped_lock lock(mutex_);

        if (queue_.empty()) {
            return false;
        }

        element = queue_.front();
        queue_.pop();
        return true;
    }

   private:
    std::queue<T> queue_;
    std::mutex mutex_;
    std::condition_variable condition_var_;
};

}  // namespace spoofy

#endif  // _QUEUE_H_
