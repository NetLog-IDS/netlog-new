#ifndef _APP_H_
#define _APP_H_
#include <cclap/cclap.h>
#include <tins/tins.h>

#include <memory>
#include <string_view>

#include "spoofy/utils/queue.h"

namespace spoofy {

struct ApplicationContext;

/**
 * @class Application
 * @brief Manages application data and initiates program execution.
 * */
class Application {
   public:
    Application(int argc, char *argv[]);
    ~Application();

    Application() = delete;
    Application(const Application &) = delete;
    Application(Application &&) = delete;
    void operator=(const Application &) = delete;
    void operator=(Application &&) = delete;

    void setup();
    void start();
    void start_live();

   private:
    std::unique_ptr<ApplicationContext> ctx_;
};

}  // namespace spoofy

#endif  // _APP_H_
