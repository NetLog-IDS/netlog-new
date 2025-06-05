#include <iostream>
#include <stdexcept>
#include <thread>
#include <vector>

#include "spoofy/app.h"

int main(int argc, char* argv[]) {
    std::ios::sync_with_stdio(false);

    try {
        bool is_live = false;
        for (int i = 1; i < argc; ++i) {
            std::string arg = argv[i];
            if (arg == "--live") {
                is_live = true;
            }
        }

        auto start = std::chrono::high_resolution_clock::now();
        spoofy::Application app(argc, argv);
        std::cout << "[INFO] Starting application...\n" << std::endl;
        if (is_live) {
            app.start_live();
        } else {
            app.start();
        }

        auto end = std::chrono::high_resolution_clock::now();
        std::chrono::duration<double, std::milli> elapsed = end - start;
        std::cout << "Total Elapsed time: " << elapsed.count() << " ms" << std::endl;
    } catch (const std::exception& e) {
        std::cerr << e.what() << std::endl;
        std::cerr << "Usage: ./spoofy -i <iface | file> [-f filter] [-l | --live]\n";
        return -1;
    }
}
