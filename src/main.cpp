#include <iostream>
#include <stdexcept>

#include "spoofy/app.h"

int main(int argc, char* argv[]) {
    std::ios::sync_with_stdio(false);

    try {
        spoofy::Application app(argc, argv);
        auto start = std::chrono::high_resolution_clock::now();
        std::cout << "[INFO] Starting application...\n" << std::endl;
        app.start();
        auto end = std::chrono::high_resolution_clock::now();
        std::chrono::duration<double, std::milli> elapsed = end - start;
        std::cout << "Total Elapsed time: " << elapsed.count() << " ms" << std::endl;
    } catch (const std::exception& e) {
        std::cerr << e.what() << std::endl;
        std::cerr << "Usage: ./spoofy -i <iface | file> [-f filter] [-l | --live]\n";
        return -1;
    }
}
