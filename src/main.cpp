#include <iostream>
#include <stdexcept>

#include "spoofy/app.h"

int main(int argc, char* argv[]) {
    try {
        spoofy::Application app(argc, argv);
        app.start();
    } catch (const std::exception& e) {
        std::cerr << e.what() << std::endl;
        std::cerr << "Usage: ./spoofy -i <iface | file> [-f filter] [-l | --live]\n";
        return -1;
    }
}
