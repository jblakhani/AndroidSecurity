#include <fstream>
#include <string>

extern "C" int countAnonExecRegions() {
    std::ifstream maps("/proc/self/maps");
    if (!maps.is_open()) {
        return -1;
    }

    int count = 0;
    std::string line;
    while (std::getline(maps, line)) {
        if (line.find(" r-x") != std::string::npos &&
            (line.find("[anon") != std::string::npos || line.find("/dev/ashmem") != std::string::npos)) {
            count++;
        }
    }
    return count;
}
