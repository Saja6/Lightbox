#include <iostream>
#include "Malware.h"
int main(int argc, const char * argv[]) {
    MW::Malware m;
    try {
        m.attack();
    } catch (const std::exception& e) {
        std::cerr << e.what() << std::endl;
    }
    printf("Attack finished.\n");
    return 0;
}
