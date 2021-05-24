#include "tcpflow.h"

int main() {
    const char* device = std::getenv("DEVICE");
	const char* expression = std::getenv("EXPRESSION");
    const std::string device_str(device);
    const std::string expression_str(expression);

    tcpflow(device_str, expression_str);
}