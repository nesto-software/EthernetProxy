#include "tcpflow.h"
#include "greengrasssdk.h"

void handler(const gg_lambda_context *cxt) {
    (void)cxt;
    return;
}

int main() {
    gg_error err = GGE_SUCCESS;

    err = gg_global_init(0);
    if(err) {
        gg_log(GG_LOG_ERROR, "gg_global_init failed %d", err);
        return -1;
    }

    gg_runtime_start(handler, GG_RT_OPT_ASYNC);

	const char* device = std::getenv("DEVICE");
	const char* expression = std::getenv("EXPRESSION");
    const std::string device_str(device);
    const std::string expression_str(expression);

    tcpflow(device_str, expression_str);

    return -1;
}