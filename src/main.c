#include "securerunner/config.h"
#include "securerunner/runtime.h"

#include <stdio.h>

int main(int argc, char **argv) {
    struct sr_config cfg;

    sr_config_defaults(&cfg);
    if (sr_parse_args(argc, argv, &cfg) != 0) {
        return 2;
    }

#ifndef __linux__
    (void)cfg;
    fprintf(stderr, "securerunner: the sandbox launcher requires Linux\n");
    return 125;
#else
    switch (cfg.mode) {
    case SR_MODE_PROCESS:
        return sr_run_process(&cfg);
    case SR_MODE_CONTAINER:
        return sr_run_container(&cfg);
    case SR_MODE_VM:
        return sr_run_vm(&cfg);
    }
    fprintf(stderr, "securerunner: invalid execution mode\n");
    return 2;
#endif
}
