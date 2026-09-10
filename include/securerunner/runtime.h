#ifndef SECURERUNNER_RUNTIME_H
#define SECURERUNNER_RUNTIME_H

#include "securerunner/config.h"

int sr_run_process(const struct sr_config *cfg);
int sr_run_container(const struct sr_config *cfg);
int sr_run_vm(const struct sr_config *cfg);

#endif
