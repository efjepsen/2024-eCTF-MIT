/**
 * @file "ap_boot.h"
 * @brief Boot-related functions for AP
 */

#ifndef _AP_BOOT_H_
#define _AP_BOOT_H_

#include "ap_common.h"

// Boot the components and board if the components validate
void attempt_boot(void);

// Validate that all components are present
int validate_components(void);

// Command components to boot
int boot_components(void);

// Command AP to boot
void boot(void);

#endif
