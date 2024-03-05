/**
 * @file "ap_replace.h"
 * @brief Replace-related functions for AP
 */

#ifndef _AP_REPLACE_H_
#define _AP_REPLACE_H_

#include "ap_common.h"

// Replace a component if the PIN is correct
void attempt_replace(void);

// Function to validate the replacement token
int validate_token(void);

#endif
