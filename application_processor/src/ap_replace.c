/**
 * @file ap_replace.c
 * @brief Replace-related functions for AP
 */

#include "ap_common.h"

// Replace a component if the PIN is correct
void attempt_replace() {
    char buf[50];

    if (validate_token()) {
        return;
    }

    uint32_t component_id_in = 0;
    uint32_t component_id_out = 0;

    recv_input("Component ID In: ", buf);
    sscanf(buf, "%x", &component_id_in);
    recv_input("Component ID Out: ", buf);
    sscanf(buf, "%x", &component_id_out);

    if (swap_components(component_id_in, component_id_out) == ERROR_RETURN) {
        // Component Out was not found
        print_error("Component 0x%08x is not provisioned for the system\r\n",
                component_id_out);
        return;
    }

    print_debug("Replaced 0x%08x with 0x%08x\n", component_id_out,
            component_id_in);
    print_success("Replace\n");
}

// Function to validate the replacement token
int validate_token() {
    char buf[50];
    recv_input("Enter token: ", buf);
    if (!strcmp(buf, AP_TOKEN)) {
        print_debug("Token Accepted!\n");
        return SUCCESS_RETURN;
    }
    print_error("Invalid Token!\n");
    return ERROR_RETURN;
}
