/**
 * @file ap_list.c
 * @brief List-related functions for AP
 */

#include "ap_common.h"

// Scan I2C address space for connected components
int scan_components() {
    // TODO we need to use ephemeral nonces in this section.
    // this section differs from our normal messaging scheme, where
    // we will only send to valid components we are provisioned for.

    // Print out provisioned component IDs
    for (unsigned id = 0; id < get_num_components(); id++) {
        print_info("P>0x%08x\n", get_component_id(id));
    }

    // Scan scan command to each component 
    for (i2c_addr_t addr = 0x8; addr < 0x78; addr++) {
        // I2C Blacklist:
        // 0x18, 0x28, and 0x36 conflict with separate devices on MAX78000FTHR
        if (addr == 0x18 || addr == 0x28 || addr == 0x36) {
            continue;
        }

        mit_comp_id_t component_id = addr;

        // Use proper component id if possible.
        for (int id = 0; id < get_num_components(); id++) {
            if (component_id_to_i2c_addr(get_component_id(id)) == addr) {
                component_id = get_component_id(id);
            }
        }

        ephemeral_handshake(component_id);
    }
    print_success("List\n");
    return SUCCESS_RETURN;
}
