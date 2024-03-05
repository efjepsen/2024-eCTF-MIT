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

        // Create command message
        uint8_t dummy = 0x55;
        make_mit_packet(addr, MIT_CMD_SCAN, &dummy, 1);
        
        // Send out command and receive result
        int len = issue_cmd(addr);

        mit_packet_t * packet = get_rx_packet();

        // Success, device is present
        if (len > 0) {
            print_info("F>0x%08x\n", packet->ad.comp_id);
        }
    }
    print_success("List\n");
    return SUCCESS_RETURN;
}
