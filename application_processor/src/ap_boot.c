/**
 * @file ap_boot.c
 * @brief Boot-related functions for AP
 */

#include "ap_common.h"

// Boot the components and board if the components validate
void attempt_boot() {
    if (validate_components()) {
        print_error("Components could not be validated\n");
        return;
    }
    print_debug("All Components validated\n");
    if (boot_components()) {
        print_error("Failed to boot all components\n");
        return;
    }
    // Print boot message
    // This always needs to be printed when booting
    print_info("AP>%s\n", AP_BOOT_MSG);
    print_success("Boot\n");
    // Boot
    boot();
}

// Validate that all components are present
int validate_components() {
    // Send validate command to each component
    for (unsigned i = 0; i < get_num_components(); i++) {
        // Get component id
        mit_comp_id_t component_id = get_component_id(i);

        // Create command message
        uint8_t dummy = 0x55;
        int ret = make_mit_packet(component_id, MIT_CMD_VALIDATE, &dummy, 1);
        if (ret != SUCCESS_RETURN) {
            return ret;
        }
        
        // Send out command and receive result
        int len = issue_cmd(component_id);
        if (len == ERROR_RETURN) {
            print_error("Could not validate component\n");
            return ERROR_RETURN;
        }

        mit_packet_t * packet = get_rx_packet();

        // Check that the result is correct
        if (packet->ad.comp_id != component_id) {
            print_error("Component ID: 0x%08x invalid\n", packet->ad.comp_id);
            return ERROR_RETURN;
        }
    }
    return SUCCESS_RETURN;
}

// Command components to boot
int boot_components() {
    // Send boot command to each component
    for (unsigned i = 0; i < get_num_components(); i++) {
        // Get component id
        mit_comp_id_t component_id = get_component_id(i);
        
        // Create command message
        uint8_t dummy = 0x55;
        make_mit_packet(component_id, MIT_CMD_BOOT, &dummy, 1);
        
        // Send out command and receive result
        int len = issue_cmd(component_id);
        if (len == ERROR_RETURN) {
            print_error("Could not boot component\n");
            return ERROR_RETURN;
        }

        mit_packet_t * packet = get_rx_packet();

        // Print boot message from component
        print_info("0x%08x>%s\n", packet->ad.comp_id, ap_plaintext);
    }
    return SUCCESS_RETURN;
}

// Boot sequence
// YOUR DESIGN MUST NOT CHANGE THIS FUNCTION
// Boot message is customized through the AP_BOOT_MSG macro
void boot() {
    // POST BOOT FUNCTIONALITY
    // DO NOT REMOVE IN YOUR DESIGN
    #ifdef POST_BOOT
        POST_BOOT
    #else
    // Everything after this point is modifiable in your design
    // LED loop to show that boot occurred
    while (1) {
        LED_On(LED1);
        MXC_Delay(500000);
        LED_On(LED2);
        MXC_Delay(500000);
        LED_On(LED3);
        MXC_Delay(500000);
        LED_Off(LED1);
        MXC_Delay(500000);
        LED_Off(LED2);
        MXC_Delay(500000);
        LED_Off(LED3);
        MXC_Delay(500000);
    }
    #endif
}
