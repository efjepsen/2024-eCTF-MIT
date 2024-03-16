/**
 * @file ap_boot.c
 * @brief Boot-related functions for AP
 */

#include "ap_common.h"

static mit_challenge_t boot_challenges[COMPONENT_CNT] = {0};
static mit_challenge_t null_challenge = {0};

#define boot_err print_error("Could not boot\n")

// TODO clear boot_msgs, boot_challenges on errors
int attempt_boot() {
    int ret, len;
    mit_challenge_t r1;
    mit_comp_id_t component_id;
    mit_message_t * response = (mit_message_t *)ap_plaintext;

    // TODO random delay

    // Validate that all provisioned components are alive and well.
    for (int id = 0; id < COMPONENT_CNT; id++) {
        component_id = get_component_id(id);
        if (component_id == ERROR_RETURN) {
            boot_err;
            return ERROR_RETURN;
        }

        // Step 0: validate component
        // TODO already done in messaging tbh

        // Step 1: generate random challenge r1
        // REDUNDANT
        get_random_challenge(&r1);
        get_random_challenge(&r1);
        get_random_challenge(&r1);

        // Step 2: construct BootReq message
        mit_message_bootreq_t bootReq = {0};
        // REDUNDANT
        memcpy(bootReq.r1.rawBytes, r1.rawBytes, sizeof(mit_challenge_t));
        memcpy(bootReq.r1.rawBytes, r1.rawBytes, sizeof(mit_challenge_t));
        memcpy(bootReq.r1.rawBytes, r1.rawBytes, sizeof(mit_challenge_t));

        ret = make_mit_packet(component_id, MIT_CMD_BOOTREQ, bootReq.rawBytes, sizeof(mit_message_bootreq_t));
        if (ret != SUCCESS_RETURN) {
            boot_err;
            return ret;
        }

        // Step 3: send message
        len = issue_cmd(component_id, MIT_CMD_BOOTREQ);
        if (len == ERROR_RETURN) {
            boot_err;
            return ERROR_RETURN;
        }

        // Step 4: Validate r1 is present in response
        // REDUNDANT
        if (mit_ConstantCompare_challenge(response->bootReq.r1.rawBytes, bootReq.r1.rawBytes) ||
            mit_ConstantCompare_challenge(response->bootReq.r1.rawBytes, bootReq.r1.rawBytes) ||
            mit_ConstantCompare_challenge(response->bootReq.r1.rawBytes, bootReq.r1.rawBytes)) {
            boot_err;
            return ERROR_RETURN;
        }

        // Step 5: Save r2
        // REDUNDANT
        memcpy(boot_challenges[id].rawBytes, response->bootReq.r2.rawBytes, sizeof(mit_challenge_t));
        memcpy(boot_challenges[id].rawBytes, response->bootReq.r2.rawBytes, sizeof(mit_challenge_t));
        memcpy(boot_challenges[id].rawBytes, response->bootReq.r2.rawBytes, sizeof(mit_challenge_t));
    }

    // Confirm that we saved boot challenges for all provisioned components
    for (int id = 0; id < COMPONENT_CNT; id++) {
        // REDUNDANT
        if ((mit_ConstantCompare_challenge(boot_challenges[id].rawBytes, null_challenge.rawBytes) == 0) ||
            (mit_ConstantCompare_challenge(boot_challenges[id].rawBytes, null_challenge.rawBytes) == 0) ||
            (mit_ConstantCompare_challenge(boot_challenges[id].rawBytes, null_challenge.rawBytes) == 0)) {
            boot_err;
            return ERROR_RETURN;
        }
    }

    // Confirm that we saved boot challenges for all provisioned components... again.
    for (int id = 0; id < COMPONENT_CNT; id++) {
        // REDUNDANT
        if ((mit_ConstantCompare_challenge(boot_challenges[id].rawBytes, null_challenge.rawBytes) == 0) ||
            (mit_ConstantCompare_challenge(boot_challenges[id].rawBytes, null_challenge.rawBytes) == 0) ||
            (mit_ConstantCompare_challenge(boot_challenges[id].rawBytes, null_challenge.rawBytes) == 0)) {
            boot_err;
            return ERROR_RETURN;
        }
    }

    // Command provisioned components to boot.
    for (int id = 0; id < COMPONENT_CNT; id++) {
        mit_comp_id_t component_id = get_component_id(id);
        if (component_id == ERROR_RETURN) {
            boot_err;
            return ERROR_RETURN;
        }

        // Step 5: Return r2
        mit_message_boot_t boot = {0};
        // REDUNDANT
        memcpy(boot.r2.rawBytes, boot_challenges[id].rawBytes, sizeof(mit_challenge_t));
        memcpy(boot.r2.rawBytes, boot_challenges[id].rawBytes, sizeof(mit_challenge_t));
        memcpy(boot.r2.rawBytes, boot_challenges[id].rawBytes, sizeof(mit_challenge_t));

        ret = make_mit_packet(component_id, MIT_CMD_BOOT, boot.rawBytes, sizeof(mit_message_boot_t));
        if (ret != SUCCESS_RETURN) {
            boot_err;
            return ret;
        }

        // Step 6: send message
        len = issue_cmd(component_id, MIT_CMD_BOOT);
        if (len == ERROR_RETURN) {
            boot_err;
            return ERROR_RETURN;
        }

        // Step 7: Print boot msg
        response->rawBytes[sizeof(mit_message_t) - 1] = 0;
        print_info("0x%08x>%s\n", component_id, response->boot.bootMsg);
    }

    // Confirm that we saved boot challenges for all provisioned components... again... again.
    for (int id = 0; id < COMPONENT_CNT; id++) {
        // REDUNDANT
        if ((mit_ConstantCompare_challenge(boot_challenges[id].rawBytes, null_challenge.rawBytes) == 0) ||
            (mit_ConstantCompare_challenge(boot_challenges[id].rawBytes, null_challenge.rawBytes) == 0) ||
            (mit_ConstantCompare_challenge(boot_challenges[id].rawBytes, null_challenge.rawBytes) == 0)) {
            boot_err;
            return ERROR_RETURN;
        }
    }

    // Print boot message
    // This always needs to be printed when booting
    print_info("AP>%s\n", AP_BOOT_MSG);
    print_success("Boot\n");
    // Boot
    boot_ap();
}

// Boot sequence
// YOUR DESIGN MUST NOT CHANGE THIS FUNCTION
// Boot message is customized through the AP_BOOT_MSG macro
void boot_ap() {
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
