/**
 * @file ap_attest.c
 * @brief Attest-related functions for AP
 */

#include "ap_common.h"

// Attest a component if the PIN is correct
void attempt_attest() {
    char * buf = get_uart_buf();

    if (validate_pin()) {
        return;
    }
    uint32_t component_id;
    recv_input("Component ID: ", 10); // 0x + 8 chars
    sscanf(buf, "%x", &component_id);
    if (attest_component(component_id) == SUCCESS_RETURN) {
        print_success("Attest\n");
    }
}

// Send attestation request to specific component
int attest_component(uint32_t component_id) {
    int ret, len;
    mit_challenge_t r1;
    // Step 0: validate component
    // TODO already done in messaging tbh

    // Step 1: generate random challenge r1
    get_random_challenge(&r1);

    // Step 2: construct AttestReq message
    mit_message_attestreq_t attestReq = {0};
    memcpy(attestReq.r1.rawBytes, r1.rawBytes, sizeof(mit_challenge_t));

    ret = make_mit_packet(component_id, MIT_CMD_ATTESTREQ, attestReq.rawBytes, sizeof(mit_message_attestreq_t));
    if (ret != SUCCESS_RETURN) {
        return ret;
    }

    // Step 3: send message
    // TODO validate opcode inside issue_cmd
    len = issue_cmd(component_id);
    if (len == ERROR_RETURN) {
        return ERROR_RETURN;
    }

    // Step 4: Validate r1 is present in response
    mit_message_t * response = (mit_message_t *)ap_plaintext;
    if (memcmp(response->attestReq.r1.rawBytes, attestReq.r1.rawBytes, sizeof(mit_challenge_t)) != 0) {
        return ERROR_RETURN;
    }

    // Step 5: Return r2
    mit_message_attest_t attest = {0};
    memcpy(attest.r2.rawBytes, response->attestReq.r2.rawBytes, sizeof(mit_challenge_t));

    ret = make_mit_packet(component_id, MIT_CMD_ATTEST, attest.rawBytes, sizeof(mit_message_attest_t));
    if (ret != SUCCESS_RETURN) {
        return ret;
    }

    // Step 6: send message
    // TODO validate opcode inside issue_cmd
    len = issue_cmd(component_id);
    if (len == ERROR_RETURN) {
        return ERROR_RETURN;
    }

    // Step 7: Print attestation data
    // TODO ensure response is a string :)
    response->rawBytes[sizeof(mit_message_t) - 1] = 0;
    print_info("C>0x%08x\n", component_id);
    print_info("%s", response->attest.customerData);
    return SUCCESS_RETURN;
}

// Compare the entered PIN to the correct PIN
int validate_pin(void) {
    char * buf = get_uart_buf();
    recv_input("Enter pin: ", 6);
    if (!strcmp(buf, AP_PIN)) {
        print_debug("Pin Accepted!\n");
        return SUCCESS_RETURN;
    }
    print_error("Invalid PIN!\n");
    return ERROR_RETURN;
}
