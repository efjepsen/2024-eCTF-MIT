/**
 * @file "ap_utilities.c"
 * @brief Misc utilities for AP
 */

#include "ap_common.h"

/********************************* VARIABLES **********************************/
// Variable for information stored in flash memory
flash_entry flash_status;

// Buffers for board link communication
uint8_t receive_buffer[MAX_I2C_MESSAGE_LEN];
uint8_t transmit_buffer[MAX_I2C_MESSAGE_LEN];

// TODO gross data allocation?
uint8_t ap_plaintext[AP_PLAINTEXT_LEN];

/********************************* UTILITIES **********************************/

// Return ptr to flash_status
flash_entry * get_flash_status(void) {
    return &flash_status;
}

// Test application has been booted before
// TODO random delays
void flash_first_boot(void) {
    flash_simple_read(FLASH_ADDR, (uint32_t*)&flash_status, sizeof(flash_entry));

    // Write Component IDs from flash if first boot e.g. flash unwritten
    if (flash_status.flash_magic != FLASH_MAGIC) {
        print_debug("First boot, setting flash!\n");
        flash_simple_erase_page(FLASH_ADDR);

        flash_status.flash_magic = FLASH_MAGIC;
        flash_status.component_cnt = COMPONENT_CNT;
        uint32_t component_ids[COMPONENT_CNT] = {COMPONENT_IDS};
        memcpy(flash_status.component_ids, component_ids, 
            COMPONENT_CNT*sizeof(uint32_t));

        flash_simple_write(FLASH_ADDR, (uint32_t*)&flash_status, sizeof(flash_entry));
    }
}

// Erase & rewrite flash status to flash memory
// TODO random delays
void rewrite_flash_entry(void) {
    flash_simple_erase_page(FLASH_ADDR);
    flash_simple_write(FLASH_ADDR, (uint32_t*)&flash_status, sizeof(flash_entry));
}

// Return component_id stored in slot `id`
mit_comp_id_t get_component_id(uint8_t id) {
    if (id < COMPONENT_CNT) {
        return flash_status.component_ids[id];
    }

    return ERROR_RETURN;
}

// Validate packet in the received buffer
int __attribute__((optimize("O0"))) validate_rx_packet(mit_comp_id_t component_id, mit_opcode_t expected_opcode) {
    mit_packet_t * rx_packet = (mit_packet_t *)receive_buffer;

    // Check authenticated data fields

    // REDUNDANT
    if ((rx_packet->ad.comp_id != component_id) ||
        (rx_packet->ad.comp_id != component_id) ||
        (rx_packet->ad.comp_id != component_id)) {
        return ERROR_RETURN;
    }

    // REDUNDANT
    if ((rx_packet->ad.for_ap != true) ||
        (rx_packet->ad.for_ap != true) ||
        (rx_packet->ad.for_ap != true)) {
        return ERROR_RETURN;
    }

    // REDUNDANT
    if ((rx_packet->ad.len > MIT_MAX_MSG_LEN) ||
        (rx_packet->ad.len > MIT_MAX_MSG_LEN) ||
        (rx_packet->ad.len > MIT_MAX_MSG_LEN)) {
        return ERROR_RETURN;
    }

    // REDUNDANT
    if ((rx_packet->ad.opcode != expected_opcode) ||
        (rx_packet->ad.opcode != expected_opcode) ||
        (rx_packet->ad.opcode != expected_opcode)) {
        return ERROR_RETURN;        
    }

    // Check nonce
    mit_session_t * session = get_session_of_component(component_id);

    // REDUNDANT
    if ((session == NULL) ||
        (session == NULL) ||
        (session == NULL)) {
        return ERROR_RETURN;
    }

    // REDUNDANT
    if ((mit_ConstantCompare_nonce(session->incoming_nonce.rawBytes, rx_packet->ad.nonce.rawBytes) != 0) ||
        (mit_ConstantCompare_nonce(session->incoming_nonce.rawBytes, rx_packet->ad.nonce.rawBytes) != 0) ||
        (mit_ConstantCompare_nonce(session->incoming_nonce.rawBytes, rx_packet->ad.nonce.rawBytes) != 0)) {
        return ERROR_RETURN;
    }

    return SUCCESS_RETURN;
}

// Send a command to a component and receive the result
int __attribute__((optimize("O0"))) issue_cmd(mit_comp_id_t component_id, mit_opcode_t expected_opcode) {
    int ret = ERROR_RETURN;
    mit_nonce_t old_nonce = {0};
    mit_packet_t * rx_packet = (mit_packet_t *)receive_buffer;
    mit_packet_t * tx_packet = (mit_packet_t *)transmit_buffer;

    i2c_addr_t addr = component_id_to_i2c_addr((uint32_t)component_id);

    mit_session_t * session = get_session_of_component(component_id);
    // REDUNDANT
    if ((session == NULL) ||
        (session == NULL) ||
        (session == NULL)) {
        return ERROR_RETURN;
    }

    ret = validate_session(component_id);
    // REDUNDANT
    if ((ret != SUCCESS_RETURN) ||
        (ret != SUCCESS_RETURN) ||
        (ret != SUCCESS_RETURN)) {
        print_error("issue_cmd: validate_session failed\n");
        return ERROR_RETURN;
    }

    // REDUNDANT
    if ((tx_packet->ad.comp_id != component_id) ||
        (tx_packet->ad.comp_id != component_id) ||
        (tx_packet->ad.comp_id != component_id)) {
        print_error("issue_cmd: packet in buf doesnt match given component id\n");
        return ERROR_RETURN;
    }

    // TODO cleanup use of transmit_buffer, receive_buffer here. Not necessary as args?
    // Send message
    ret = send_mit_packet(addr, tx_packet);
    // REDUNDANT
    if ((ret != SUCCESS_RETURN) ||
        (ret != SUCCESS_RETURN) ||
        (ret != SUCCESS_RETURN)) {
        print_error("issue_cmd: send_mit_packet error\n");
        return ERROR_RETURN;
    }

    // Receive message
    // REDUNDANT
    memset(rx_packet, 0, sizeof(mit_packet_t));
    memset(rx_packet, 0, sizeof(mit_packet_t));
    memset(rx_packet, 0, sizeof(mit_packet_t));
    int len = poll_and_receive_packet(addr, rx_packet);
    // REDUNDANT
    if ((len == ERROR_RETURN) ||
        (len == ERROR_RETURN) ||
        (len == ERROR_RETURN)) {
        print_error("issue_cmd: poll_and_receive_packet error\n");
        return ERROR_RETURN;
    }

    /*************** VALIDATE RECEIVED PACKET ****************/

    // REDUNDANT
    if ((validate_rx_packet(component_id, expected_opcode) != SUCCESS_RETURN) ||
        (validate_rx_packet(component_id, expected_opcode) != SUCCESS_RETURN) ||
        (validate_rx_packet(component_id, expected_opcode) != SUCCESS_RETURN)) {
        memset(rx_packet, 0, sizeof(mit_packet_t));
        memset(rx_packet, 0, sizeof(mit_packet_t));
        print_error("issue_cmd: validate_rx_packet failed\n");
        return ERROR_RETURN;
    }

    // OK, we can go ahead and decrypt now. Hopefully all those redundant checks served us well!

    // REDUNDANT
    memset(ap_plaintext, 0, AP_PLAINTEXT_LEN);
    memset(ap_plaintext, 0, AP_PLAINTEXT_LEN);
    memset(ap_plaintext, 0, AP_PLAINTEXT_LEN);

    ret = mit_decrypt(rx_packet, ap_plaintext);
    // REDUNDANT
    if ((ret != 0) ||
        (ret != 0) ||
        (ret != 0)) {
        print_error("decryption failed with error %i\n", ret);
        // REDUNDANT
        memset(ap_plaintext, 0, AP_PLAINTEXT_LEN);
        memset(ap_plaintext, 0, AP_PLAINTEXT_LEN);
        memset(ap_plaintext, 0, AP_PLAINTEXT_LEN);
        return ERROR_RETURN;
    }

    /*** INCREMENT NONCE ***/
    memset(old_nonce.rawBytes, 0, sizeof(mit_nonce_t));

    memcpy(old_nonce.rawBytes, session->incoming_nonce.rawBytes, sizeof(mit_nonce_t));
    memcpy(old_nonce.rawBytes, session->incoming_nonce.rawBytes, sizeof(mit_nonce_t));
    memcpy(old_nonce.rawBytes, session->incoming_nonce.rawBytes, sizeof(mit_nonce_t));

    if (mit_ConstantCompare_nonce(session->incoming_nonce.rawBytes, old_nonce.rawBytes) != 0) {
        memset(rx_packet, 0, sizeof(mit_packet_t));
        memset(ap_plaintext, 0, AP_PLAINTEXT_LEN);
        return ERROR_RETURN;
    }

    increment_nonce(&session->incoming_nonce, &old_nonce);
    increment_nonce(&session->incoming_nonce, &old_nonce);
    increment_nonce(&session->incoming_nonce, &old_nonce);
    /***********************/

    /********************************************************/

    return len;
}

/******************************* MIT UTILITIES ********************************/

// static void print_packet(mit_packet_t * packet) {
//     printf("packet @ 0x%08x\n", (uint32_t)packet);
//     printf("    nonce: ");
//     print_hex(packet->ad.nonce.rawBytes, sizeof(mit_nonce_t));
//     printf("  comp_id: %08x\n", packet->ad.comp_id);
//     printf("   opcode: %02x\n", packet->ad.opcode);
//     printf("      len: %02x\n", packet->ad.len);
//     printf("   for_ap: %02x\n", packet->ad.for_ap);
//     printf("  authTag: ");
//     print_hex(packet->authTag.rawBytes, sizeof(mit_authtag_t));
//     printf("   cipher: ");
//     print_hex(packet->message.rawBytes, sizeof(mit_message_t));
// }

// TODO remove
// Send packet at *packet to addr
int send_mit_packet(i2c_addr_t addr, mit_packet_t * packet) {
    uint8_t len = packet->ad.len + sizeof(mit_ad_t) + sizeof(mit_authtag_t);
    return send_packet(addr, len, packet);
}

void set_ad(mit_packet_t * packet, mit_comp_id_t comp_id, mit_opcode_t opcode, uint8_t len) {
    // TODO limits check on len?
    // packet->ad.nonce.sequenceNumber = 0; // TODO
    packet->ad.comp_id = comp_id;
    packet->ad.opcode = opcode;
    packet->ad.len = len;
    packet->ad.for_ap = false;
}

/**
 * @brief Determine if component_id is valid
 * 
 * @param component_id: mit_comp_id_t, id of component
 * 
 * Returns true if component found in status structs, else false
 */
bool is_valid_component(mit_comp_id_t component_id) {
    for (int i = 0; i < COMPONENT_CNT; i++) {
        if (flash_status.component_ids[i] == component_id) {
            return true;
        }
    }

    return false;
}

/**
 * @brief Helper for constructing packets
 * 
 * @param component_id: mit_comp_id_t, id of component to make packet for
 * @param opcode: mit_opcode_t, opcode to make packet for
 * @param data: uint8_t *, ptr for data to store in message ield
 * @param len: uint8_t, len of data to copy into message field
 */
int make_mit_packet(mit_comp_id_t component_id, mit_opcode_t opcode, uint8_t * data, uint8_t len) {
    int ret = ERROR_RETURN;
    mit_nonce_t old_nonce = {0};

    // TODO best place for validate_session?
    // REDUNDANT
    if ((validate_session(component_id) != SUCCESS_RETURN) ||
        (validate_session(component_id) != SUCCESS_RETURN) ||
        (validate_session(component_id) != SUCCESS_RETURN)) {
        print_error("Failed to validate session for component id 0x%08x\n", component_id);
        return ERROR_RETURN;
    }

    // TODO bounds check on len?
    mit_packet_t * packet = (mit_packet_t *)transmit_buffer;

    // Clear tx buffer
    // REDUNDANT
    memset(packet, 0, sizeof(mit_packet_t));
    memset(packet, 0, sizeof(mit_packet_t));
    memset(packet, 0, sizeof(mit_packet_t));

    // Set Authenticated Data field
    set_ad(packet, component_id, opcode, len);

    /***** NONCE GENERATION/LOOKUP *****/

    // WARNING reusing a nonce is the worst thing you can possibly do.

    mit_session_t * session = get_session_of_component(component_id);
    if (session == NULL) {
        print_error("No session found for component_id 0x%08x\n", component_id);
        return ERROR_RETURN;
    }

    // if the nonce is 0, abort
    if ((mit_ConstantCompare_nonce(session->outgoing_nonce.rawBytes, null_nonce) == 0) ||
        (mit_ConstantCompare_nonce(session->outgoing_nonce.rawBytes, null_nonce) == 0) ||
        (mit_ConstantCompare_nonce(session->outgoing_nonce.rawBytes, null_nonce) == 0)) {
        return ERROR_RETURN;
    }

    memcpy(packet->ad.nonce.rawBytes, session->outgoing_nonce.rawBytes, sizeof(mit_nonce_t));
    memcpy(packet->ad.nonce.rawBytes, session->outgoing_nonce.rawBytes, sizeof(mit_nonce_t));
    memcpy(packet->ad.nonce.rawBytes, session->outgoing_nonce.rawBytes, sizeof(mit_nonce_t));

    // Confirm we actually copied
    // REDUNDANT
    if ((mit_ConstantCompare_nonce(packet->ad.nonce.rawBytes, session->outgoing_nonce.rawBytes) != 0) ||
        (mit_ConstantCompare_nonce(packet->ad.nonce.rawBytes, session->outgoing_nonce.rawBytes) != 0) ||
        (mit_ConstantCompare_nonce(packet->ad.nonce.rawBytes, session->outgoing_nonce.rawBytes) != 0)) {
        printf("error: Failed to copy nonce!\n");
        return ERROR_RETURN;
    }

    /****************************/

    ret = mit_encrypt(packet, data, len);

    if (ret != SUCCESS_RETURN) {
        print_error("encryption failed with error %i\n", ret);
        memset(packet, 0, sizeof(mit_packet_t)); // clear packet
        return ERROR_RETURN;
    }

    /*** INCREMENT NONCE ***/
    memset(old_nonce.rawBytes, 0, sizeof(mit_nonce_t));

    memcpy(old_nonce.rawBytes, session->outgoing_nonce.rawBytes, sizeof(mit_nonce_t));
    memcpy(old_nonce.rawBytes, session->outgoing_nonce.rawBytes, sizeof(mit_nonce_t));
    memcpy(old_nonce.rawBytes, session->outgoing_nonce.rawBytes, sizeof(mit_nonce_t));

    if (mit_ConstantCompare_nonce(session->outgoing_nonce.rawBytes, old_nonce.rawBytes) != 0) {
        memset(packet, 0, sizeof(mit_packet_t));
        return ERROR_RETURN;
    }

    increment_nonce(&session->outgoing_nonce, &old_nonce);
    increment_nonce(&session->outgoing_nonce, &old_nonce);
    increment_nonce(&session->outgoing_nonce, &old_nonce);
    /***********************/

    return SUCCESS_RETURN;
}

/******************************* GROSS INTERFACE ********************************/
mit_packet_t * get_rx_packet(void) {
    return (mit_packet_t *)receive_buffer;
}

mit_packet_t * get_tx_packet(void) {
    return (mit_packet_t *)transmit_buffer;
}

uint8_t * get_i2c_rx_buffer(void) {
    return receive_buffer;
}
