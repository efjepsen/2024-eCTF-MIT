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

// Send a command to a component and receive the result
int issue_cmd(mit_comp_id_t component_id, mit_opcode_t expected_opcode) {
    int ret;

    i2c_addr_t addr = component_id_to_i2c_addr((uint32_t)component_id);

    ret = validate_session(component_id);
    if (ret != SUCCESS_RETURN) {
        print_error("issue_cmd: validate_session failed\n");
        return ERROR_RETURN;
    }

    mit_packet_t * packet = get_tx_packet();
    if (packet->ad.comp_id != component_id) {
        print_error("issue_cmd: packet in buf doesnt match given component id\n");
        return ERROR_RETURN;
    }

    // TODO cleanup use of transmit_buffer, receive_buffer here. Not necessary as args?
    // Send message
    int result = send_mit_packet(addr, (mit_packet_t *)transmit_buffer);
    if (result == ERROR_RETURN) {
        print_error("issue_cmd: send_mit_packet error\n");
        return ERROR_RETURN;
    }

    // Receive message
    int len = poll_and_receive_packet(addr, receive_buffer);
    if (len == ERROR_RETURN) {
        print_error("issue_cmd: poll_and_receive_packet error\n");
        return ERROR_RETURN;
    }

    /*************** VALIDATE RECEIVED PACKET ****************/
    packet = get_rx_packet();

    if (packet->ad.comp_id != component_id) {
        print_error("rx packet (0x%08x) doesn't match given component id (0x%08x)\n", packet->ad.comp_id, component_id);
        return ERROR_RETURN;
    }

    if (packet->ad.for_ap != true) {
        print_error("rx packet not tagged for AP\n");
        return ERROR_RETURN;
    }

    // TODO use message len lookup table?
    if (packet->ad.len == 0) {
        print_error("rx packet has null message length\n");
        return ERROR_RETURN;
    }

    if (packet->ad.opcode != expected_opcode) {
        print_error("rx packet has wrong opcode, expected 0x%02x, got 0x%02x\n", expected_opcode, packet->ad.opcode);
        return ERROR_RETURN;
    }

    mit_session_t * session = get_session_of_component(component_id);
    if (session == NULL) {
        print_error("Session not found for component id 0x%08x\n", component_id);
    }

    // Validate incoming nonce matches expected nonce
    if (mit_ConstantCompare_nonce(session->incoming_nonce.rawBytes, packet->ad.nonce.rawBytes) == 0) {
        ret = mit_decrypt(packet, ap_plaintext);

        if (ret != SUCCESS_RETURN) {
            print_error("decryption failed with error %i\n", ret);
            memset(ap_plaintext, 0, AP_PLAINTEXT_LEN);
            return ERROR_RETURN;
        }
    } else {
        print_error("Incoming nonce (seq 0x%08x) doesn't match expected nonce (seq 0x%08x)\n",
            packet->ad.nonce.sequenceNumber, session->incoming_nonce.sequenceNumber
        );
        return ERROR_RETURN;
    }

    increment_nonce(&session->incoming_nonce);

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
    int ret;

    // TODO best place for validate_session?
    ret = validate_session(component_id);
    if (ret != SUCCESS_RETURN) {
        print_error("Failed to validate session for component id 0x%08x\n", component_id);
        return ERROR_RETURN;
    }

    // TODO bounds check on len?
    mit_packet_t * packet = (mit_packet_t *)transmit_buffer;

    // Set Authenticated Data field
    set_ad(packet, component_id, opcode, len);

    /***** NONCE GENERATION/LOOKUP *****/

    // WARNING reusing a nonce is the worst thing you can possibly do.

    mit_session_t * session = get_session_of_component(component_id);
    if (session == NULL) {
        print_error("No session found for component_id 0x%08x\n", component_id);
        return ERROR_RETURN;
    }

    // if the nonce is 0, generate a random nonce
    while (mit_ConstantCompare_nonce(session->outgoing_nonce.rawBytes, null_nonce) == 0) {
        get_rand_bytes(session->outgoing_nonce.rawBytes, sizeof(mit_nonce_t));
    }

    memcpy(packet->ad.nonce.rawBytes, session->outgoing_nonce.rawBytes, sizeof(mit_nonce_t));

    // TODO do we really need this :)
    if (mit_ConstantCompare_nonce(packet->ad.nonce.rawBytes, session->outgoing_nonce.rawBytes) != 0) {
        print_error("Failed to copy nonce!\n");
        return ERROR_RETURN;
    }
    /****************************/

    ret = mit_encrypt(packet, data, len);

    if (ret != SUCCESS_RETURN) {
        print_error("encryption failed with error %i\n", ret);
        memset(packet, 0, sizeof(mit_packet_t)); // clear packet
        return ERROR_RETURN;
    }

    increment_nonce(&session->outgoing_nonce);

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
