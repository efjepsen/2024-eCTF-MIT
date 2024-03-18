/**
 * @file ap_postboot.c
 * @brief Post-Boot-related functions for AP
 */

#include "ap_common.h"

/**
 * @brief Secure Send 
 * 
 * @param address: i2c_addr_t, I2C address of recipient
 * @param buffer: uint8_t*, pointer to data to be send
 * @param len: uint8_t, size of data to be sent 
 * 
 * Securely send data over I2C. This function is utilized in POST_BOOT functionality.
 * This function must be implemented by your team to align with the security requirements.

*/
int secure_send(uint8_t address, uint8_t* buffer, uint8_t len) {
    int ret;
    mit_comp_id_t component_id = ERROR_RETURN;
    mit_packet_t * tx_packet = get_tx_packet();

    for (int id = 0; id < COMPONENT_CNT; id++) {
        if (component_id_to_i2c_addr(get_component_id(id)) == address) {
            component_id = get_component_id(id);
        }
    }

    if (component_id == ERROR_RETURN) {
        return ERROR_RETURN;
    }

    ret = make_mit_packet(component_id, MIT_CMD_POSTBOOT, buffer, len);
    if (ret != SUCCESS_RETURN) {
        return ret;
    }

    return send_mit_packet(address, tx_packet);
}

/**
 * @brief Secure Receive
 * 
 * @param address: i2c_addr_t, I2C address of sender
 * @param buffer: uint8_t*, pointer to buffer to receive data to
 * 
 * @return int: number of bytes received, negative if error
 * 
 * Securely receive data over I2C. This function is utilized in POST_BOOT functionality.
 * This function must be implemented by your team to align with the security requirements.
*/
int secure_receive(i2c_addr_t address, uint8_t* buffer) {
    int ret, len;
    mit_packet_t * packet = get_rx_packet();
    mit_nonce_t old_nonce = {0};
    mit_comp_id_t component_id = ERROR_RETURN;

    for (int id = 0; id < COMPONENT_CNT; id++) {
        if (component_id_to_i2c_addr(get_component_id(id)) == address) {
            component_id = get_component_id(id);
        }
    }

    if (component_id == ERROR_RETURN) {
        return ERROR_RETURN;
    }

    len = poll_and_receive_packet(address, packet);
    if (len == ERROR_RETURN) {
        return ERROR_RETURN;
    }
   /*************** VALIDATE RECEIVED PACKET ****************/

    if (packet->ad.comp_id != component_id) {
        print_error("rx packet (0x%08x) doesn't match given component id (0x%08x)\n", packet->ad.comp_id, component_id);
        return ERROR_RETURN;
    }

    if (packet->ad.for_ap != true) {
        print_error("rx packet not tagged for AP\n");
        return ERROR_RETURN;
    }

    if (packet->ad.len == 0) {
        print_error("rx packet has null message length\n");
        return ERROR_RETURN;
    }

    if (packet->ad.opcode != MIT_CMD_POSTBOOT) {
        print_error("secure_send: bad opcode 0x%02x\n", packet->ad.comp_id);
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
            print_error("secure_receive: decryption failed with error %i\n", ret);
            memset(ap_plaintext, 0, AP_PLAINTEXT_LEN);
            return ERROR_RETURN;
        }
    } else {
        print_error("Incoming nonce (seq 0x%08x) doesn't match expected nonce (seq 0x%08x)\n",
            packet->ad.nonce.sequenceNumber, session->incoming_nonce.sequenceNumber
        );
        return ERROR_RETURN;
    }

    /*** INCREMENT NONCE ***/
    memset(old_nonce.rawBytes, 0, sizeof(mit_nonce_t));

    memcpy(old_nonce.rawBytes, session->incoming_nonce.rawBytes, sizeof(mit_nonce_t));
    memcpy(old_nonce.rawBytes, session->incoming_nonce.rawBytes, sizeof(mit_nonce_t));
    memcpy(old_nonce.rawBytes, session->incoming_nonce.rawBytes, sizeof(mit_nonce_t));

    if (mit_ConstantCompare_nonce(session->incoming_nonce.rawBytes, old_nonce.rawBytes) != 0) {
        memset(packet, 0, sizeof(mit_packet_t));
        memset(ap_plaintext, 0, AP_PLAINTEXT_LEN);
        return ERROR_RETURN;
    }

    increment_nonce(&session->incoming_nonce, &old_nonce);
    increment_nonce(&session->incoming_nonce, &old_nonce);
    increment_nonce(&session->incoming_nonce, &old_nonce);
    /***********************/

    /********************************************************/
    memcpy(buffer, ap_plaintext, len);

    return len;
}

/**
 * @brief Get Provisioned IDs
 * 
 * @param uint32_t* buffer
 * 
 * @return int: number of ids
 * 
 * Return the currently provisioned IDs and the number of provisioned IDs
 * for the current AP. This functionality is utilized in POST_BOOT functionality.
 * This function must be implemented by your team.
*/
int get_provisioned_ids(uint32_t* buffer) {
    for (int id = 0; id < COMPONENT_CNT; id++) {
        buffer[id] = get_component_id(id);
    }
    return COMPONENT_CNT;
}
