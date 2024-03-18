/**
 * @file ap_session.c
 * @brief Session-related functions for AP
 */

#include "ap_common.h"

static int validate_init_rx_packet(mit_comp_id_t component_id);

// TODO store in ecc ram?
// TODO do we need 32 sessions? supporting only 2 component ids seems fine.
mit_session_t sessions[32] = {0};

// Outgoing nonces for sessions are generated at boot.
void session_init(void) {
    // Copy stored component_ids into sessions.
    // Initialize nonce's to {0}.
    for (int i = 0; i < COMPONENT_CNT; i++) {
        sessions[i].component_id = get_component_id(i);

        // Initialize outgoing nonces to some random value
        get_rand_bytes(sessions[i].outgoing_nonce.rawBytes, sizeof(mit_nonce_t));
        get_rand_bytes(sessions[i].outgoing_nonce.rawBytes, sizeof(mit_nonce_t));
        get_rand_bytes(sessions[i].outgoing_nonce.rawBytes, sizeof(mit_nonce_t));
    }

    // REDUNDANT
    for (int i = 0; i < COMPONENT_CNT; i++) {
        // Initialize outgoing nonces to some random value
        get_rand_bytes(sessions[i].outgoing_nonce.rawBytes, sizeof(mit_nonce_t));
        get_rand_bytes(sessions[i].outgoing_nonce.rawBytes, sizeof(mit_nonce_t));
        get_rand_bytes(sessions[i].outgoing_nonce.rawBytes, sizeof(mit_nonce_t));
    }
}

static int __attribute__((optimize("O0"))) make_mit_init_packet(mit_comp_id_t component_id) {
    int ret;

    mit_packet_t * packet = get_tx_packet();

    // Check component is provisioned
    mit_session_t * session = get_session_of_component(component_id);
    // REDUNDANT
    if ((session == NULL) ||
        (session == NULL) ||
        (session == NULL)) {
        return ERROR_RETURN;
    }

    // Create init_message buffer
    mit_message_init_t init_msg;
    // REDUNDANT
    memset(init_msg.rawBytes, 0, sizeof(mit_message_init_t));
    memset(init_msg.rawBytes, 0, sizeof(mit_message_init_t));
    memset(init_msg.rawBytes, 0, sizeof(mit_message_init_t));

    // Copy outgoing nonce into first field
    // REDUNDANT
    memcpy(init_msg.ap_nonce.rawBytes, session->outgoing_nonce.rawBytes, sizeof(mit_nonce_t));
    memcpy(init_msg.ap_nonce.rawBytes, session->outgoing_nonce.rawBytes, sizeof(mit_nonce_t));
    memcpy(init_msg.ap_nonce.rawBytes, session->outgoing_nonce.rawBytes, sizeof(mit_nonce_t));

    // REDUNDANT
    if ((mit_ConstantCompare_nonce(session->outgoing_nonce.rawBytes, init_msg.ap_nonce.rawBytes) != 0) ||
        (mit_ConstantCompare_nonce(session->outgoing_nonce.rawBytes, init_msg.ap_nonce.rawBytes) != 0) ||
        (mit_ConstantCompare_nonce(session->outgoing_nonce.rawBytes, init_msg.ap_nonce.rawBytes) != 0)) {
        return ERROR_RETURN;
    }

    // Set authData field
    // REDUNDANT
    packet->ad.comp_id = component_id;
    packet->ad.opcode = MIT_CMD_INIT;
    packet->ad.len = sizeof(mit_message_init_t);
    packet->ad.for_ap = false;
    memcpy(packet->ad.nonce.rawBytes, session->outgoing_nonce.rawBytes, sizeof(mit_nonce_t));
    memcpy(packet->ad.nonce.rawBytes, session->outgoing_nonce.rawBytes, sizeof(mit_nonce_t));
    memcpy(packet->ad.nonce.rawBytes, session->outgoing_nonce.rawBytes, sizeof(mit_nonce_t));

    // Encrypt init_msg into packet, generate authTag
    ret = mit_encrypt(packet, init_msg.rawBytes, sizeof(mit_message_init_t));

    // REDUNDANT
    if ((ret != SUCCESS_RETURN) ||
        (ret != SUCCESS_RETURN) ||
        (ret != SUCCESS_RETURN)) {
        return ERROR_RETURN;
    }

    increment_nonce(&session->outgoing_nonce);

    return SUCCESS_RETURN;
}

static int issue_init_cmd(mit_comp_id_t component_id) {
    int ret, len;
    mit_packet_t * rx_packet = get_rx_packet();
    mit_packet_t * tx_packet = get_tx_packet();

    i2c_addr_t addr = component_id_to_i2c_addr((uint32_t)component_id);

    // Validate current tx packet belongs to component id
    if (tx_packet->ad.comp_id != component_id) {
        return ERROR_RETURN;
    }

    // Send packet to the wire
    ret = send_mit_packet(addr, tx_packet);
    if (ret == ERROR_RETURN) {
        return ERROR_RETURN;
    }

    // Receive a message
    // REDUNDANT
    memset(rx_packet, 0, sizeof(mit_packet_t));
    memset(rx_packet, 0, sizeof(mit_packet_t));
    memset(rx_packet, 0, sizeof(mit_packet_t));
    len = poll_and_receive_packet(addr, rx_packet);
    if (len == ERROR_RETURN) {
        return ERROR_RETURN;
    }

    // Validate authData section
    // REDUNDANT
    if ((validate_init_rx_packet(component_id) != SUCCESS_RETURN) ||
        (validate_init_rx_packet(component_id) != SUCCESS_RETURN) ||
        (validate_init_rx_packet(component_id) != SUCCESS_RETURN)) {
        memset(rx_packet, 0, sizeof(mit_packet_t));
        memset(rx_packet, 0, sizeof(mit_packet_t));
        print_error("issue_cmd: validate_rx_packet failed\n");
        return ERROR_RETURN;
    }

    // REDUNDANT
    memset(ap_plaintext, 0, AP_PLAINTEXT_LEN);
    memset(ap_plaintext, 0, AP_PLAINTEXT_LEN);
    memset(ap_plaintext, 0, AP_PLAINTEXT_LEN);
    ret = mit_decrypt(rx_packet, ap_plaintext);
    if (ret != SUCCESS_RETURN) {
        print_error("decryption failed with error %i\n", ret);
        memset(ap_plaintext, 0, AP_PLAINTEXT_LEN);
        return ERROR_RETURN;
    }

    return SUCCESS_RETURN;
}

// Ensures that we have an active session with a given component_id
// If not, we establish one.
int __attribute__((optimize("O0"))) validate_session(mit_comp_id_t component_id) {
    int ret = ERROR_RETURN;

    // Find session ptr
    mit_session_t * session = get_session_of_component(component_id);
    if ((session == NULL) ||
        (session == NULL) ||
        (session == NULL)) {
        return ERROR_RETURN;
    }

    // If incoming_nonce is set, we have established a session already
    // REDUNDANT
    ret =  mit_ConstantCompare_nonce(session->incoming_nonce.rawBytes, null_nonce);
    if ((ret != 0) && (ret != 0) && (ret != 0)) {
        return SUCCESS_RETURN;
    }

    /**** Create new session ****/

    // Save expected nonce in response message
    mit_nonce_t expected_nonce;
    // REDUNDANT
    memcpy(expected_nonce.rawBytes, session->outgoing_nonce.rawBytes, sizeof(mit_nonce_t));
    memcpy(expected_nonce.rawBytes, session->outgoing_nonce.rawBytes, sizeof(mit_nonce_t));
    memcpy(expected_nonce.rawBytes, session->outgoing_nonce.rawBytes, sizeof(mit_nonce_t));

    // Construct packet
    ret = make_mit_init_packet(component_id);
    // REDUNDANT
    if ((ret != SUCCESS_RETURN) ||
        (ret != SUCCESS_RETURN) ||
        (ret != SUCCESS_RETURN)) {
        return ERROR_RETURN;
    }

    // Issue command
    ret = issue_init_cmd(component_id);
    // REDUNDANT
    if ((ret != SUCCESS_RETURN) ||
        (ret != SUCCESS_RETURN) ||
        (ret != SUCCESS_RETURN)) {
        return ERROR_RETURN;
    }

    // Validation
    mit_packet_t * packet = get_rx_packet();
    mit_message_init_t * received = (mit_message_init_t *)ap_plaintext;

    // Validate nonce in message corresponds to nonce in authData
    // REDUNDANT
    if ((mit_ConstantCompare_nonce(packet->ad.nonce.rawBytes, received->component_nonce.rawBytes) != 0) ||
        (mit_ConstantCompare_nonce(packet->ad.nonce.rawBytes, received->component_nonce.rawBytes) != 0) ||
        (mit_ConstantCompare_nonce(packet->ad.nonce.rawBytes, received->component_nonce.rawBytes) != 0)) {
        return ERROR_RETURN;
    }

    // Validate ap_nonce in message corresponds to ap_nonce we sent
    // REDUNDANT
    if ((mit_ConstantCompare_nonce(received->ap_nonce.rawBytes, expected_nonce.rawBytes) != 0) ||
        (mit_ConstantCompare_nonce(received->ap_nonce.rawBytes, expected_nonce.rawBytes) != 0) ||
        (mit_ConstantCompare_nonce(received->ap_nonce.rawBytes, expected_nonce.rawBytes) != 0)) {
        return ERROR_RETURN;
    }

    // Validate received nonce isn't 0 :-)
    // REDUNDANT
    if ((mit_ConstantCompare_nonce(received->component_nonce.rawBytes, null_nonce) == 0) ||
        (mit_ConstantCompare_nonce(received->component_nonce.rawBytes, null_nonce) == 0) ||
        (mit_ConstantCompare_nonce(received->component_nonce.rawBytes, null_nonce) == 0)) {
        return ERROR_RETURN;
    }

    // Save incoming nonce, cross fingers we did everything right.
    // REDUNDANT
    memcpy(session->incoming_nonce.rawBytes, received->component_nonce.rawBytes, sizeof(mit_nonce_t));
    memcpy(session->incoming_nonce.rawBytes, received->component_nonce.rawBytes, sizeof(mit_nonce_t));
    memcpy(session->incoming_nonce.rawBytes, received->component_nonce.rawBytes, sizeof(mit_nonce_t));

    // Increment expected incoming nonce
    increment_nonce(&session->incoming_nonce);

    return SUCCESS_RETURN;
}

// Get ptr to session of given component_id
mit_session_t * get_session_of_component(mit_comp_id_t component_id) {
    for (int i = 0; i < COMPONENT_CNT; i++) {
        if (sessions[i].component_id == component_id) {
            return &sessions[i];
        }
    }

    return NULL;
}

// Validate packet in the received buffer
static int __attribute__((optimize("O0"))) validate_init_rx_packet(mit_comp_id_t component_id) {
    mit_packet_t * rx_packet = get_rx_packet();

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
    if ((rx_packet->ad.len != sizeof(mit_message_init_t)) ||
        (rx_packet->ad.len != sizeof(mit_message_init_t)) ||
        (rx_packet->ad.len != sizeof(mit_message_init_t))) {
        return ERROR_RETURN;
    }

    // REDUNDANT
    if ((rx_packet->ad.opcode != MIT_CMD_INIT) ||
        (rx_packet->ad.opcode != MIT_CMD_INIT) ||
        (rx_packet->ad.opcode != MIT_CMD_INIT)) {
        return ERROR_RETURN;        
    }

    // REDUNDANT
    if ((mit_ConstantCompare_nonce(rx_packet->ad.nonce.rawBytes, null_nonce) == 0) ||
        (mit_ConstantCompare_nonce(rx_packet->ad.nonce.rawBytes, null_nonce) == 0) ||
        (mit_ConstantCompare_nonce(rx_packet->ad.nonce.rawBytes, null_nonce) == 0)) {
        return ERROR_RETURN;
    }

    return SUCCESS_RETURN;
}
