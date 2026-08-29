#include "pairing/PairingMessageHelper.h"
#include <pb_encode.h>
#include <pb_decode.h>
#include <pb_common.h>
#include "pairingmessage.pb.h"

uint8_t *PairingMessageHelper::encodePairingMessage(Pairing_PairingMessage &message)
{
    // 1. get the size of the meggase
    size_t msg_required_buffer_size;
    bool was_size_found = pb_get_encoded_size(&msg_required_buffer_size, Pairing_PairingMessage_fields, &message);

    if (!was_size_found)
    {
        return NULL;
    }

    // 2. Dynamically allocate or claim a block matching that exact size
    uint8_t *dynamic_buffer = (uint8_t *)malloc(msg_required_buffer_size);
    if (!dynamic_buffer)
        return NULL;

    // 3. Create a real stream and serialize into your perfectly-sized buffer
    pb_ostream_t real_stream = pb_ostream_from_buffer(dynamic_buffer, msg_required_buffer_size);
    if (pb_encode(&real_stream, Pairing_PairingMessage_fields, &message))
    {
        // remember to clear the buffer when no longer needed
        return dynamic_buffer;
    }
    return NULL;
}

// remember to free the buffer after using it
uint8_t *PairingMessageHelper::createPairingRequest(String service_name, String model)
{
    Pairing_PairingMessage message = Pairing_PairingMessage_init_default;

    Pairing_PairingRequest request = Pairing_PairingRequest_init_default;

    request.service_name = const_cast<char*>(service_name.c_str());
    request.client_name = const_cast<char*>(model.c_str());

    size_t msg_pyload_size;
    bool was_size_found = pb_get_encoded_size(&msg_pyload_size, Pairing_PairingRequest_fields, &request);

    if (!was_size_found)
    {
        return NULL;
    }

    message.playload_size = msg_pyload_size;
    message.payload.pairing_request = request;
    message.which_payload = Pairing_PairingMessage_pairing_request_tag;

    message.status = Pairing_PairingMessage_Status::Pairing_PairingMessage_Status_STATUS_OK;
    message.protocol_version = 2;

    return encodePairingMessage(message);
}

/*
uint8_t *PairingMessageHelper::createPairingOption()
{
    Pairing_PairingMessage message = Pairing_PairingMessage_init_default;
    Pairing_PairingOption option = Pairing_PairingOption_init_default;
    option.preferred_role = Pairing_RoleType_ROLE_TYPE_INPUT;
    Pairing_PairingEncoding encodings[] = {PAIRING_PAIRING_ENCODING_INIT};
    encodings[0].type = PAIRING_PAIRING_ENCODING_ENCODING_TYPE_ENCODING_TYPE_HEXADECIMAL;
    encodings[0].symbol_length = 6;
    Pairing__PairingEncoding *array = encodings;
    option.input_encodings = &array;
    option.n_input_encodings = 1;

    message.pairing_option = &option;
    message.status = PAIRING_PAIRING_MESSAGE_STATUS_STATUS_OK;
    message.protocol_version = 2;

    uint8_t *buffer = encodePairingMessage(message);
    return buffer;
}

uint8_t *PairingMessageHelper::createPairingConfiguration()
{
    Pairing__PairingMessage message = PAIRING_PAIRING_MESSAGE_INIT;
    Pairing__PairingConfiguration configuration = PAIRING_PAIRING_CONFIGURATION_INIT;
    message.pairing_configuration = &configuration;

    message.pairing_configuration->client_role = PAIRING_ROLE_TYPE_ROLE_TYPE_INPUT;
    Pairing__PairingEncoding encoding = PAIRING__PAIRING_ENCODING_INIT;
    message.pairing_configuration->encoding = &encoding;

    message.pairing_configuration->encoding->type = PAIRING_PAIRING_ENCODING_ENCODING_TYPE_ENCODING_TYPE_HEXADECIMAL;
    message.pairing_configuration->encoding->symbol_length = 6;

    message.status = PAIRING_PAIRING_MESSAGE_STATUS_STATUS_OK;
    message.protocol_version = 2;
    return encodePairingMessage(message);
}

uint8_t *PairingMessageManager::createPairingSecret(const uint8_t *secret)
{
    Pairing__PairingMessage message = PAIRING__PAIRING_MESSAGE__INIT;
    Pairing__PairingSecret secretMessage = PAIRING__PAIRING_SECRET__INIT;
    message.pairing_secret = &secretMessage;

    message.pairing_secret->secret.data = (uint8_t *)secret;
    message.pairing_secret->secret.len = 32;

    message.status = PAIRING__PAIRING_MESSAGE__STATUS__STATUS_OK;
    message.protocol_version = 2;
    return encodePairingMessage(message);
}

*/