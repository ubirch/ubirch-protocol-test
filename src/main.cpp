#include <ubirch/ubirch_protocol.h>
#include <source/edebug.h>
#include <nacl/armnacl.h>
#include <mbed_mem_trace.h>

static const unsigned char private_key[crypto_sign_SECRETKEYBYTES] = {
        0x69, 0x09, 0xcb, 0x3d, 0xff, 0x94, 0x43, 0x26, 0xed, 0x98, 0x72, 0x60,
        0x1e, 0xb3, 0x3c, 0xb2, 0x2d, 0x9e, 0x20, 0xdb, 0xbb, 0xe8, 0x17, 0x34,
        0x1c, 0x81, 0x33, 0x53, 0xda, 0xc9, 0xef, 0xbb, 0x7c, 0x76, 0xc4, 0x7c,
        0x51, 0x61, 0xd0, 0xa0, 0x3e, 0x7a, 0xe9, 0x87, 0x01, 0x0f, 0x32, 0x4b,
        0x87, 0x5c, 0x23, 0xda, 0x81, 0x31, 0x32, 0xcf, 0x8f, 0xfd, 0xaa, 0x55,
        0x93, 0xe6, 0x3e, 0x6a
};

static const unsigned char UUID[16] = "WHATEVER";

int ed25519_sign(const char *buf, size_t len, unsigned char signature[crypto_sign_BYTES]) {
    crypto_uint16 signedLength;
    unsigned char *signedMessage = new unsigned char[crypto_sign_BYTES + 32];
    crypto_sign(signedMessage, &signedLength, (const unsigned char *) buf, (crypto_uint16) len, private_key);
    memcpy(signature, signedMessage, crypto_sign_BYTES);
    delete[] signedMessage;
    return 0;
}

int main() {
    EDEBUG_SETUP(NULL);
    EDEBUG_PRINTF("ubirch-protocol test\r\n");

#ifdef MBED_MEM_TRACING_ENABLED
    mbed_mem_trace_set_callback(mbed_mem_trace_default_callback);
#endif

    msgpack_sbuffer *sbuf = msgpack_sbuffer_new();
    ubirch_protocol *proto = ubirch_protocol_new(proto_chained, sbuf, msgpack_sbuffer_write, ed25519_sign, UUID);
    msgpack_packer *pk = msgpack_packer_new(proto, ubirch_protocol_write);

    ubirch_protocol_start(proto, pk);
    msgpack_pack_int(pk, 99);
    ubirch_protocol_finish(proto, pk);

    EDEBUG_DUMP("MSG", (uint8_t*) sbuf->data, sbuf->size);

    msgpack_packer_free(pk);
    ubirch_protocol_free(proto);

    while (1);
}
