#include <stdio.h>
#include <stdlib.h>
#include <secp256k1.h>

int main() {
    secp256k1_context *context = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    unsigned char private_key[32];
    unsigned char public_key[33];
    size_t public_key_len = 33;

    // Generate a random private key (32 bytes)
    FILE *frand = fopen("/dev/urandom", "rb");
    fread(private_key, 32, 1, frand);
    fclose(frand);

    // Verify the private key is valid
    if (!secp256k1_ec_seckey_verify(context, private_key)) {
        printf("Invalid private key\n");
        return 1;
    }

    // Compute the public key from the private key
    secp256k1_pubkey pubkey;
    if (!secp256k1_ec_pubkey_create(context, &pubkey, private_key)) {
        printf("Public key creation failed\n");
        return 1;
    }

    // Serialize the public key in compressed format
    secp256k1_ec_pubkey_serialize(context, public_key, &public_key_len, &pubkey, SECP256K1_EC_COMPRESSED);

    // Output the private and public keys
    printf("Private Key: ");
    for (int i = 0; i < 32; i++) {
        printf("%02x", private_key[i]);
    }
    printf("\n");

    printf("Public Key: ");
    for (size_t i = 0; i < public_key_len; i++) {
        printf("%02x", public_key[i]);
    }
    printf("\n");

    // Clean up
    secp256k1_context_destroy(context);
    return 0;
}
