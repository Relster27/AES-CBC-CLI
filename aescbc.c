#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <ctype.h>
#include <getopt.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/random.h>
#include <unistd.h>

/*
TODO:
Further work is to implement the pbkdf2 function to generate a key from a password and salt, and generate a random IV if not provided. For now just exits if no key or IV is provided
*/

/*
Test input:
./aescbc -e -i test.txt -o test.out --bits 256 -key 00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff -iv 00112233445566778899aabbccddeeff

./aescbc -d -i test.out -o test.dec --bits 256 -key 00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff -iv 00112233445566778899aabbccddeeff
*/

#define pr(...) fprintf(stderr, __VA_ARGS__)

static const uint8_t sbox[256] = {
        0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
        0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
        0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
        0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
        0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
        0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
        0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
        0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
        0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
        0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
        0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
        0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
        0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
        0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
        0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
        0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
};

static const uint8_t inv_sbox[256] = {
        0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
        0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
        0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
        0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
        0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
        0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
        0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
        0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
        0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
        0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
        0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
        0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
        0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
        0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
        0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
        0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d
};

enum operation {
        NOT_SPECIFIED = 0,
        ENC,
        DEC
};

typedef struct {
        enum operation op;
        char           *in_file;
        char           *out_file;
        uint16_t       bits;
        uint8_t        key[32];
        uint8_t        iv[16];
} attribute;

typedef struct {
        FILE     *in_fp;
        FILE     *out_fp;
        uint8_t  *in_buf;
        uint8_t  *out_buf;
        uint64_t in_file_sz;     // Size of the input file (-in).
        uint64_t pad_sz;         // Number of padding bytes appended.
        uint64_t block_count;
        uint8_t  rounds;          // AES rounds selected by the key size.
} aes_context;

#define AES_BLOCK_SIZE     (16ul)
#define SLACK   (16ul)

attribute attr = {0};
aes_context ctx = {0};

/* === Functions prototype === */
void parse_args(int argc, char *argv[]);

int hex2bytes(const char *hex, uint8_t *out, size_t out_len);
void print_help(void);
size_t key_expansion(const uint8_t *key, uint16_t bits, uint8_t expanded_key[240]);
void process_files(void);
void setup_buffers(void);

void add_padding(void);
size_t remove_padding(void);
void AES_block_encryption(const uint64_t block, const uint8_t expanded_key[240]);
void AES_block_decryption(const uint64_t block, const uint8_t expanded_key[240]);
void add_round_key(uint8_t *state, const uint8_t *roundkey);
void sub_bytes(uint8_t *state);
void shiftrows(uint8_t *state);
void mix_column(uint8_t *state);
void inv_sub_bytes(uint8_t *state);
void inv_shiftrows(uint8_t *state);
void inv_mix_column(uint8_t *state);
void write_output(size_t output_size);
void print_out_blocks(void);
/* =========================== */

int main(int argc, char *argv[])
{
        if (argc < 2) {
                pr("Usage: %s (-e | -d) -bits <128|192|256> -in <file> -out <file> [OPTIONS]\nOr run: %s --help\n",
                        argv[0], argv[0]);
                exit(EXIT_FAILURE);
        }
        parse_args(argc, argv);

        // -- Expand key once
        uint8_t expanded_key[240] = {0};
        if (key_expansion(attr.key, attr.bits, expanded_key) == 0) {
                pr("Key expansion failed\n");
                exit(EXIT_FAILURE);
        }

        // -- Determine rounds
        switch (attr.bits) {
                case 128: ctx.rounds = 10; break;
                case 192: ctx.rounds = 12; break;
                case 256: ctx.rounds = 14; break;
                default: pr("Invalid AES key size\n"); exit(EXIT_FAILURE);
        }

        switch (attr.op) {
        case ENC: {
                process_files();
                setup_buffers();
                add_padding();

                // -- Block chaining
                const uint8_t *previous = attr.iv;
                for (uint64_t block = 0; block < ctx.block_count; block++) {
                        uint8_t *state = ctx.out_buf + block * AES_BLOCK_SIZE;
                        for (size_t i = 0; i < AES_BLOCK_SIZE; i++) {
                                state[i] ^= previous[i];
                        }
                        AES_block_encryption(block, expanded_key);
                        previous = state;
                }

                write_output((size_t)(ctx.in_file_sz + ctx.pad_sz));
                break;
        }
        case DEC: {
                process_files();
                if (ctx.in_file_sz == 0 || ctx.in_file_sz % AES_BLOCK_SIZE != 0) {
                        pr("Ciphertext must contain a nonzero multiple of 16 bytes\n");
                        exit(EXIT_FAILURE);
                }
                setup_buffers();

                const uint8_t *previous = attr.iv;
                for (uint64_t block = 0; block < ctx.block_count; block++) {
                        uint8_t *state = ctx.out_buf + block * AES_BLOCK_SIZE;
                        AES_block_decryption(block, expanded_key);
                        for (size_t i = 0; i < AES_BLOCK_SIZE; i++) {
                                state[i] ^= previous[i];
                        }
                        previous = ctx.in_buf + block * AES_BLOCK_SIZE;
                }

                write_output(remove_padding());
                break;
        }
        default:
                pr("Invalid operation\n");
                exit(EXIT_FAILURE);
        }

        // -- Cleanups
        if (fclose(ctx.in_fp) != 0) {
                pr("Failed to close input file\n");
                exit(EXIT_FAILURE);
        }
        if (fclose(ctx.out_fp) != 0) {
                pr("Failed to close output file\n");
                exit(EXIT_FAILURE);
        }
        free(ctx.in_buf);
        free(ctx.out_buf);

        return EXIT_SUCCESS;
}

void parse_args(int argc, char *argv[])
{
        if (argc > 1) {
                if (strcmp(argv[1], "-h") == 0 || strcmp(argv[1], "--help") == 0) {
                        print_help();
                        exit(EXIT_SUCCESS);
                }
        }

        struct option long_opts[] = {
                {"encrypt", no_argument,       NULL, 'e'},
                {"decrypt", no_argument,       NULL, 'd'},
                {"in",      required_argument, NULL, 'i'},
                {"out",     required_argument, NULL, 'o'},
                {"bits",    required_argument, NULL, 'b'},
                {"key",     required_argument, NULL, 'k'},
                {"iv",      required_argument, NULL, 'v'},
                {0, 0, 0, 0}
        };

        int opt;
        char *key_hex = NULL;
        char *iv_hex = NULL;
        while ((opt = getopt_long_only(argc, argv, "edi:o:b:k:v:", long_opts, NULL)) != -1) {
                switch (opt) {
                        case 'e':
                                if (attr.op != NOT_SPECIFIED) {
                                        pr("Specify exactly one operation (-e or -d)\n");
                                        exit(EXIT_FAILURE);
                                }
                                attr.op = ENC;
                                break;
                        case 'd':
                                if (attr.op != NOT_SPECIFIED) {
                                        pr("Specify exactly one operation (-e or -d)\n");
                                        exit(EXIT_FAILURE);
                                }
                                attr.op = DEC;
                                break;
                        case 'i':
                                if (optarg[0] == '-') {
                                        pr("Invalid input filename: %s\n", optarg);
                                        exit(EXIT_FAILURE);
                                }
                                attr.in_file = optarg;
                                break;
                        case 'o':
                                if (optarg[0] == '-') {
                                        pr("Invalid output filename: %s\n", optarg);
                                        exit(EXIT_FAILURE);
                                }
                                attr.out_file = optarg;
                                break;
                        case 'b': attr.bits = (uint16_t)strtoul(optarg, NULL, 10); break;
                        case 'k': key_hex = optarg; break;
                        case 'v': iv_hex = optarg; break;
                        default:
                                print_help();
                                exit(EXIT_FAILURE);
                }
        }

        // -- Check if operation is specified
        if (attr.op == NOT_SPECIFIED) {
                pr("Missing operation (-e or -d)\n");
                exit(EXIT_FAILURE);
        }

        // -- Check if bits/key size is valid
        if (attr.bits != 128 && attr.bits != 192 && attr.bits != 256) {
                pr("Invalid AES bits/key size\n");
                exit(EXIT_FAILURE);
        }

        // -- Check if input/output file is specified
        if (!attr.in_file || !attr.out_file) {
                pr("Missing input or output file\n");
                exit(EXIT_FAILURE);
        }

        // -- Check if key and iv are provided
        if (!key_hex || !iv_hex) {
                pr("Please specify a Key and IV (in hex)\n");
                exit(EXIT_FAILURE);
        }

        // -- Check if valid hexes on supplied Key and IV
        // -- Currently, user has to provide a valid hex string with exactly the right length for the key and IV. If not, it will exit with an error
        size_t key_len = attr.bits / 8;
        if (hex2bytes(key_hex, attr.key, key_len) != 0) {
                pr("Invalid Key hex string\n");
                exit(EXIT_FAILURE);
        }
        if (hex2bytes(iv_hex, attr.iv, 16) != 0) {
                pr("Invalid IV hex string\n");
                exit(EXIT_FAILURE);
        }
}

int hex2bytes(const char *hex, uint8_t *out, size_t out_len)
{
        if (strlen(hex) != out_len * 2)
                return -1;

        for (size_t i = 0; i < out_len; i++) {
                unsigned int byte;

                if (!isxdigit((unsigned char)hex[i * 2]) ||
                        !isxdigit((unsigned char)hex[i * 2 + 1]))
                        return -1;

                if (sscanf(hex + i * 2, "%2x", &byte) != 1)
                        return -1;

                out[i] = (uint8_t)byte;
        }

        return 0;
}

void print_help(void)
{
        pr("NAME\n");
        pr("\taescbc - AES-CBC encryption/decryption utility\n\n");

        pr("DESCRIPTION\n");
        pr("\tA CLI AES-CBC encryption/decryption tool. Supports AES-128, AES-192, and AES-256.\n\n");
        
        pr("USAGE\n");
        pr("\t./aescbc (-e | -d) -bits <128|192|256> -in <file> -out <file> [OPTIONS]\n\n");

        pr("OPTIONS\n");
        pr("\t-h,--help\t\t Display this message\n");
        pr("\t-e\t\t Encrypt\n");
        pr("\t-d\t\t Decrypt\n");
        pr("\t-in\t\t Input file\n");
        pr("\t-out\t\t Output file\n");
        pr("\t-bits val\t Number of bits (128, 192, or 256)\n");
        pr("\t-key val\t Key in hex\n");
        pr("\t-iv val\t\t IV in hex\n\n");

        pr("EXAMPLES\n");
        pr("\t./aescbc -e -bits 128 -in plain.txt -out cipher.bin -key <hex> -iv <hex>\n");
        pr("\t./aescbc -d -bits 256 -in cipher.bin -out plain.txt -key <hex> -iv <hex>\n");
}

static uint8_t xtime(uint8_t value)
{
        return (uint8_t)((value << 1) ^ ((value & 0x80) ? 0x1b : 0));
}

static uint8_t gf_multiply(uint8_t value, uint8_t factor)
{
        uint8_t result = 0;
        for (size_t bit = 0; bit < 8; bit++) {
                if (factor & 1) {
                        result ^= value;
                }
                value = xtime(value);
                factor >>= 1;
        }
        return result;
}

/*
        Caller provides 240 output bytes (the maximum AES key schedule size).
        Returns 176, 208, or 240 bytes; returns 0 for invalid arguments.
        Round r uses expanded_key + r * 16. This does not modify the input key.
*/
size_t key_expansion(const uint8_t *key, uint16_t bits, uint8_t expanded_key[240])
{
        if (!key || !expanded_key || (bits != 128 && bits != 192 && bits != 256)) {
                return 0;
        }

        size_t nk = bits / 32;
        size_t rounds = nk + 6;
        size_t total_words = 4 * (rounds + 1);
        uint8_t rcon = 0x01;

        memmove(expanded_key, key, nk * 4);
        for (size_t i = nk; i < total_words; i++) {
                uint8_t temp[4];
                memcpy(temp, expanded_key + (i - 1) * 4, sizeof(temp));

                if (i % nk == 0) {
                        // RotWord: [a,b,c,d] -> [b,c,d,a]
                        uint8_t first = temp[0];
                        temp[0] = temp[1];
                        temp[1] = temp[2];
                        temp[2] = temp[3];
                        temp[3] = first;

                        for (size_t j = 0; j < 4; j++) {
                                temp[j] = sbox[temp[j]];
                        }
                        temp[0] ^= rcon;
                        rcon = xtime(rcon);
                } else if (nk == 8 && i % nk == 4) {
                        for (size_t j = 0; j < 4; j++) {
                                temp[j] = sbox[temp[j]];
                        }
                }

                for (size_t j = 0; j < 4; j++) {
                        expanded_key[i * 4 + j] = expanded_key[(i - nk) * 4 + j] ^ temp[j];
                }
        }

        return total_words * 4;
}

void process_files(void)
{
        ctx.in_fp = fopen(attr.in_file, "rb");
        if (!ctx.in_fp) {
                pr("Failed to open input file: %s\n", attr.in_file);
                exit(EXIT_FAILURE);
        }

        // -- Get the file size
        int seek_end = fseek(ctx.in_fp, 0, SEEK_END);
        if (seek_end != 0) {
                pr("Failed to seek to end of input file\n");
                exit(EXIT_FAILURE);
        }

        long file_size = ftell(ctx.in_fp);
        if (file_size < 0 || (uintmax_t)file_size > SIZE_MAX - AES_BLOCK_SIZE - SLACK) {
                pr("Invalid or unsupported input file size\n");
                fclose(ctx.in_fp);
                exit(EXIT_FAILURE);
        }
        ctx.in_file_sz = (uint64_t)file_size;
        rewind(ctx.in_fp);
}

void setup_buffers(void)
{
        // -- Move input file content into a buffer
        ctx.in_buf = calloc(ctx.in_file_sz ? ctx.in_file_sz : 1, sizeof(uint8_t));
        if (!ctx.in_buf) {
                pr("Failed to alloc buffer for input file\n");
                exit(EXIT_FAILURE);
        }

        uint64_t n = fread(ctx.in_buf, sizeof(uint8_t), ctx.in_file_sz, ctx.in_fp);
        if (n != ctx.in_file_sz) {
                pr("Failed to read from file into input buffer\n");
                exit(EXIT_FAILURE);
        }

        // -- Shared setup copies
        ctx.pad_sz = 0;
        ctx.block_count = ctx.in_file_sz / AES_BLOCK_SIZE;

        // -- Reserve room for optional encryption padding and future salt data.
        ctx.out_buf = calloc((ctx.in_file_sz + AES_BLOCK_SIZE + SLACK), sizeof(uint8_t));
        if (!ctx.out_buf) {
                pr("Failed to alloc output buffer\n");
                exit(EXIT_FAILURE);
        }

        memcpy(ctx.out_buf, ctx.in_buf, ctx.in_file_sz);
}

void add_padding(void)
{
        // -- Encryption only: PKCS#7 adds a full block for aligned input too
        ctx.pad_sz = AES_BLOCK_SIZE - (ctx.in_file_sz % AES_BLOCK_SIZE);
        memset(ctx.out_buf + ctx.in_file_sz, (uint8_t)ctx.pad_sz, ctx.pad_sz);
        ctx.block_count = (ctx.in_file_sz + ctx.pad_sz) / AES_BLOCK_SIZE;
}

size_t remove_padding(void)
{
        // -- Decryption only: validate all PKCS#7 bytes, then return the data length.
        if (ctx.in_file_sz == 0 || ctx.in_file_sz % AES_BLOCK_SIZE != 0) {
                pr("Invalid ciphertext length\n");
                exit(EXIT_FAILURE);
        }
        size_t total = (size_t)ctx.in_file_sz;
        uint8_t padding = ctx.out_buf[total - 1];
        if (padding == 0 || padding > AES_BLOCK_SIZE) {
                pr("Invalid PKCS#7 padding\n");
                exit(EXIT_FAILURE);
        }
        for (size_t i = 0; i < padding; i++) {
                if (ctx.out_buf[total - 1 - i] != padding) {
                        pr("Invalid PKCS#7 padding\n");
                        exit(EXIT_FAILURE);
                }
        }
        return total - padding;
}

void AES_block_encryption(const uint64_t block, const uint8_t expanded_key[240])
{
        uint8_t *state = ctx.out_buf + block * AES_BLOCK_SIZE;
        add_round_key(state, expanded_key);

        for (uint8_t r = 1; r < ctx.rounds; r++) {
                sub_bytes(state);
                shiftrows(state);
                mix_column(state);
                add_round_key(state, expanded_key + r * AES_BLOCK_SIZE);
        }

        sub_bytes(state);
        shiftrows(state);
        add_round_key(state, expanded_key + ctx.rounds * AES_BLOCK_SIZE);
}

void AES_block_decryption(const uint64_t block, const uint8_t expanded_key[240])
{
        uint8_t *state = ctx.out_buf + block * AES_BLOCK_SIZE;

        add_round_key(state, expanded_key + ctx.rounds * AES_BLOCK_SIZE);
        for (uint8_t r = ctx.rounds - 1; r > 0; r--) {
                inv_shiftrows(state);
                inv_sub_bytes(state);
                add_round_key(state, expanded_key + r * AES_BLOCK_SIZE);
                inv_mix_column(state);
        }
        inv_shiftrows(state);
        inv_sub_bytes(state);
        add_round_key(state, expanded_key);
}

void add_round_key(uint8_t *state, const uint8_t *roundkey)
{
        for (size_t i = 0; i < AES_BLOCK_SIZE; i++) {
                state[i] ^= roundkey[i];
        }
}

void sub_bytes(uint8_t *state)
{
        for (size_t i = 0; i < AES_BLOCK_SIZE; i++) {
                state[i] = sbox[state[i]];
        }
}

void shiftrows(uint8_t *state)
{
        uint8_t tmp;
        uint8_t *block_start = state;
            
        // Row 1: 1-byte left circular shift
        tmp = block_start[1];
        block_start[1] = block_start[5];
        block_start[5] = block_start[9];
        block_start[9] = block_start[13];
        block_start[13] = tmp;
            
        // Row 2: 2-byte left circular shift
        tmp = block_start[2];
        block_start[2] = block_start[10];
        block_start[10] = tmp;
        tmp = block_start[6];
        block_start[6] = block_start[14];
        block_start[14] = tmp;
            
        // Row 3: 3-byte left circular shift
        tmp = block_start[3];
        block_start[3] = block_start[15];
        block_start[15] = block_start[11];
        block_start[11] = block_start[7];
        block_start[7] = tmp;
}

void mix_column(uint8_t *state)
{
        for (size_t col = 0; col < 4; col++) {
                uint8_t *column = state + col * 4;
                uint8_t a = column[0], b = column[1];
                uint8_t c = column[2], d = column[3];

                column[0] = xtime(a) ^ (xtime(b) ^ b) ^ c ^ d;
                column[1] = a ^ xtime(b) ^ (xtime(c) ^ c) ^ d;
                column[2] = a ^ b ^ xtime(c) ^ (xtime(d) ^ d);
                column[3] = (xtime(a) ^ a) ^ b ^ c ^ xtime(d);
        }
}

void inv_sub_bytes(uint8_t *state)
{
        for (size_t i = 0; i < AES_BLOCK_SIZE; i++) {
                state[i] = inv_sbox[state[i]];
        }
}

void inv_shiftrows(uint8_t *state)
{
        for (size_t row = 1; row < 4; row++) {
                uint8_t original[4];
                for (size_t col = 0; col < 4; col++) {
                        original[col] = state[col * 4 + row];
                }
                for (size_t col = 0; col < 4; col++) {
                        state[col * 4 + row] = original[(col + 4 - row) % 4];
                }
        }
}

void inv_mix_column(uint8_t *state)
{
        for (size_t col = 0; col < 4; col++) {
                uint8_t *column = state + col * 4;
                uint8_t a = column[0], b = column[1];
                uint8_t c = column[2], d = column[3];

                column[0] = gf_multiply(a, 0x0e) ^ gf_multiply(b, 0x0b) ^ gf_multiply(c, 0x0d) ^ gf_multiply(d, 0x09);
                column[1] = gf_multiply(a, 0x09) ^ gf_multiply(b, 0x0e) ^ gf_multiply(c, 0x0b) ^ gf_multiply(d, 0x0d);
                column[2] = gf_multiply(a, 0x0d) ^ gf_multiply(b, 0x09) ^ gf_multiply(c, 0x0e) ^ gf_multiply(d, 0x0b);
                column[3] = gf_multiply(a, 0x0b) ^ gf_multiply(b, 0x0d) ^ gf_multiply(c, 0x09) ^ gf_multiply(d, 0x0e);
        }
}

void write_output(size_t output_size)
{
        ctx.out_fp = fopen(attr.out_file, "wb");
        if (!ctx.out_fp) {
                pr("Failed to open output file: %s\n", attr.out_file);
                exit(EXIT_FAILURE);
        }

        // -- Caller supplies the ciphertext size or the unpadded plaintext size
        if (fwrite(ctx.out_buf, 1, output_size, ctx.out_fp) != output_size) {
                pr("Failed to write output\n");
                exit(EXIT_FAILURE);
        }
}

// Helper
void print_out_blocks(void)
{
        if (!ctx.out_buf) {
                pr("Output buffer is not initialized\n");
                return;
        }

        ctx.block_count = (ctx.in_file_sz + ctx.pad_sz) / AES_BLOCK_SIZE;
        for (uint64_t block = 0; block < ctx.block_count; block++) {
                pr("Block %" PRIu64 " (offset %" PRIu64 "):\n", block + 1, block * AES_BLOCK_SIZE);
                for (size_t row = 0; row < 4; row++) {
                        for (size_t col = 0; col < 4; col++) {
                                pr("%02x%s", (unsigned int)ctx.out_buf[block * AES_BLOCK_SIZE + col * 4 + row],
                                        col == 3 ? "\n" : " ");
                        }
                }
                pr("\n");
        }
}
