#ifndef PACKGUARD_COMPRESSER_H
#define PACKGUARD_COMPRESSER_H

#include <lzma.h>
#include <stddef.h>
#include <stdint.h>

#define COMPRESS_PRESET    6u
#define COMPRESS_DICT_SIZE (1u << 20)
#define COMPRESS_LC        3u
#define COMPRESS_SINK_SIZE (16u * 1024u)

/* A reusable raw LZMA2 encoder that counts compressed bytes instead of keeping them. */
typedef struct {
    lzma_options_lzma options;
    lzma_filter filters[2];
    lzma_stream stream;
    unsigned char sink[COMPRESS_SINK_SIZE];
} compressor;

/*
 * Sets up c as a raw LZMA2 encoder (no .xz container or headers) starting
 * from the given preset, then overriding the dictionary size and lc.
 * Use COMPRESS_PRESET, COMPRESS_DICT_SIZE and COMPRESS_LC for the README's
 * v1 settings: preset 6 (extreme off), 1 MiB dictionary, lc = 3.
 * The encoder's memory is allocated once here and reused by every call.
 *
 * Returns 0 on success, -1 if the settings are invalid or memory runs out.
 */
int compressor_init(compressor *c, uint32_t preset, uint32_t dict_size, uint32_t lc);

/*
 * Compresses len bytes of data and stores the compressed size in *out.
 * This is C(x) in the NCD formula.
 *
 * Returns 0 on success, -1 on failure.
 */
int compressed_size(compressor *c, const unsigned char *data, size_t len, size_t *out);

/*
 * Compresses a followed by b as one stream, without copying them together,
 * and stores the compressed size in *out. This is C(xy) in the NCD formula.
 * The result depends on order: C(ab) and C(ba) can differ.
 *
 * Returns 0 on success, -1 on failure.
 */
int compressed_size_pair(compressor *c, const unsigned char *a, size_t alen,
                         const unsigned char *b, size_t blen, size_t *out);

/*
 * Compresses data with dict pre-loaded into the encoder as a preset
 * dictionary and stores the compressed size in *out. Only data is compressed,
 * so this is C(y|x), a cheaper estimate of C(xy) - C(x) with x = dict and
 * y = data. With C(x) cached per reference, C(x) + C(y|x) stands in for C(xy)
 * at a fraction of the cost. Only the last dict_size bytes of dict are used.
 *
 * Returns 0 on success, -1 on failure.
 */
int compressed_size_given(compressor *c, const unsigned char *dict, size_t dict_len,
                          const unsigned char *data, size_t len, size_t *out);

/* Releases the encoder memory held by c. */
void compressor_free(compressor *c);

#endif
