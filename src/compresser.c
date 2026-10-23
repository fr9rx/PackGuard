#include "compresser.h"

#include <string.h>

#if LZMA_VERSION >= UINT32_C(50060000) && LZMA_VERSION < UINT32_C(50060020)
#error "liblzma 5.6.0 and 5.6.1 are backdoored (CVE-2024-3094); build with 5.4.x or 5.8.x"
#endif

int compressor_init(compressor *c, uint32_t preset, uint32_t dict_size, uint32_t lc)
{
    if (c == NULL)
        return -1;
    memset(c, 0, sizeof *c);

    if (lzma_lzma_preset(&c->options, preset))
        return -1;
    c->options.dict_size = dict_size;
    c->options.lc = lc;

    c->filters[0].id = LZMA_FILTER_LZMA2;
    c->filters[0].options = &c->options;
    c->filters[1].id = LZMA_VLI_UNKNOWN;
    c->filters[1].options = NULL;

    c->stream = (lzma_stream)LZMA_STREAM_INIT;
    if (lzma_raw_encoder(&c->stream, c->filters) != LZMA_OK) {
        lzma_end(&c->stream);
        return -1;
    }
    return 0;
}

/*
 * Pushes len bytes through the encoder, throwing the output into the sink.
 * With LZMA_RUN it returns once all input is consumed; with LZMA_FINISH it
 * returns once the stream is complete. Returns 0 on success, -1 on failure.
 */
static int feed(compressor *c, const unsigned char *data, size_t len, lzma_action action)
{
    c->stream.next_in = data;
    c->stream.avail_in = len;

    for (;;) {
        c->stream.next_out = c->sink;
        c->stream.avail_out = sizeof c->sink;

        lzma_ret ret = lzma_code(&c->stream, action);
        if (action == LZMA_FINISH && ret == LZMA_STREAM_END)
            return 0;
        if (ret != LZMA_OK)
            return -1;
        if (action == LZMA_RUN && c->stream.avail_in == 0)
            return 0;
    }
}

int compressed_size_pair(compressor *c, const unsigned char *a, size_t alen,
                         const unsigned char *b, size_t blen, size_t *out)
{
    if (c == NULL || out == NULL || (a == NULL && alen > 0) || (b == NULL && blen > 0))
        return -1;

    if (lzma_raw_encoder(&c->stream, c->filters) != LZMA_OK)
        return -1;
    if (feed(c, a, alen, LZMA_RUN) != 0 || feed(c, b, blen, LZMA_FINISH) != 0)
        return -1;

    *out = (size_t)c->stream.total_out;
    return 0;
}

int compressed_size(compressor *c, const unsigned char *data, size_t len, size_t *out)
{
    return compressed_size_pair(c, data, len, NULL, 0, out);
}

int compressed_size_given(compressor *c, const unsigned char *dict, size_t dict_len,
                          const unsigned char *data, size_t len, size_t *out)
{
    if (c == NULL || (dict == NULL && dict_len > 0))
        return -1;
    if (dict_len > c->options.dict_size) {
        dict += dict_len - c->options.dict_size;
        dict_len = c->options.dict_size;
    }

    c->options.preset_dict = dict_len > 0 ? dict : NULL;
    c->options.preset_dict_size = (uint32_t)dict_len;
    int rc = compressed_size(c, data, len, out);
    c->options.preset_dict = NULL;
    c->options.preset_dict_size = 0;
    return rc;
}

void compressor_free(compressor *c)
{
    if (c == NULL)
        return;
    lzma_end(&c->stream);
}
