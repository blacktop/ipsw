#include "lzraven.h"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define RAVEN_PROBABILITY_SCALE UINT32_C(16384)
#define RAVEN_BLOCK_SIZE UINT32_C(524288)
#define RAVEN_WINDOW_SIZE UINT32_C(8388608)
#define RAVEN_LITERAL_TAIL_SIZE UINT32_C(32)
#define RAVEN_MIN_COMPRESSED_SIZE UINT32_C(64)
#define RAVEN_MAX_INPUT_SIZE UINT32_C(0xe0000000)
#define RAVEN_LZ4_HASH_SIZE UINT32_C(4096)
#define RAVEN_LZ4_BLOCK_SIZE UINT32_C(65536)
#define RAVEN_PARSE_LIMIT UINT32_C(4096)
#define RAVEN_NICE_LENGTH UINT32_C(64)
#define RAVEN_REPEAT_LIMIT UINT32_C(348)
#define RAVEN_NEW_MATCH_LIMIT UINT32_C(332)
#define RAVEN_DECODE_SCRATCH_SIZE UINT32_C(35424)
#define RAVEN_DECODE_FLAGS_OFFSET UINT32_C(18976)

enum raven_command {
    RAVEN_COMMAND_REPEAT_BYTE = 7,
    RAVEN_COMMAND_REPEAT_SHORT = 8,
    RAVEN_COMMAND_REPEAT_LONG = 12,
    RAVEN_COMMAND_LITERAL = 16,
    RAVEN_COMMAND_COMPOSITE = 17,
    RAVEN_COMMAND_UNREACHED = 18
};

enum raven_cdf_bank {
    RAVEN_COMMANDS = 0,
    RAVEN_MATCHED_HIGH = 14,
    RAVEN_MATCHED_LOW = 206,
    RAVEN_LITERAL_HIGH = 254,
    RAVEN_LITERAL_LOW = 270,
    RAVEN_SHORT_LENGTH = 526,
    RAVEN_LONG_LENGTH = 530,
    RAVEN_LENGTH_EXTRA = 534,
    RAVEN_NEW_LENGTH = 540,
    RAVEN_NEW_EXTRA = 568,
    RAVEN_DISTANCE = 574
};

struct raven_model {
    uint16_t binary_probability[14][4];
    uint16_t cdf[588][16];
    uint32_t recent_distances[4];
    uint32_t previous_block_size;
    uint8_t state;
};

struct raven_ans_reader {
    const uint8_t *data;
    size_t word_count;
    size_t word_index;
    uint64_t states[8];
    uint32_t lane_index;
};

struct raven_match {
    uint32_t command;
    uint32_t length;
    uint32_t distance;
    uint32_t recent_index;
};

struct raven_lz4_entry {
    uint32_t position;
    uint32_t word;
};

struct raven_match_candidate {
    uint32_t distance;
    uint32_t length;
};

struct raven_hash_pipeline {

    uint32_t prefix2;
    uint32_t prefix3;
    uint32_t prefix4;
};

struct raven_match_finder {
    const uint8_t *input;
    uint32_t limit;
    uint32_t next_position;
    uint32_t (*children)[2];
    uint32_t window_mask;
    uint16_t hash2[8192];
    uint16_t hash3[65536];
    uint32_t hash4[1048576];
    struct raven_match_candidate matches[RAVEN_NEW_MATCH_LIMIT];
    uint32_t match_count;
    struct raven_hash_pipeline pipeline[4];
    uint16_t depth;
    uint16_t nice_length;
};

struct raven_price_cache {

    uint16_t recent[4][64];
    uint16_t new_lengths[7][4][64];
};

struct raven_parse_node {
    uint32_t price;
    uint32_t argument;
    uint16_t length;
    uint8_t command;
    uint8_t first_command;
    uint16_t literal_count;
    uint16_t repeat_length;
    uint32_t recent_distances[4];
    uint8_t state;
};

struct raven_parser {
    struct raven_parse_node nodes[RAVEN_PARSE_LIMIT + 1];
    uint32_t cursor;
    uint32_t end;
};

struct raven_bit_writer {
    uint8_t *data;
    size_t cursor;
    int failed;
};

struct raven_entropy_event {
    uint16_t start;
    uint16_t frequency;
    uint32_t value;
};

struct raven_event_buffer {
    struct raven_entropy_event *events;
    size_t count;
    size_t capacity;
    int failed;
};

struct raven_encoder {
    struct raven_model model;
    struct raven_price_cache prices;
    struct raven_parser parser;
    struct raven_match_finder finder;
    struct raven_lz4_entry trial_table[RAVEN_LZ4_HASH_SIZE];
};

static const uint8_t raven_literal_states[14] = {0, 0, 0, 2, 3, 1, 5, 1, 7, 4, 6, 8, 6, 8};
static const uint8_t raven_literal_contexts[14] = {4, 3, 3, 2, 1, 2, 1, 2, 1, 0, 0, 0, 0, 0};

static const uint16_t raven_cost_lut[512] = {
    10240, 8616, 7862, 7365, 6993, 6697, 6450, 6239, 6054, 5890, 5742, 5607, 5484, 5370, 5265, 5166,
    5074,  4987, 4905, 4827, 4753, 4683, 4616, 4552, 4490, 4431, 4374, 4319, 4267, 4216, 4166, 4119,
    4073,  4028, 3984, 3942, 3901, 3861, 3822, 3784, 3747, 3711, 3676, 3642, 3608, 3576, 3543, 3512,
    3481,  3451, 3421, 3393, 3364, 3336, 3309, 3282, 3256, 3230, 3204, 3179, 3155, 3130, 3107, 3083,
    3060,  3037, 3015, 2993, 2971, 2950, 2929, 2908, 2887, 2867, 2847, 2827, 2808, 2789, 2770, 2751,
    2733,  2714, 2696, 2679, 2661, 2644, 2626, 2609, 2593, 2576, 2560, 2543, 2527, 2511, 2496, 2480,
    2465,  2450, 2435, 2420, 2405, 2390, 2376, 2361, 2347, 2333, 2319, 2305, 2292, 2278, 2265, 2251,
    2238,  2225, 2212, 2199, 2187, 2174, 2161, 2149, 2137, 2124, 2112, 2100, 2088, 2077, 2065, 2053,
    2042,  2030, 2019, 2008, 1996, 1985, 1974, 1963, 1953, 1942, 1931, 1920, 1910, 1899, 1889, 1879,
    1868,  1858, 1848, 1838, 1828, 1818, 1808, 1798, 1789, 1779, 1770, 1760, 1751, 1741, 1732, 1722,
    1713,  1704, 1695, 1686, 1677, 1668, 1659, 1650, 1641, 1633, 1624, 1615, 1607, 1598, 1590, 1581,
    1573,  1565, 1556, 1548, 1540, 1532, 1523, 1515, 1507, 1499, 1491, 1484, 1476, 1468, 1460, 1452,
    1445,  1437, 1429, 1422, 1414, 1407, 1399, 1392, 1385, 1377, 1370, 1363, 1355, 1348, 1341, 1334,
    1327,  1320, 1313, 1306, 1299, 1292, 1285, 1278, 1271, 1264, 1257, 1251, 1244, 1237, 1231, 1224,
    1217,  1211, 1204, 1198, 1191, 1185, 1179, 1172, 1166, 1159, 1153, 1147, 1141, 1134, 1128, 1122,
    1116,  1110, 1104, 1097, 1091, 1085, 1079, 1073, 1067, 1061, 1056, 1050, 1044, 1038, 1032, 1026,
    1021,  1015, 1009, 1003, 998,  992,  986,  981,  975,  970,  964,  959,  953,  948,  942,  937,
    931,   926,  920,  915,  910,  904,  899,  894,  888,  883,  878,  873,  868,  862,  857,  852,
    847,   842,  837,  832,  827,  822,  817,  812,  807,  802,  797,  792,  787,  782,  777,  772,
    767,   762,  758,  753,  748,  743,  738,  734,  729,  724,  719,  715,  710,  705,  701,  696,
    692,   687,  682,  678,  673,  669,  664,  660,  655,  651,  646,  642,  637,  633,  628,  624,
    620,   615,  611,  606,  602,  598,  593,  589,  585,  581,  576,  572,  568,  564,  559,  555,
    551,   547,  543,  538,  534,  530,  526,  522,  518,  514,  510,  506,  501,  497,  493,  489,
    485,   481,  477,  473,  469,  465,  462,  458,  454,  450,  446,  442,  438,  434,  430,  426,
    423,   419,  415,  411,  407,  403,  400,  396,  392,  388,  385,  381,  377,  373,  370,  366,
    362,   359,  355,  351,  348,  344,  340,  337,  333,  330,  326,  322,  319,  315,  312,  308,
    304,   301,  297,  294,  290,  287,  283,  280,  276,  273,  269,  266,  263,  259,  256,  252,
    249,   245,  242,  239,  235,  232,  228,  225,  222,  218,  215,  212,  208,  205,  202,  198,
    195,   192,  189,  185,  182,  179,  175,  172,  169,  166,  163,  159,  156,  153,  150,  147,
    143,   140,  137,  134,  131,  128,  124,  121,  118,  115,  112,  109,  106,  103,  99,   96,
    93,    90,   87,   84,   81,   78,   75,   72,   69,   66,   63,   60,   57,   54,   51,   48,
    45,    42,   39,   36,   33,   30,   27,   24,   21,   18,   15,   13,   10,   7,    4,    1,
};

static uint16_t raven_load16(const uint8_t *bytes)
{
    return (uint16_t)((uint32_t)bytes[0] | (uint32_t)bytes[1] << 8);
}

static uint32_t raven_load32(const uint8_t *bytes)
{
    return (uint32_t)bytes[0] | (uint32_t)bytes[1] << 8 | (uint32_t)bytes[2] << 16 | (uint32_t)bytes[3] << 24;
}

static void raven_store16(uint8_t *bytes, uint16_t value)
{
    bytes[0] = (uint8_t)value;
    bytes[1] = (uint8_t)(value >> 8);
}

static void raven_store32(uint8_t *bytes, uint32_t value)
{
    uint32_t i;

    for (i = 0; i < 4; ++i) {
        bytes[i] = (uint8_t)(value >> (8 * i));
    }
}

static uint32_t raven_log2(uint32_t value)
{
    uint32_t bits = 0;

    while (value >>= 1) {
        ++bits;
    }
    return bits;
}

static inline int32_t raven_floor_shift(int32_t value, uint32_t rate)
{

    return value >= 0 ? value / (INT32_C(1) << rate) : -((-value + (INT32_C(1) << rate) - 1) / (INT32_C(1) << rate));
}

static inline void raven_model_update_cdf(uint16_t cdf[16], uint32_t symbol, uint32_t rate)
{
    uint32_t i;

    for (i = 0; i < 16; ++i) {
        int32_t target = (int32_t)(32 * (i + 1));

        if (i >= symbol) {
            target += (int32_t)(RAVEN_PROBABILITY_SCALE - 512 + (UINT32_C(1) << rate) - 1);
        }
        cdf[i] = (uint16_t)(cdf[i] + raven_floor_shift(target - cdf[i], rate));
    }
}

static inline void raven_model_update_binary(uint16_t *probability, uint32_t bit)
{
    uint32_t threshold = *probability;

    *probability = (uint16_t)(bit ? threshold - (threshold >> 5) : threshold + ((RAVEN_PROBABILITY_SCALE - threshold) >> 5));
}

static inline uint32_t raven_model_next_state(uint32_t state, uint32_t command)
{
    if (command == RAVEN_COMMAND_LITERAL) {
        return raven_literal_states[state];
    }
    if (command < RAVEN_COMMAND_REPEAT_BYTE) {
        return state < 9 ? 11 : 13;
    }
    if (command == RAVEN_COMMAND_REPEAT_BYTE) {
        return state < 9 ? 9 : 12;
    }
    return state < 9 ? 10 : 12;
}

static inline uint32_t raven_model_literal_context(uint32_t state)
{
    return raven_literal_contexts[state];
}

static inline void raven_model_init(struct raven_model *model)
{
    uint32_t row;
    uint32_t i;

    memset(model, 0, sizeof(*model));
    for (row = 0; row < 14; ++row) {
        for (i = 0; i < 4; ++i) {
            model->binary_probability[row][i] = 8192;
        }
    }
    for (row = 0; row < 588; ++row) {
        for (i = 0; i < 16; ++i) {
            model->cdf[row][i] = (uint16_t)((i + 1) * 1024);
        }
    }
    for (row = 0; row < 14; ++row) {
        uint32_t sum = 0;

        for (i = 0; i < 16; ++i) {
            uint32_t heavy = row < 9 ? (i == 0 || i == 7 || i == 8) : i < 3;

            sum += heavy ? 17 : 1;
            model->cdf[row][i] = (uint16_t)(sum * 256);
        }
    }
    for (i = 0; i < 4; ++i) {
        model->recent_distances[i] = 1;
    }
}

static uint32_t raven_ans_read_word(struct raven_ans_reader *reader)
{
    size_t index = reader->word_index++;

    if (index >= reader->word_count) {

        return 0;
    }
    return raven_load32(reader->data + 4 * index);
}

static uint64_t raven_ans_normalize(struct raven_ans_reader *reader, uint64_t value)
{
    if (value < (UINT64_C(1) << 32)) {
        value = (value << 32) | raven_ans_read_word(reader);
    }
    return value;
}

static void raven_ans_reader_init(struct raven_ans_reader *reader, const uint8_t *data, size_t size)
{
    uint64_t header;
    uint32_t lane;

    memset(reader, 0, sizeof(*reader));
    reader->data = data;
    reader->word_count = size / 4;

    header = (uint64_t)raven_ans_read_word(reader) << 32;
    header |= raven_ans_read_word(reader);
    for (lane = 1; lane < 8; ++lane) {
        uint32_t low;
        uint32_t high;
        uint32_t width;

        header = raven_ans_normalize(reader, header);
        low = (uint32_t)header;
        header = (header & UINT64_C(0xffffffff00000000)) | raven_ans_read_word(reader);
        width = (uint32_t)header & 31;
        header >>= 5;
        if (width) {
            header = raven_ans_normalize(reader, header);
        }
        high = (UINT32_C(1) << width) | ((uint32_t)header & ((UINT32_C(1) << width) - 1));
        header >>= width;
        reader->states[lane] = (uint64_t)high << 32 | low;
    }
    reader->states[0] = header;
}

static uint32_t raven_ans_read_bits(struct raven_ans_reader *reader, uint32_t count)
{
    uint32_t lane = reader->lane_index++ & 7;
    uint64_t value = raven_ans_normalize(reader, reader->states[lane]);
    uint32_t result = (uint32_t)value & ((UINT32_C(1) << count) - 1);

    reader->states[lane] = value >> count;
    return result;
}

static uint32_t raven_ans_read_symbol(struct raven_ans_reader *reader, struct raven_model *model, uint32_t index, uint32_t rate)
{
    uint32_t lane = reader->lane_index++ & 7;
    uint32_t symbol = 0;
    uint32_t lower;
    uint32_t frequency;
    uint64_t value = raven_ans_normalize(reader, reader->states[lane]);
    uint32_t slot = (uint32_t)value & (RAVEN_PROBABILITY_SCALE - 1);
    uint16_t *cdf = model->cdf[index];

    while (symbol < 15 && slot >= cdf[symbol]) {
        ++symbol;
    }
    lower = symbol ? cdf[symbol - 1] : 0;
    frequency = cdf[symbol] - lower;
    reader->states[lane] = (value >> 14) * frequency + slot - lower;
    raven_model_update_cdf(cdf, symbol, rate);
    return symbol;
}

static uint32_t raven_ans_read_binary(struct raven_ans_reader *reader, uint16_t *probability)
{
    uint32_t lane = reader->lane_index++ & 7;
    uint64_t value = raven_ans_normalize(reader, reader->states[lane]);
    uint32_t slot = (uint32_t)value & (RAVEN_PROBABILITY_SCALE - 1);
    uint32_t bit = slot >= *probability;
    uint32_t lower = bit ? *probability : 0;
    uint32_t frequency = bit ? RAVEN_PROBABILITY_SCALE - *probability : *probability;

    reader->states[lane] = (value >> 14) * frequency + slot - lower;
    raven_model_update_binary(probability, bit);
    return bit;
}

static uint32_t raven_decode_long_length(struct raven_ans_reader *reader, struct raven_model *model, uint32_t primary, uint32_t extension, uint32_t position)
{
    uint32_t value = raven_ans_read_symbol(reader, model, primary, 6);

    if (value < 10) {
        return value;
    }
    if (value == 10) {
        return 10 + raven_ans_read_symbol(reader, model, extension + 4, 6);
    }
    if (value == 15) {
        return 330;
    }
    if (value == 14) {
        value += raven_ans_read_symbol(reader, model, extension + 5, 6);
    }
    return 16 * value + raven_ans_read_symbol(reader, model, extension + position, 6) - 150;
}

static void raven_decode_literal(struct raven_ans_reader *reader, struct raven_model *model, uint8_t *dst, size_t position)
{
    uint32_t context = dst[position - 1] >> 6;
    uint32_t phase = (uint32_t)position & 3;
    uint32_t high;
    uint32_t low;

    if (model->state < 3) {
        high = raven_ans_read_symbol(reader, model, RAVEN_LITERAL_HIGH + 4 * phase + context, 7);
        low = raven_ans_read_symbol(reader, model, RAVEN_LITERAL_LOW + 64 * phase + 16 * context + high, 7);
    } else {
        uint32_t matched = dst[position - model->recent_distances[0]];
        uint32_t match_context = raven_model_literal_context(model->state);

        high = raven_ans_read_symbol(reader, model, RAVEN_MATCHED_HIGH + 64 * match_context + 16 * context + (matched >> 4), 6);
        if (high == matched >> 4) {
            low = raven_ans_read_symbol(reader, model, RAVEN_MATCHED_LOW + 16 * match_context + (matched & 15), 6);
        } else {
            low = raven_ans_read_symbol(reader, model, RAVEN_LITERAL_LOW + 64 * phase + 16 * context + high, 7);
        }
    }
    dst[position] = (uint8_t)(high * 16 + low);
    model->state = (uint8_t)raven_model_next_state(model->state, RAVEN_COMMAND_LITERAL);
}

static int raven_decode_match(struct raven_ans_reader *reader, struct raven_model *model, size_t position, struct raven_match *match)
{
    uint32_t phase = (uint32_t)position & 3;

    match->command = raven_ans_read_symbol(reader, model, RAVEN_COMMANDS + model->state, 6);
    if (match->command < RAVEN_COMMAND_REPEAT_BYTE) {
        uint32_t high;
        uint32_t low;
        uint64_t decoded;

        match->length = 2 + raven_decode_long_length(reader, model, RAVEN_NEW_LENGTH + 4 * match->command + phase, RAVEN_NEW_EXTRA, phase);
        high = raven_ans_read_symbol(reader, model, RAVEN_DISTANCE + 2 * match->command, 7);
        low = raven_ans_read_symbol(reader, model, RAVEN_DISTANCE + 2 * match->command + 1, 7);
        if (!match->command) {
            decoded = high * 16u + low + 1u;
        } else {
            uint32_t bits = (high >> 2) + 4 * match->command - 2;

            decoded = (uint64_t)((high & 3) | 4) << (bits + 4);
            decoded += (uint64_t)16 * raven_ans_read_bits(reader, bits) + low + 1;
        }
        if (decoded > position) {
            return 0;
        }
        match->distance = (uint32_t)decoded;
        match->recent_index = 3;
    } else {
        match->recent_index = match->command & 3;
        if (match->command == RAVEN_COMMAND_REPEAT_BYTE) {
            match->recent_index = 0;
            match->length = 1;
        } else if (match->command < RAVEN_COMMAND_REPEAT_LONG) {
            match->length = 2 + raven_ans_read_symbol(reader, model, RAVEN_SHORT_LENGTH + phase, 6);
        } else {
            match->length = 18 + raven_decode_long_length(reader, model, RAVEN_LONG_LENGTH + phase, RAVEN_LENGTH_EXTRA, phase);
        }
        match->distance = model->recent_distances[match->recent_index];
    }
    return 1;
}

static size_t raven_decode_block_data(struct raven_model *model, uint8_t *dst, size_t capacity, size_t start, const uint8_t *data, size_t size, int *committed)
{
    struct raven_ans_reader reader;
    uint32_t encoded_delta;
    uint32_t block_size;
    uint32_t delta;
    uint32_t width;
    uint32_t i;
    size_t position = start;
    size_t end;

    raven_ans_reader_init(&reader, data, size);
    width = raven_ans_read_bits(&reader, 5);
    encoded_delta = width ? raven_ans_read_bits(&reader, width) + ((UINT32_C(1) << width) - 1) : 0;
    delta = (encoded_delta >> 1) ^ (0u - (encoded_delta & 1));
    block_size = model->previous_block_size + delta;

    model->previous_block_size = block_size;
    if (block_size < RAVEN_MIN_COMPRESSED_SIZE || block_size > RAVEN_BLOCK_SIZE || block_size > capacity - start) {
        return 0;
    }
    end = start + block_size - RAVEN_LITERAL_TAIL_SIZE;
    if (!start) {
        dst[position++] = (uint8_t)raven_ans_read_bits(&reader, 8);
    }
    for (i = 0; i < 4; ++i) {
        if (!model->recent_distances[i] || model->recent_distances[i] > position) {
            return 0;
        }
    }
    while (position < end) {
        uint32_t phase = (uint32_t)position & 3;
        struct raven_match match;

        if (raven_ans_read_binary(&reader, &model->binary_probability[model->state][phase])) {
            raven_decode_literal(&reader, model, dst, position++);
            continue;
        }
        if (!raven_decode_match(&reader, model, position, &match)) {
            return 0;
        }
        if (!match.distance || match.distance > position || match.length > end - position) {
            return 0;
        }
        for (i = match.recent_index; i; --i) {
            model->recent_distances[i] = model->recent_distances[i - 1];
        }
        model->recent_distances[0] = match.distance;
        model->state = (uint8_t)raven_model_next_state(model->state, match.command);
        while (match.length--) {
            dst[position] = dst[position - match.distance];
            ++position;
        }
    }

    if (position != end) {
        return 0;
    }
    *committed = 1;
    for (i = 0; i < 8; ++i) {
        raven_store32(dst + end + 4 * i, (uint32_t)reader.states[i]);
    }
    return reader.word_index != reader.word_count ? 0 : block_size;
}

static size_t raven_decode_block(struct raven_model *model, uint8_t *dst, size_t capacity, size_t start, const uint8_t *data, size_t size)
{
    uint32_t previous_distances[4];
    uint8_t previous_state = model->state;
    int committed = 0;
    size_t result;

    memcpy(previous_distances, model->recent_distances, sizeof(previous_distances));
    result = raven_decode_block_data(model, dst, capacity, start, data, size, &committed);
    if (!committed) {
        memcpy(model->recent_distances, previous_distances, sizeof(previous_distances));
        model->state = previous_state;
    }
    return result;
}

static void raven_unfilter_x86(uint8_t *dst, size_t begin, size_t end)
{
    size_t position = begin;

    while (end - position >= 5) {
        uint32_t value;

        if ((dst[position++] & 254) != 232) {
            continue;
        }
        if (dst[position + 3] != 0 && dst[position + 3] != 255) {

            position += 3;
            continue;
        }

        value = raven_load32(dst + position);
        value = (value & UINT32_C(0x01000000)) + ((value & 255) << 16) + (value & 65280) + ((value >> 16) & 255) - (uint32_t)position;
        value = (value & UINT32_C(0x01ffffff)) - ((value & UINT32_C(0x01000000)) << 1);
        raven_store32(dst + position, value);
        position += 4;
    }
}

static void raven_unfilter_arm64(uint8_t *dst, size_t begin, size_t end, uint32_t alignment)
{
    size_t position;

    for (position = begin + alignment; end - position >= 4; position += 4) {
        uint32_t value = raven_load32(dst + position);
        uint32_t immediate;

        if ((value & UINT32_C(0xfc000000)) == UINT32_C(0x94000000)) {
            if ((value + UINT32_C(0x800000)) & UINT32_C(0x03000000)) {
                continue;
            }

            value -= (uint32_t)position >> 2;
            value = UINT32_C(0x94000000) | (value & UINT32_C(0xffffff)) | ((value & UINT32_C(0x800000)) ? UINT32_C(0x3000000) : 0);
        } else if ((value & UINT32_C(0x9f000000)) == UINT32_C(0x90000000)) {
            if ((value + UINT32_C(0x400000)) & UINT32_C(0x800000)) {
                continue;
            }
            immediate = ((value >> 11) & UINT32_C(0x1c0000)) | ((value >> 5) & UINT32_C(0x3ffff));

            immediate -= (uint32_t)position >> 12;
            value = (value & UINT32_C(0x9000001f)) | (immediate << 29) | ((immediate << 4) & UINT32_C(0x800000)) | ((immediate << 3) & UINT32_C(0x7fffe0));
        } else {
            continue;
        }
        raven_store32(dst + position, value);
    }
}

static void raven_unfilter_blocks(uint8_t *dst, size_t size, const uint8_t *flags)
{
    size_t block_count = size / RAVEN_BLOCK_SIZE + (size % RAVEN_BLOCK_SIZE != 0);
    size_t block;

    for (block = 0; block < block_count; ++block) {
        size_t begin = block * RAVEN_BLOCK_SIZE;
        size_t end = size - begin > RAVEN_BLOCK_SIZE ? begin + RAVEN_BLOCK_SIZE : size;
        uint32_t block_flags;

        if (end - begin < RAVEN_MIN_COMPRESSED_SIZE) {
            continue;
        }
        block_flags = raven_load16(flags + 2 * block);
        if (block_flags & 4) {
            raven_unfilter_x86(dst, begin, end);
        }
        if (block_flags & 2) {
            raven_unfilter_arm64(dst, begin, end, block_flags >> 10);
        }
    }
}

static size_t raven_decode_frame(struct raven_model *model, uint8_t *flags, uint8_t *dst, size_t capacity, const uint8_t *src, size_t size)
{
    size_t cursor = 8;
    size_t written = 0;

    raven_model_init(model);
    while (size - cursor >= 4) {
        uint32_t header = raven_load32(src + cursor);
        size_t payload_size = header >> 12;
        size_t decoded_size;

        cursor += 4;
        if (!payload_size) {
            raven_unfilter_blocks(dst, written, flags);
            return written;
        }
        if (payload_size > size - cursor || written % RAVEN_BLOCK_SIZE || written >= capacity) {
            return 0;
        }
        raven_store16(flags + 2 * (written / RAVEN_BLOCK_SIZE), (uint16_t)(header & 4095));
        if (header & 1) {
            if (payload_size > capacity - written) {
                return 0;
            }
            memcpy(dst + written, src + cursor, payload_size);
            decoded_size = payload_size;
        } else {
            decoded_size = raven_decode_block(model, dst, capacity, written, src + cursor, payload_size);
            if (!decoded_size) {
                return 0;
            }
        }
        written += decoded_size;
        cursor += payload_size;
    }
    return 0;
}

static void raven_model_store(uint8_t *scratch, const struct raven_model *model)
{
    uint32_t row;
    uint32_t i;

    for (row = 0; row < 14; ++row) {
        for (i = 0; i < 4; ++i) {
            raven_store16(scratch + 2 * (4 * row + i), model->binary_probability[row][i]);
        }
    }
    for (row = 0; row < 588; ++row) {
        for (i = 0; i < 16; ++i) {
            raven_store16(scratch + 112 + 2 * (16 * row + i), model->cdf[row][i]);
        }
    }
    for (i = 0; i < 4; ++i) {
        raven_store32(scratch + 18936 + 4 * i, 1);
        raven_store32(scratch + 18952 + 4 * i, model->recent_distances[i]);
    }
    raven_store32(scratch + 18968, model->previous_block_size);
    scratch[18972] = model->state;
}

static size_t raven_decode_scratch(void *destination, size_t capacity, const void *source, size_t size, void *scratch)
{
    const uint8_t *src = source;
    struct raven_model model;
    uint8_t *aligned;
    size_t result;

    if (!src || (!destination && capacity) || size < 8 || size > UINT32_MAX || raven_load32(src) != UINT32_C(0xecca002b) || (raven_load32(src + 4) & UINT32_C(0x03ffffff))) {
        return 0;
    }
    if (capacity > UINT32_MAX) {
        capacity = UINT32_MAX;
    }
    aligned = (uint8_t *)scratch + ((0u - (uintptr_t)scratch) & 63u);
    result = raven_decode_frame(&model, aligned + RAVEN_DECODE_FLAGS_OFFSET, destination, capacity, src, size);
    raven_model_store(aligned, &model);
    return result;
}

static struct raven_lz4_entry raven_lz4_insert(struct raven_lz4_entry *table, const uint8_t *data, uint32_t position)
{
    uint32_t word = raven_load32(data + position);
    uint32_t product = (uint32_t)((uint64_t)word * UINT64_C(0x9e3779b1));
    uint32_t index = product >> 20;
    struct raven_lz4_entry previous = table[index];

    table[index].position = position;
    table[index].word = word;
    return previous;
}

static size_t raven_lz4_block_size(struct raven_lz4_entry *table, const uint8_t *data, uint32_t begin, uint32_t size, size_t capacity)
{
    uint32_t literal_begin = begin;
    uint32_t end = begin + size;
    uint32_t scan_limit = size >= 128 ? end - 128 : begin;
    size_t written = 0;
    size_t match_capacity;

    if (capacity < 128) {
        return 0;
    }
    match_capacity = capacity - 128;
    if (size >= 128) {
        do {
            uint32_t position = literal_begin;
            uint32_t distance = 0;
            uint32_t match_end;
            uint32_t literal_size;
            uint32_t match_extra;
            size_t token_size;

            do {
                struct raven_lz4_entry previous = raven_lz4_insert(table, data, position);
                uint32_t i;

                for (i = 0; i < 5; ++i) {
                    struct raven_lz4_entry next = {0, 0};
                    uint32_t candidate = position + i;
                    uint32_t delta = candidate - previous.position;

                    if (i < 4) {
                        next = raven_lz4_insert(table, data, candidate + 1);
                    }
                    if (previous.word == raven_load32(data + candidate) && delta && delta < 65536) {
                        position = candidate;
                        distance = delta;
                        break;
                    }
                    previous = next;
                }
                if (!distance) {
                    position += 5;
                }
            } while (!distance && position < scan_limit);
            if (!distance) {
                break;
            }
            match_end = position + 4;
            do {
                uint32_t i;

                for (i = 0; i < 8; ++i) {
                    if (data[match_end + i] != data[match_end + i - distance]) {
                        break;
                    }
                }
                match_end += i;
                if (i < 8) {
                    break;
                }
            } while (match_end < scan_limit);
            while (position > literal_begin && position > distance && data[position - 1] == data[position - distance - 1]) {
                --position;
            }
            literal_size = position - literal_begin;
            match_extra = match_end - position - 4;
            token_size = literal_size + 3;
            if (literal_size >= 15) {
                token_size += 1 + (literal_size - 15) / 255;
            }
            if (match_extra >= 15) {
                token_size += 1 + (match_extra - 15) / 255;
            }
            if (token_size > match_capacity - written) {
                return 0;
            }
            written += token_size;
            literal_begin = match_end;
        } while (literal_begin < scan_limit && written < match_capacity);
    }
    if (literal_begin < end) {
        uint32_t literal_size = end - literal_begin;
        size_t tail_size = literal_size + 1;

        if (capacity - written <= tail_size) {
            return 0;
        }
        if (literal_size >= 15) {
            tail_size += 1 + (literal_size - 15) / 255;
        }
        if (tail_size > capacity - written) {
            return 0;
        }
        written += tail_size;
    }
    return written;
}

static size_t raven_lz4_trial_size(struct raven_lz4_entry *table, const uint8_t *data, uint32_t size, size_t capacity)
{
    uint32_t position = 0;
    size_t written = 0;
    uint32_t i;

    for (i = 0; i < RAVEN_LZ4_HASH_SIZE; ++i) {
        table[i].position = UINT32_C(0x80000000);
        table[i].word = 0;
    }
    while (position < size) {
        uint32_t block_size = size - position;
        size_t packed_size;

        if (block_size > RAVEN_LZ4_BLOCK_SIZE) {
            block_size = RAVEN_LZ4_BLOCK_SIZE;
        }
        if (capacity - written < 12) {
            return 0;
        }
        packed_size = raven_lz4_block_size(table, data, position, block_size, capacity - written - 12);
        if (!packed_size || packed_size + 12 >= block_size + 8) {
            packed_size = block_size + 8;
        } else {
            packed_size += 12;
        }
        if (packed_size > capacity - written) {
            return 0;
        }
        written += packed_size;
        position += block_size;
    }
    return capacity - written < 4 ? 0 : written + 4;
}

static void raven_filter_x86(uint8_t *data, uint32_t begin, uint32_t end)
{
    uint32_t position = begin;

    while (end - position >= 5) {
        uint32_t value;
        uint32_t signed_value;

        if ((data[position++] & 254) != 232) {
            continue;
        }
        if (data[position + 3] != 0 && data[position + 3] != 255) {
            position += 3;
            continue;
        }
        value = raven_load32(data + position) + position;
        signed_value = (value & UINT32_C(0x1ffffff)) - ((value << 1) & UINT32_C(0x2000000));
        value = ((value & 255) << 16) | (value & 65280) | ((value >> 16) & 255) | (signed_value & UINT32_C(0xff000000));
        raven_store32(data + position, value);
        position += 4;
    }
}

static void raven_filter_arm64(uint8_t *data, uint32_t begin, uint32_t end, uint32_t alignment)
{
    uint32_t position;

    for (position = begin + alignment; end - position >= 4; position += 4) {
        uint32_t value = raven_load32(data + position);
        uint32_t immediate;

        if ((value & UINT32_C(0xfc000000)) == UINT32_C(0x94000000)) {
            if ((value + UINT32_C(0x800000)) & UINT32_C(0x3000000)) {
                continue;
            }
            value += position >> 2;
            value = UINT32_C(0x94000000) | (value & UINT32_C(0xffffff)) | ((value & UINT32_C(0x800000)) ? UINT32_C(0x3000000) : 0);
        } else if ((value & UINT32_C(0x9f000000)) == UINT32_C(0x90000000)) {
            if ((value + UINT32_C(0x400000)) & UINT32_C(0x800000)) {
                continue;
            }
            immediate = ((value >> 3) & UINT32_C(0x1e1ffffc)) | ((value >> 29) & 3);
            immediate += position >> 12;
            value = (value & UINT32_C(0x9000001f)) | ((immediate << 11) & UINT32_C(0x60000000)) | ((immediate << 6) & UINT32_C(0x800000)) | ((immediate & UINT32_C(0x3ffff)) << 5);
        } else {
            continue;
        }
        raven_store32(data + position, value);
    }
}

static int32_t raven_filter_alignment(const uint8_t *data, uint32_t begin, uint32_t end)
{
    uint32_t counts[4] = {0};
    uint32_t position;
    uint32_t selected = 0;
    uint32_t i;

    for (position = begin; end - position >= 4; ++position) {
        if ((raven_load32(data + position) & UINT32_C(0xff9ff000)) == UINT32_C(0xd61f0000)) {
            ++counts[position & 3];
        }
    }
    for (i = 1; i < 4; ++i) {
        if (counts[i] > counts[selected]) {
            selected = i;
        }
    }
    return counts[selected] >= 4 ? (int32_t)selected : -1;
}

static uint32_t raven_filter_x86_count(const uint8_t *data, uint32_t begin, uint32_t end)
{
    uint32_t position = begin;
    uint32_t count = 0;

    while (end - position >= 5) {
        if ((data[position++] & 254) == 232) {
            uint32_t high = (uint32_t)data[position + 2] | (uint32_t)data[position + 3] << 8;

            if (((high + 1) & 65534) == 0) {
                ++count;
            }
            ++position;
        }
    }
    return count;
}

static void raven_filter_input(struct raven_lz4_entry *table, uint8_t *data, const uint8_t *source, uint32_t size, size_t capacity, uint16_t *flags)
{
    uint32_t begin = 0;

    if (size) {
        memcpy(data, source, size);
    }
    while (begin < size) {
        uint32_t block_size = size - begin;
        uint32_t end;
        size_t arm_size = 0;
        size_t x86_size = 0;
        size_t baseline_size;
        int32_t alignment;
        uint32_t selected = 0;

        if (block_size > RAVEN_BLOCK_SIZE) {
            block_size = RAVEN_BLOCK_SIZE;
        }
        end = begin + block_size;
        if (block_size >= 64) {
            alignment = raven_filter_alignment(data, begin, end);
            if (alignment >= 0) {
                raven_filter_arm64(data, begin, end, (uint32_t)alignment);
                arm_size = raven_lz4_trial_size(table, data + begin, block_size, capacity);
                memcpy(data + begin, source + begin, block_size);
            }
            if (raven_filter_x86_count(data, begin, end) >= 4) {
                raven_filter_x86(data, begin, end);
                x86_size = raven_lz4_trial_size(table, data + begin, block_size, capacity);
                memcpy(data + begin, source + begin, block_size);
            }
            if (arm_size || x86_size) {
                baseline_size = raven_lz4_trial_size(table, data + begin, block_size, capacity);
                if (arm_size && baseline_size > arm_size + 64) {
                    selected = ((uint32_t)alignment << 10) | 2;
                    raven_filter_arm64(data, begin, end, (uint32_t)alignment);
                }
                if (x86_size && baseline_size > x86_size + 64) {
                    selected |= 4;
                    raven_filter_x86(data, begin, end);
                }
            }
        }
        flags[begin / RAVEN_BLOCK_SIZE] = (uint16_t)selected;
        begin = end;
    }
}

static uint32_t raven_match_extend(const uint8_t *left, const uint8_t *right, uint32_t length, uint32_t limit)
{
    while (length < limit && left[length] == right[length]) {
        ++length;
    }
    return length < limit ? length : limit;
}

static void raven_finder_update_pipeline(struct raven_match_finder *finder, uint32_t position)
{
    uint32_t word = raven_load32(finder->input + position + 3);
    uint32_t product = (uint8_t)word * UINT32_C(0x97654321);
    uint32_t hash2 = (uint8_t)(word >> 8) ^ (product >> 19);
    uint32_t hash3 = (uint16_t)(word >> 8) ^ (product >> 16);
    uint32_t product4 = (uint32_t)((uint64_t)(uint16_t)word * UINT64_C(0x97654321));
    uint32_t hash4 = (product4 >> 12) ^ (word >> 16);
    uint32_t future = position + 2;
    struct raven_hash_pipeline *slot = &finder->pipeline[(position & 3) ^ 2];
    uint32_t short2 = slot->prefix2;
    uint32_t short3 = slot->prefix3;
    uint32_t long4 = slot->prefix4;
    uint32_t candidate2 = (future & UINT32_C(0xffff0000)) | finder->hash2[short2];
    uint32_t candidate3 = (future & UINT32_C(0xffff0000)) | finder->hash3[short3];

    if (candidate2 >= future) {
        candidate2 -= 65536;
    }
    if (candidate3 >= future) {
        candidate3 -= 65536;
    }
    slot->prefix2 = candidate2;
    slot->prefix3 = candidate3;
    slot->prefix4 = finder->hash4[long4];
    finder->hash2[short2] = (uint16_t)future;
    finder->hash3[short3] = (uint16_t)future;
    finder->hash4[long4] = future;
    slot = &finder->pipeline[(position - 1) & 3];
    slot->prefix2 = hash2;
    slot->prefix3 = hash3;
    slot->prefix4 = hash4;
}

static uint32_t raven_finder_walk_tree(struct raven_match_finder *finder, uint32_t position, uint32_t count, uint32_t best, int record)
{
    uint32_t *lower = &finder->children[position & finder->window_mask][0];
    uint32_t *upper = lower + 1;
    uint32_t oldest = position >= finder->window_mask ? position - finder->window_mask : 0;
    uint32_t candidate = finder->pipeline[position & 3].prefix4;
    uint32_t limit = finder->limit - position;
    uint32_t lower_length = 0;
    uint32_t upper_length = 0;
    uint32_t depth = finder->depth;

    if (limit > finder->nice_length) {
        limit = finder->nice_length;
    }
    while (depth && candidate > oldest) {
        uint32_t *children = finder->children[candidate & finder->window_mask];
        uint32_t length = lower_length < upper_length ? lower_length : upper_length;
        int improved;

        --depth;
        length = raven_match_extend(finder->input + position, finder->input + candidate, length, limit);
        improved = record && length > best;
        if (improved) {
            finder->matches[count].distance = position - candidate;
            finder->matches[count].length = length;
            ++count;
            best = length;
        }
        if (length == limit && (!record || improved)) {
            *lower = children[0];
            *upper = children[1];
            return count;
        }
        if (finder->input[position + length] >= finder->input[candidate + length]) {
            *lower = candidate;
            lower = children + 1;
            lower_length = length;
            candidate = children[1];
        } else {
            *upper = candidate;
            upper = children;
            upper_length = length;
            candidate = children[0];
        }
    }
    *lower = 0;
    *upper = 0;
    return count;
}

static void raven_finder_skip(struct raven_match_finder *finder, uint32_t position)
{
    raven_finder_walk_tree(finder, position, 0, 0, 0);
    raven_finder_update_pipeline(finder, position);
}

static uint32_t raven_finder_search_tree(struct raven_match_finder *finder, uint32_t position)
{
    const uint8_t *input = finder->input + position;
    const struct raven_hash_pipeline *slot = &finder->pipeline[position & 3];
    uint32_t candidate2 = slot->prefix2;
    uint32_t candidate3 = slot->prefix3;
    uint32_t candidate = 0;
    uint32_t count = 0;
    uint32_t best = 3;
    uint32_t prefix = 0;
    uint32_t limit = finder->limit - position;
    int search;

    if (limit > finder->nice_length) {
        limit = finder->nice_length;
    }
    if (candidate2 != candidate3 && ((raven_load32(input) ^ raven_load32(finder->input + candidate2)) & 65535) == 0) {
        finder->matches[count].distance = position - candidate2;
        finder->matches[count].length = 2;
        ++count;
        prefix = 2;
        candidate = candidate2;
    }
    if (((raven_load32(input) ^ raven_load32(finder->input + candidate3)) & UINT32_C(0xffffff)) == 0) {
        finder->matches[count].distance = position - candidate3;
        finder->matches[count].length = 3;
        ++count;
        prefix = 3;
        candidate = candidate3;
    }
    if (count) {
        best = raven_match_extend(input, finder->input + candidate, prefix, limit);
        finder->matches[count - 1].length = best;
    }
    search = !count || best < limit;
    count = raven_finder_walk_tree(finder, position, count, best, search);
    raven_finder_update_pipeline(finder, position);
    return count;
}

static uint32_t raven_finder_search(struct raven_match_finder *finder, uint32_t position)
{
    struct raven_match_candidate *last;
    uint32_t length;
    uint32_t limit;

    if (position + 1 == finder->next_position) {
        return finder->match_count ? finder->matches[finder->match_count - 1].length : 0;
    }
    while (finder->next_position < position) {
        uint32_t skipped = finder->next_position++;

        raven_finder_skip(finder, skipped);
    }
    finder->match_count = raven_finder_search_tree(finder, finder->next_position++);
    if (!finder->match_count) {
        return 0;
    }
    last = &finder->matches[finder->match_count - 1];
    length = last->length;
    if (length < finder->nice_length) {
        return length;
    }
    limit = finder->limit - position;
    if (limit > RAVEN_NEW_MATCH_LIMIT) {
        limit = RAVEN_NEW_MATCH_LIMIT;
    }
    length = raven_match_extend(finder->input + position, finder->input + position - last->distance, length, limit);
    last->length = length;
    return length;
}

static uint32_t raven_price_cdf(const struct raven_model *model, uint32_t bank, uint32_t symbol)
{
    const uint16_t *cdf = model->cdf[bank];
    uint32_t lower = symbol ? cdf[symbol - 1] : 0;
    uint32_t frequency = cdf[symbol] - lower;

    return raven_cost_lut[frequency >> 5];
}

static uint32_t raven_price_length(const struct raven_model *model, uint32_t primary, uint32_t extension, uint32_t phase, uint32_t value)
{
    uint32_t group;
    uint32_t price;

    if (value < 10) {
        return raven_price_cdf(model, primary, value);
    }
    if (value < 26) {
        return raven_price_cdf(model, primary, 10) + raven_price_cdf(model, extension + 4, value - 10);
    }
    group = (value + 150) >> 4;
    price = raven_price_cdf(model, primary, group);
    price += raven_price_cdf(model, extension + phase, (value + 150) & 15);
    return price;
}

static uint32_t raven_price_recent(const struct raven_model *model, uint32_t phase, uint32_t length)
{
    if (length <= 17) {
        return raven_price_cdf(model, RAVEN_SHORT_LENGTH + phase, length - 2);
    }
    return raven_price_length(model, RAVEN_LONG_LENGTH + phase, RAVEN_LENGTH_EXTRA, phase, length - 18);
}

static uint32_t raven_price_literal(const struct raven_model *model, const uint8_t *input, uint32_t position, uint32_t state, uint32_t distance)
{
    uint32_t phase = position & 3;
    uint32_t context = input[position - 1] >> 6;
    uint32_t high = input[position] >> 4;
    uint32_t low = input[position] & 15;
    uint32_t high_bank = RAVEN_LITERAL_HIGH + 4 * phase + context;
    uint32_t low_bank = RAVEN_LITERAL_LOW + 64 * phase + 16 * context + high;
    uint32_t price = raven_cost_lut[(16384 - model->binary_probability[state][phase]) >> 5];

    if (state > 2) {
        uint32_t predicted = input[position - distance];
        uint32_t match_context = raven_model_literal_context(state);

        high_bank = RAVEN_MATCHED_HIGH + 64 * match_context + 16 * context + (predicted >> 4);
        if (high == (predicted >> 4)) {
            low_bank = RAVEN_MATCHED_LOW + 16 * match_context + (predicted & 15);
        }
    }
    return price + raven_price_cdf(model, high_bank, high) + raven_price_cdf(model, low_bank, low);
}

static uint32_t raven_price_command(const struct raven_model *model, uint32_t state, uint32_t phase, uint32_t command)
{
    return raven_cost_lut[model->binary_probability[state][phase] >> 5] + raven_price_cdf(model, RAVEN_COMMANDS + state, command);
}

static uint32_t raven_distance_class(uint32_t distance)
{
    uint32_t value = distance - 1;

    return value < 256 ? 0 : (raven_log2(value) - 4) / 4;
}

static uint32_t raven_price_distance(const struct raven_model *model, uint32_t distance)
{
    uint32_t value = distance - 1;
    uint32_t distance_class = raven_distance_class(distance);
    uint32_t high = value >> 4;
    uint32_t bits = 0;

    if (distance_class) {
        uint32_t width = raven_log2(value) - 4;

        bits = width - 2;
        high = 4 * (width - 4 * distance_class) + (value >> (width + 2)) - 4;
    }
    return 1024 * bits + raven_price_cdf(model, RAVEN_DISTANCE + 2 * distance_class, high) + raven_price_cdf(model, RAVEN_DISTANCE + 2 * distance_class + 1, value & 15);
}

static void raven_prices_refresh_recent(struct raven_price_cache *prices, const struct raven_model *model, uint32_t phase)
{
    uint16_t *cache = prices->recent[phase];
    uint32_t length;

    cache[0] = 16;
    cache[1] = 0;
    for (length = 2; length < 64; ++length) {
        cache[length] = (uint16_t)raven_price_recent(model, phase, length);
    }
}

static void raven_prices_refresh_new(struct raven_price_cache *prices, const struct raven_model *model, uint32_t distance_class, uint32_t phase)
{
    uint16_t *cache = prices->new_lengths[distance_class][phase];
    uint32_t primary = RAVEN_NEW_LENGTH + 4 * distance_class + phase;
    uint32_t length;

    cache[0] = 16;
    for (length = 2; length < 64; ++length) {
        cache[length] = (uint16_t)raven_price_length(model, primary, RAVEN_NEW_EXTRA, phase, length - 2);
    }
}

static void raven_prices_refresh(struct raven_price_cache *prices, const struct raven_model *model)
{
    uint32_t phase;
    uint32_t distance_class;

    for (phase = 0; phase < 4; ++phase) {
        raven_prices_refresh_recent(prices, model, phase);
        for (distance_class = 0; distance_class < 7; ++distance_class) {
            raven_prices_refresh_new(prices, model, distance_class, phase);
        }
    }
}

static void raven_prices_commit(struct raven_price_cache *prices, const struct raven_model *model, uint32_t recent, uint32_t distance_class, uint32_t phase, uint32_t length)
{
    uint16_t *cache = recent ? prices->recent[phase] : prices->new_lengths[distance_class][phase];
    uint32_t primary = RAVEN_NEW_LENGTH + 4 * distance_class + phase;

    --cache[0];
    if (!cache[0]) {
        if (recent) {
            raven_prices_refresh_recent(prices, model, phase);
        } else {
            raven_prices_refresh_new(prices, model, distance_class, phase);
        }
    } else if (length < 64) {
        cache[length] = (uint16_t)(recent ? raven_price_recent(model, phase, length) : raven_price_length(model, primary, RAVEN_NEW_EXTRA, phase, length - 2));
    }
}

static uint32_t raven_repeat_command(uint32_t length)
{
    return length < 2 ? RAVEN_COMMAND_REPEAT_BYTE : length < 18 ? RAVEN_COMMAND_REPEAT_SHORT : RAVEN_COMMAND_REPEAT_LONG;
}

static void raven_parser_prepare_nodes(struct raven_parser *parser, uint32_t *furthest, uint32_t target)
{
    while (*furthest < target) {
        parser->nodes[++*furthest].price = UINT32_MAX;
    }
}

static void raven_parser_set_path(struct raven_parse_node *node, uint32_t price, uint32_t argument, uint32_t length, uint32_t command)
{
    node->price = price;
    node->argument = argument;
    node->length = (uint16_t)length;
    node->command = (uint8_t)command;
}

static void raven_parser_reconstruct(struct raven_parser *parser, uint32_t end)
{
    struct raven_parse_node *node = &parser->nodes[end];
    uint32_t argument = node->argument;
    uint32_t length = node->length;
    uint32_t begin = end - length;
    struct raven_parse_node *previous;
    uint32_t first_length;
    uint32_t literals;
    uint32_t tail;
    uint32_t command;

    if (begin) {
        raven_parser_reconstruct(parser, begin);
    }
    previous = &parser->nodes[begin];
    if (node->command != RAVEN_COMMAND_COMPOSITE) {
        previous->argument = argument;
        previous->length = (uint16_t)length;
        previous->command = node->command;
        return;
    }
    command = node->first_command;
    literals = node->literal_count;
    tail = node->repeat_length;
    first_length = length - literals - tail;
    previous->argument = argument;
    previous->length = (uint16_t)first_length;
    previous->command = (uint8_t)command;
    parser->nodes[begin + first_length].state = (uint8_t)raven_model_next_state(previous->state, command);
    begin += first_length;
    while (literals--) {
        parser->nodes[begin].command = RAVEN_COMMAND_LITERAL;
        parser->nodes[begin].length = 1;
        parser->nodes[begin + 1].state = (uint8_t)raven_model_next_state(parser->nodes[begin].state, RAVEN_COMMAND_LITERAL);
        ++begin;
    }
    parser->nodes[begin].argument = 0;
    parser->nodes[begin].length = (uint16_t)tail;
    parser->nodes[begin].command = (uint8_t)raven_repeat_command(tail);
}

static void raven_parser_history(struct raven_parser *parser, uint32_t index)
{
    struct raven_parse_node *node = &parser->nodes[index];
    const struct raven_parse_node *previous = &parser->nodes[index - node->length];
    uint32_t command = node->command;
    uint32_t selected;
    uint32_t distance;
    uint32_t i;

    memcpy(node->recent_distances, previous->recent_distances, sizeof(node->recent_distances));
    if (command == RAVEN_COMMAND_COMPOSITE) {
        node->state = (uint8_t)raven_model_next_state(0, raven_repeat_command(node->repeat_length));
        command = node->first_command;
    } else {
        node->state = (uint8_t)raven_model_next_state(previous->state, command);
    }
    if (command == RAVEN_COMMAND_REPEAT_BYTE || command == RAVEN_COMMAND_LITERAL) {
        return;
    }
    selected = command > RAVEN_COMMAND_REPEAT_BYTE ? node->argument : 3;
    distance = command > RAVEN_COMMAND_REPEAT_BYTE ? node->recent_distances[selected] : node->argument;
    for (i = selected; i; --i) {
        node->recent_distances[i] = node->recent_distances[i - 1];
    }
    node->recent_distances[0] = distance;
}

static void raven_parser_composite(
    struct raven_encoder *encoder, uint32_t index, uint32_t position, uint32_t end, uint32_t argument, uint32_t distance, uint32_t first_length, uint32_t first_command, uint32_t first_price, uint32_t literal_limit, uint32_t *furthest)
{
    struct raven_parser *parser = &encoder->parser;
    const struct raven_model *model = &encoder->model;
    struct raven_parse_node *node = &parser->nodes[index];
    const uint8_t *input = encoder->finder.input;
    uint32_t after = position + first_length;
    uint32_t literals = 0;
    uint32_t repeat;
    uint32_t limit;
    uint32_t state;
    uint32_t price = first_price;
    uint32_t target;
    uint32_t i;
    struct raven_parse_node *destination;

    if (after >= end) {
        return;
    }
    while (input[after + literals] != input[after + literals - distance]) {
        if (after + literals + 1 >= end || literals == literal_limit) {
            return;
        }
        ++literals;
    }
    if (!literals) {
        return;
    }
    limit = end - after - literals;
    if (limit >= encoder->finder.nice_length) {
        limit = encoder->finder.nice_length - 1;
    }
    repeat = raven_match_extend(input + after + literals, input + after + literals - distance, 1, limit);
    state = raven_model_next_state(node->state, first_command);
    for (i = 0; i < literals; ++i) {
        price += raven_price_literal(model, input, after + i, state, distance);
        state = raven_model_next_state(state, RAVEN_COMMAND_LITERAL);
    }
    price += raven_price_command(model, state, (after + literals) & 3, raven_repeat_command(repeat));
    price += encoder->prices.recent[(after + literals) & 3][repeat];
    price += node->price;
    target = index + first_length + literals + repeat;
    raven_parser_prepare_nodes(parser, furthest, target);
    destination = &parser->nodes[target];
    if (price < destination->price) {
        raven_parser_set_path(destination, price, argument, first_length + literals + repeat, RAVEN_COMMAND_COMPOSITE);
        destination->first_command = (uint8_t)first_command;
        destination->literal_count = (uint16_t)literals;
        destination->repeat_length = (uint16_t)repeat;
    }
}

static uint32_t raven_parser_next(struct raven_encoder *encoder, uint32_t position, uint32_t end, uint32_t *argument, uint32_t *length)
{
    struct raven_parser *parser = &encoder->parser;
    const struct raven_model *model = &encoder->model;
    struct raven_match_finder *finder = &encoder->finder;
    const uint8_t *input = finder->input;
    uint32_t furthest = 1;
    uint32_t index = 0;

    if (parser->cursor != parser->end) {
        struct raven_parse_node *node = &parser->nodes[parser->cursor];

        parser->cursor += node->length;
        *argument = node->argument;
        *length = node->length;
        return node->command;
    }
    if (end - position > RAVEN_PARSE_LIMIT) {
        end = position + RAVEN_PARSE_LIMIT;
    }
    parser->nodes[0].price = 0;
    parser->nodes[0].state = model->state;
    memcpy(parser->nodes[0].recent_distances, model->recent_distances, sizeof(parser->nodes[0].recent_distances));
    parser->nodes[1].price = UINT32_MAX;
    parser->nodes[1].command = RAVEN_COMMAND_UNREACHED;
    while (index < furthest) {
        struct raven_parse_node *node = &parser->nodes[index];
        uint32_t current = position + index;
        uint32_t remaining = end - current;
        uint32_t phase = current & 3;
        uint32_t recent_lengths[4];
        uint32_t best_index = 0;
        uint32_t best_recent;
        uint32_t new_match_length;
        uint32_t literal_price;
        uint32_t minimum;
        uint32_t limit = remaining < RAVEN_REPEAT_LIMIT ? remaining : RAVEN_REPEAT_LIMIT;
        uint32_t i;

        if (index) {
            raven_parser_history(parser, index);
        }
        for (i = 0; i < 4; ++i) {
            uint32_t match_length = raven_match_extend(input + current, input + current - node->recent_distances[i], 0, limit);

            if (i && match_length == 1) {
                match_length = 0;
            }
            recent_lengths[i] = match_length;
            if (match_length > recent_lengths[best_index]) {
                best_index = i;
            }
        }
        best_recent = recent_lengths[best_index];
        if (best_recent >= finder->nice_length) {
            uint32_t command = raven_repeat_command(best_recent);

            if (!index) {
                *argument = best_index;
                *length = best_recent;
                return command;
            }
            raven_parser_set_path(&parser->nodes[index + best_recent], 0, best_index, best_recent, command);
            furthest = index + best_recent;
            break;
        }
        new_match_length = raven_finder_search(finder, current);
        if (new_match_length > remaining) {
            new_match_length = remaining;
        }
        if (new_match_length >= finder->nice_length) {
            uint32_t distance = finder->matches[finder->match_count - 1].distance;

            if (!index) {
                *argument = distance;
                *length = new_match_length;
                return 0;
            }
            raven_parser_set_path(&parser->nodes[index + new_match_length], 0, distance, new_match_length, 0);
            furthest = index + new_match_length;
            break;
        }
        if (!(best_recent + index + new_match_length)) {
            *length = 1;
            return RAVEN_COMMAND_LITERAL;
        }
        raven_parser_prepare_nodes(parser, &furthest, index + (best_recent ? best_recent : 1));
        literal_price = raven_price_literal(model, input, current, node->state, node->recent_distances[0]);
        if (node->price + literal_price < parser->nodes[index + 1].price) {
            raven_parser_set_path(&parser->nodes[index + 1], node->price + literal_price, 0, 1, RAVEN_COMMAND_LITERAL);
        }
        minimum = recent_lengths[0] ? 1 : 2;
        if (!recent_lengths[0] && parser->nodes[index + 1].command != RAVEN_COMMAND_LITERAL && current + 1 < end && input[current + 1] == input[current + 1 - node->recent_distances[0]]) {
            uint32_t repeat_limit = end - current - 1;
            uint32_t repeat;
            uint32_t state = raven_model_next_state(node->state, RAVEN_COMMAND_LITERAL);
            uint32_t price;
            uint32_t target;

            if (repeat_limit >= finder->nice_length) {
                repeat_limit = finder->nice_length - 1;
            }
            repeat = raven_match_extend(input + current + 1, input + current + 1 - node->recent_distances[0], 1, repeat_limit);
            price = node->price + literal_price + raven_price_command(model, state, (current + 1) & 3, raven_repeat_command(repeat)) + encoder->prices.recent[(current + 1) & 3][repeat];
            target = index + repeat + 1;
            raven_parser_prepare_nodes(parser, &furthest, target);
            if (price < parser->nodes[target].price) {
                raven_parser_set_path(&parser->nodes[target], price, 0, repeat + 1, RAVEN_COMMAND_COMPOSITE);
                parser->nodes[target].first_command = RAVEN_COMMAND_LITERAL;
                parser->nodes[target].literal_count = 0;
                parser->nodes[target].repeat_length = (uint16_t)repeat;
            }
        }

        for (i = 0; i < 4; ++i) {
            uint32_t match_length = recent_lengths[i];
            uint32_t price = 0;
            uint32_t command = RAVEN_COMMAND_REPEAT_BYTE;
            uint32_t distance = node->recent_distances[i];

            if (minimum > match_length) {
                continue;
            }
            while (minimum <= match_length) {
                uint32_t target = index + minimum;
                uint32_t actual_command;

                command = raven_repeat_command(minimum);
                actual_command = command == RAVEN_COMMAND_REPEAT_BYTE ? RAVEN_COMMAND_REPEAT_BYTE : command + i;
                price = raven_price_command(model, node->state, phase, actual_command) + encoder->prices.recent[phase][minimum];
                if (node->price + price < parser->nodes[target].price) {
                    raven_parser_set_path(&parser->nodes[target], node->price + price, i, minimum, command);
                }
                ++minimum;
            }
            if (current >= distance + 4 && raven_load32(input + current - 4) != raven_load32(input + current - distance - 4)) {
                raven_parser_composite(encoder, index, current, end, i, distance, match_length, command, price, 3, &furthest);
            }
        }
        if (new_match_length > 1) {
            uint32_t new_minimum = best_recent + 1 > 2 ? best_recent + 1 : 2;

            raven_parser_prepare_nodes(parser, &furthest, index + new_match_length);
            for (i = 0; i < finder->match_count; ++i) {
                uint32_t match_length = finder->matches[i].length;
                uint32_t distance = finder->matches[i].distance;
                uint32_t distance_class = raven_distance_class(distance);
                uint32_t price = 0;
                uint32_t base_price;

                if (match_length > new_match_length) {
                    match_length = new_match_length;
                }
                if (new_minimum > match_length) {
                    continue;
                }
                base_price = raven_price_command(model, node->state, phase, distance_class) + raven_price_distance(model, distance);
                while (new_minimum <= match_length) {
                    uint32_t target = index + new_minimum;

                    price = base_price + encoder->prices.new_lengths[distance_class][phase][new_minimum];
                    if (node->price + price < parser->nodes[target].price) {
                        raven_parser_set_path(&parser->nodes[target], node->price + price, distance, new_minimum, 0);
                    }
                    ++new_minimum;
                }
                raven_parser_composite(encoder, index, current, end, distance, distance, match_length, 0, price, 2, &furthest);
            }
        }
        ++index;
    }
    raven_parser_reconstruct(parser, furthest);
    parser->end = furthest;
    parser->cursor = parser->nodes[0].length;
    *argument = parser->nodes[0].argument;
    *length = parser->nodes[0].length;
    return parser->nodes[0].command;
}

static void raven_ans_push_word(struct raven_bit_writer *writer, uint32_t value)
{
    if (writer->cursor < 4) {
        writer->failed = 1;
        return;
    }
    writer->cursor -= 4;
    raven_store32(writer->data + writer->cursor, value);
}

static uint64_t raven_ans_push_bits(struct raven_bit_writer *writer, uint64_t state, uint32_t bits, uint32_t value)
{
    if (bits && state >> (64 - bits)) {
        raven_ans_push_word(writer, (uint32_t)state);
        state >>= 32;
    }
    return state << bits | value;
}

static void raven_events_append(struct raven_event_buffer *event_buffer, uint32_t start, uint32_t frequency, uint32_t value)
{
    struct raven_entropy_event entry;

    if (event_buffer->count == event_buffer->capacity) {
        event_buffer->failed = 1;
        return;
    }
    entry.start = (uint16_t)start;
    entry.frequency = (uint16_t)frequency;
    entry.value = value;
    event_buffer->events[event_buffer->count++] = entry;
}

static void raven_events_write_bits(struct raven_event_buffer *event_buffer, uint32_t bits, uint32_t value)
{
    raven_events_append(event_buffer, bits, 0, value);
}

static void raven_events_write_binary(struct raven_event_buffer *event_buffer, uint16_t *probability, uint32_t bit)
{
    uint32_t threshold = *probability;

    raven_events_append(event_buffer, bit ? threshold : 0, bit ? RAVEN_PROBABILITY_SCALE - threshold : threshold, 0);
    raven_model_update_binary(probability, bit);
}

static void raven_events_write_cdf(struct raven_event_buffer *event_buffer, struct raven_model *model, uint32_t index, uint32_t value, uint32_t rate)
{
    uint16_t *cdf = model->cdf[index];
    uint32_t start = value ? cdf[value - 1] : 0;

    raven_events_append(event_buffer, start, cdf[value] - start, 0);
    raven_model_update_cdf(cdf, value, rate);
}

static size_t raven_ans_encode_block(const struct raven_event_buffer *event_buffer, const uint8_t *tail, uint8_t *dst, size_t capacity)
{
    uint64_t states[8];
    struct raven_bit_writer writer = {dst, capacity & ~(size_t)3, 0};
    size_t end = writer.cursor;
    size_t size;
    size_t i;
    uint64_t header_state;

    for (i = 0; i < 8; ++i) {
        states[i] = (UINT64_C(1) << 32) | raven_load32(tail + 4 * i);
    }
    for (i = event_buffer->count; i--;) {
        struct raven_entropy_event event = event_buffer->events[i];
        uint64_t lane_state = states[i & 7];

        if (!event.frequency) {
            lane_state = raven_ans_push_bits(&writer, lane_state, event.start, event.value);
        } else {
            if ((lane_state >> 50) >= event.frequency) {
                raven_ans_push_word(&writer, (uint32_t)lane_state);
                lane_state >>= 32;
            }
            lane_state = ((lane_state / event.frequency) << 14) + lane_state % event.frequency + event.start;
        }
        states[i & 7] = lane_state;
    }
    header_state = states[0];
    for (i = 7; i; --i) {
        uint32_t high = (uint32_t)(states[i] >> 32);
        uint32_t bits = raven_log2(high);

        if (bits) {
            header_state = raven_ans_push_bits(&writer, header_state, bits, high ^ (UINT32_C(1) << bits));
        }
        header_state = raven_ans_push_bits(&writer, header_state, 5, bits);
        if (header_state >> 32) {
            raven_ans_push_word(&writer, (uint32_t)header_state);
            header_state >>= 32;
        }
        header_state = (header_state << 32) | (uint32_t)states[i];
    }
    raven_ans_push_word(&writer, (uint32_t)header_state);
    raven_ans_push_word(&writer, (uint32_t)(header_state >> 32));

    if (writer.failed || writer.cursor < 4) {
        return 0;
    }
    size = end - writer.cursor;
    memmove(dst, dst + writer.cursor, size);
    return size;
}

static void raven_encode_literal(struct raven_event_buffer *event_buffer, struct raven_model *model, const uint8_t *input, size_t position)
{
    uint32_t phase = (uint32_t)position & 3u;
    uint32_t previous = input[position - 1] >> 6;
    uint32_t high = input[position] >> 4;
    uint32_t low = input[position] & 15u;
    uint32_t low_index = RAVEN_LITERAL_LOW + 64 * phase + 16 * previous + high;

    raven_events_write_binary(event_buffer, &model->binary_probability[model->state][phase], 1);
    if (model->state < 3) {
        raven_events_write_cdf(event_buffer, model, RAVEN_LITERAL_HIGH + 4 * phase + previous, high, 7);
        raven_events_write_cdf(event_buffer, model, low_index, low, 7);
    } else {
        uint32_t predicted = input[position - model->recent_distances[0]];
        uint32_t context = raven_model_literal_context(model->state);

        raven_events_write_cdf(event_buffer, model, RAVEN_MATCHED_HIGH + 64 * context + 16 * previous + (predicted >> 4), high, 6);
        if (high == (predicted >> 4)) {
            raven_events_write_cdf(event_buffer, model, RAVEN_MATCHED_LOW + 16 * context + (predicted & 15u), low, 6);
        } else {
            raven_events_write_cdf(event_buffer, model, low_index, low, 7);
        }
    }
    model->state = (uint8_t)raven_model_next_state(model->state, RAVEN_COMMAND_LITERAL);
}

static void raven_encode_length(struct raven_event_buffer *event_buffer, struct raven_model *model, uint32_t value, uint32_t primary, uint32_t extension, uint32_t high, uint32_t low)
{
    if (value < 10) {
        raven_events_write_cdf(event_buffer, model, primary, value, 6);
    } else if (value < 26) {
        raven_events_write_cdf(event_buffer, model, primary, 10, 6);
        raven_events_write_cdf(event_buffer, model, extension, value - 10, 6);
    } else if (value < 330) {
        uint32_t group = (value + 150) >> 4;

        if (group < 14) {
            raven_events_write_cdf(event_buffer, model, primary, group, 6);
        } else {
            raven_events_write_cdf(event_buffer, model, primary, 14, 6);
            raven_events_write_cdf(event_buffer, model, high, group - 14, 6);
        }
        raven_events_write_cdf(event_buffer, model, low, (value + 150) & 15u, 6);
    } else {
        raven_events_write_cdf(event_buffer, model, primary, 15, 6);
    }
}

static void raven_encode_match(struct raven_event_buffer *event_buffer, struct raven_model *model, size_t position, uint32_t match_length, uint32_t distance, uint32_t recent_index)
{
    uint32_t phase = (uint32_t)position & 3u;
    uint32_t command;
    uint32_t distance_class = 0;
    uint32_t encoded_distance = distance - 1;
    uint32_t i;

    if (recent_index < 4) {
        command = (match_length <= 17 ? RAVEN_COMMAND_REPEAT_SHORT : RAVEN_COMMAND_REPEAT_LONG) + recent_index;
    } else {
        if (encoded_distance >= 256) {
            distance_class = (raven_log2(encoded_distance) - 4) / 4;
        }
        command = distance_class;
    }
    raven_events_write_binary(event_buffer, &model->binary_probability[model->state][phase], 0);
    raven_events_write_cdf(event_buffer, model, RAVEN_COMMANDS + model->state, command, 6);
    if (recent_index < 4) {
        if (match_length <= 17) {
            raven_events_write_cdf(event_buffer, model, RAVEN_SHORT_LENGTH + phase, match_length - 2, 6);
        } else {
            raven_encode_length(event_buffer, model, match_length - 18, RAVEN_LONG_LENGTH + phase, RAVEN_LENGTH_EXTRA + 4, RAVEN_LENGTH_EXTRA + 5, RAVEN_LENGTH_EXTRA + phase);
        }
        for (i = recent_index; i; --i) {
            model->recent_distances[i] = model->recent_distances[i - 1];
        }
    } else {
        uint32_t top = encoded_distance >> 4;
        uint32_t bits = 0;

        raven_encode_length(event_buffer, model, match_length - 2, RAVEN_NEW_LENGTH + 4 * distance_class + phase, RAVEN_NEW_EXTRA + 4, RAVEN_NEW_EXTRA + 5, RAVEN_NEW_EXTRA + phase);
        if (distance_class) {
            uint32_t distance_width = raven_log2(encoded_distance) - 4;

            bits = distance_width - 2;
            top = 4 * (distance_width - 4 * distance_class) + (encoded_distance >> (distance_width + 2)) - 4;
        }
        raven_events_write_cdf(event_buffer, model, RAVEN_DISTANCE + 2 * distance_class, top, 7);
        raven_events_write_cdf(event_buffer, model, RAVEN_DISTANCE + 2 * distance_class + 1, encoded_distance & 15u, 7);
        if (distance_class) {
            raven_events_write_bits(event_buffer, bits, (encoded_distance >> 4) & ((UINT32_C(1) << bits) - 1));
        }
        for (i = 3; i; --i) {
            model->recent_distances[i] = model->recent_distances[i - 1];
        }
    }
    model->recent_distances[0] = distance;
    model->state = (uint8_t)raven_model_next_state(model->state, command);
}

static void raven_encode_token(struct raven_encoder *encoder, struct raven_event_buffer *buffer, uint32_t position, uint32_t command, uint32_t argument, uint32_t length)
{
    struct raven_model *model = &encoder->model;

    if (command == RAVEN_COMMAND_LITERAL) {
        raven_encode_literal(buffer, model, encoder->finder.input, position);
    } else if (command == RAVEN_COMMAND_REPEAT_BYTE) {
        raven_events_write_binary(buffer, &model->binary_probability[model->state][position & 3], 0);
        raven_events_write_cdf(buffer, model, RAVEN_COMMANDS + model->state, RAVEN_COMMAND_REPEAT_BYTE, 6);
        model->state = (uint8_t)raven_model_next_state(model->state, RAVEN_COMMAND_REPEAT_BYTE);
    } else if (command >= RAVEN_COMMAND_REPEAT_SHORT) {
        raven_encode_match(buffer, model, position, length, model->recent_distances[argument], argument);
        raven_prices_commit(&encoder->prices, model, 1, 0, position & 3, length);
    } else {
        raven_encode_match(buffer, model, position, length, argument, 4);
        raven_prices_commit(&encoder->prices, model, 0, raven_distance_class(argument), position & 3, length);
    }
}

static size_t raven_encode_block(struct raven_encoder *encoder, struct raven_event_buffer *event_buffer, uint8_t *destination, size_t capacity, uint32_t begin, uint32_t block_size)
{
    struct raven_model *model = &encoder->model;
    const uint8_t *input = encoder->finder.input;
    uint32_t position = begin;
    uint32_t end;
    int32_t delta;
    uint32_t zigzag;
    uint32_t width;

    if (block_size < RAVEN_MIN_COMPRESSED_SIZE) {
        return 0;
    }
    end = begin + block_size - RAVEN_LITERAL_TAIL_SIZE;
    delta = (int32_t)block_size - (int32_t)model->previous_block_size;
    zigzag = delta < 0 ? (uint32_t)(-delta) * 2 - 1 : (uint32_t)delta * 2;
    width = raven_log2(zigzag + 1);
    event_buffer->count = 0;
    event_buffer->failed = 0;
    raven_prices_refresh(&encoder->prices, model);
    encoder->parser.cursor = 0;
    encoder->parser.end = 0;
    raven_events_write_bits(event_buffer, 5, width);
    if (width) {
        raven_events_write_bits(event_buffer, width, zigzag - ((UINT32_C(1) << width) - 1));
    }
    model->previous_block_size = block_size;
    if (!begin) {
        raven_events_write_bits(event_buffer, 8, input[0]);
        ++position;
    }
    while (position < end) {
        uint32_t argument = 0;
        uint32_t length = 0;
        uint32_t command = raven_parser_next(encoder, position, end, &argument, &length);

        raven_encode_token(encoder, event_buffer, position, command, argument, length);
        position += length;
    }
    return event_buffer->failed ? 0 : raven_ans_encode_block(event_buffer, input + end, destination, capacity);
}

static size_t raven_encode_frame(struct raven_encoder *encoder, struct raven_event_buffer *event_buffer, uint16_t *filter_flags, uint8_t *destination, size_t capacity, const uint8_t *source, uint8_t *input, uint32_t size)
{
    size_t written = 8;
    uint32_t position = 0;
    uint32_t size_hint_code = 0;
    struct raven_model saved_model;

    raven_filter_input(encoder->trial_table, input, source, size, capacity, filter_flags);
    raven_model_init(&encoder->model);
    encoder->finder.input = input;
    encoder->finder.limit = size < RAVEN_LITERAL_TAIL_SIZE ? 0 : size - RAVEN_LITERAL_TAIL_SIZE;
    encoder->finder.next_position = 1;
    encoder->finder.window_mask = RAVEN_WINDOW_SIZE - 1;
    encoder->finder.depth = 48;
    encoder->finder.nice_length = RAVEN_NICE_LENGTH;
    raven_store32(destination, UINT32_C(0xecca002b));

    while (size_hint_code < 63 && ((uint64_t)((size_hint_code & 3) | 4) << ((size_hint_code + 56) / 4)) < size) {
        ++size_hint_code;
    }
    raven_store32(destination + 4, size_hint_code << 26);
    while (position < size) {
        uint32_t block_size = size - position;
        uint32_t flags = filter_flags[position / RAVEN_BLOCK_SIZE];
        size_t payload_size;

        if (capacity - written < 4) {
            return 0;
        }
        if (block_size > RAVEN_BLOCK_SIZE) {
            block_size = RAVEN_BLOCK_SIZE;
        }
        saved_model = encoder->model;
        payload_size = raven_encode_block(encoder, event_buffer, destination + written + 4, capacity - written - 4, position, block_size);
        if (!payload_size || 100 * payload_size >= 99 * (size_t)block_size) {
            if (block_size > capacity - written - 4) {
                return 0;
            }
            payload_size = block_size;
            flags |= 1;
            memcpy(destination + written + 4, input + position, block_size);

            encoder->model = saved_model;
        }
        raven_store32(destination + written, ((uint32_t)payload_size << 12) | flags);
        written += payload_size + 4;
        position += block_size;
    }
    if (capacity - written < 4) {
        return 0;
    }
    raven_store32(destination + written, 0);

    if (lzraven_decode_buffer(input, size, destination, capacity) != size || (size && memcmp(input, source, size))) {
        return 0;
    }
    return written + 4;
}

size_t lzraven_encode_bound(size_t size)
{
    size_t overhead;

    if (size > RAVEN_MAX_INPUT_SIZE) {
        return 0;
    }
    overhead = 12 + 4 * (size / RAVEN_BLOCK_SIZE + (size % RAVEN_BLOCK_SIZE != 0));
    return size > SIZE_MAX - overhead ? 0 : size + overhead;
}

size_t lzraven_encode_buffer(void *destination, size_t capacity, const void *source, size_t size)
{
    struct raven_encoder *encoder;
    struct raven_event_buffer event_buffer;
    uint8_t *input;
    uint16_t *filter_flags;
    uint32_t (*children)[2];
    size_t block_limit;
    size_t tree_size;
    size_t result = 0;

    if (!destination || (!source && size) || capacity < 8 || !lzraven_encode_bound(size)) {
        return 0;
    }
    if (capacity > UINT32_MAX) {
        capacity = UINT32_MAX;
    }
    block_limit = size < RAVEN_BLOCK_SIZE ? size : RAVEN_BLOCK_SIZE;
    tree_size = size < RAVEN_LITERAL_TAIL_SIZE ? 0 : size - RAVEN_LITERAL_TAIL_SIZE;
    if (tree_size > RAVEN_WINDOW_SIZE) {
        tree_size = RAVEN_WINDOW_SIZE;
    }
    event_buffer.capacity = 4 * block_limit + 32;
    event_buffer.events = malloc(event_buffer.capacity * sizeof(*event_buffer.events));
    encoder = calloc(1, sizeof(*encoder));
    input = malloc(size ? size : 1);
    filter_flags = calloc(size / RAVEN_BLOCK_SIZE + 1, sizeof(*filter_flags));
    children = calloc(tree_size ? tree_size : 1, sizeof(*children));
    if (encoder && input && filter_flags && children && event_buffer.events) {
        encoder->finder.children = children;
        result = raven_encode_frame(encoder, &event_buffer, filter_flags, destination, capacity, source, input, (uint32_t)size);
    }
    free(children);
    free(filter_flags);
    free(input);
    free(encoder);
    free(event_buffer.events);
    return result;
}

size_t lzraven_decode_buffer(void *destination, size_t capacity, const void *source, size_t size)
{
    return lzraven_decode_buffer_with_scratch(destination, capacity, source, size, NULL);
}

size_t lzraven_decode_scratch_size(void)
{
    return RAVEN_DECODE_SCRATCH_SIZE;
}

size_t lzraven_decode_buffer_with_scratch(void *destination, size_t capacity, const void *source, size_t size, void *scratch)
{
    uint8_t *allocated;
    volatile uint8_t *erase;
    size_t result;
    size_t i;

    if (scratch) {
        return raven_decode_scratch(destination, capacity, source, size, scratch);
    }

    allocated = malloc(RAVEN_DECODE_SCRATCH_SIZE);
    if (!allocated) {
        return 0;
    }
    result = raven_decode_scratch(destination, capacity, source, size, allocated);

    erase = allocated;
    for (i = 0; i < RAVEN_DECODE_SCRATCH_SIZE; ++i) {
        erase[i] = 0;
    }
    free(allocated);
    return result;
}
