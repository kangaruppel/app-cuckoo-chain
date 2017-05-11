#include <msp430.h>
#undef N // conflicts with us

#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>

#include <libmsp/mem.h>
#include <libwispbase/wisp-base.h>
#include <libchain/chain.h>
#include <libmspmath/msp-math.h>

#include <libio/log.h>


// Add in mutex and thread headers 
#include <libchain/thread.h>
#include <libchain/mutex.h>

#ifdef CONFIG_LIBEDB_PRINTF
#include <libedb/edb.h>
#endif

#ifdef CONFIG_EDB
#include <libedb/edb.h>
#endif

#include "pins.h"

#include "../data/keysize.h"

/*--------------------------cuckoo defs and channels-----------------------------*/
#define NUM_INSERTS (NUM_BUCKETS / 4) // shoot for 25% occupancy
#define NUM_LOOKUPS NUM_INSERTS
#define NUM_BUCKETS 256//256 // must be a power of 2
#define MAX_RELOCATIONS 8

typedef uint16_t value_t;
typedef uint16_t hash_t;
typedef uint16_t fingerprint_t;
typedef uint16_t index_t; // bucket index

typedef struct _insert_count {
    unsigned insert_count;
    unsigned inserted_count;
} insert_count_t;

typedef struct _lookup_count {
    unsigned lookup_count;
    unsigned member_count;
} lookup_count_t;

struct msg_key {
    CHAN_FIELD(value_t, key);
};

struct msg_genkey {
    CHAN_FIELD(value_t, key);
    CHAN_FIELD(task_t*, next_task);
};

struct msg_calc_indexes {
    CHAN_FIELD(value_t, key);
    CHAN_FIELD(task_t*, next_task);
};

struct msg_self_key {
    SELF_CHAN_FIELD(value_t, key);
};
#define FIELD_INIT_msg_self_key {\
    SELF_FIELD_INITIALIZER \
}

struct msg_indexes {
    CHAN_FIELD(fingerprint_t, fingerprint);
    CHAN_FIELD(index_t, index1);
    CHAN_FIELD(index_t, index2);
};

struct msg_fingerprint {
    CHAN_FIELD(fingerprint_t, fingerprint);
};

struct msg_index1 {
    CHAN_FIELD(index_t, index1);
};

struct msg_filter {
    CHAN_FIELD_ARRAY(fingerprint_t, filter, NUM_BUCKETS);
};

struct msg_self_filter {
    SELF_CHAN_FIELD_ARRAY(fingerprint_t, filter, NUM_BUCKETS);
};
#define FIELD_INIT_msg_self_filter { \
    SELF_FIELD_ARRAY_INITIALIZER(NUM_BUCKETS) \
}

struct msg_filter_insert_done {
    CHAN_FIELD_ARRAY(fingerprint_t, filter, NUM_BUCKETS);
    CHAN_FIELD(bool, success);
};

struct msg_victim {
    CHAN_FIELD_ARRAY(fingerprint_t, filter, NUM_BUCKETS);
    CHAN_FIELD(fingerprint_t, fp_victim);
    CHAN_FIELD(index_t, index_victim);
    CHAN_FIELD(unsigned, relocation_count);
};

struct msg_self_victim {
    SELF_CHAN_FIELD_ARRAY(fingerprint_t, filter, NUM_BUCKETS);
    SELF_CHAN_FIELD(fingerprint_t, fp_victim);
    SELF_CHAN_FIELD(index_t, index_victim);
    SELF_CHAN_FIELD(unsigned, relocation_count);
};
#define FIELD_INIT_msg_self_victim { \
    SELF_FIELD_ARRAY_INITIALIZER(NUM_BUCKETS), \
    SELF_FIELD_INITIALIZER, \
    SELF_FIELD_INITIALIZER, \
    SELF_FIELD_INITIALIZER \
}

struct msg_hash_args {
    CHAN_FIELD(value_t, data);
    CHAN_FIELD(task_t*, next_task);
};

struct msg_hash {
    CHAN_FIELD(hash_t, hash);
};

struct msg_member {
    CHAN_FIELD(bool, member);
};

struct msg_lookup_result {
    CHAN_FIELD(value_t, key);
    CHAN_FIELD(bool, member);
};

struct msg_self_insert_count {
    SELF_CHAN_FIELD(unsigned, insert_count);
    SELF_CHAN_FIELD(unsigned, inserted_count);
};
#define FIELD_INIT_msg_self_insert_count {\
    SELF_FIELD_INITIALIZER, \
    SELF_FIELD_INITIALIZER \
}

struct msg_self_lookup_count {
    SELF_CHAN_FIELD(unsigned, lookup_count);
    SELF_CHAN_FIELD(unsigned, member_count);
};
#define FIELD_INIT_msg_self_lookup_count {\
    SELF_FIELD_INITIALIZER, \
    SELF_FIELD_INITIALIZER \
}

struct msg_insert_count {
    CHAN_FIELD(unsigned, insert_count);
    CHAN_FIELD(unsigned, inserted_count);
};

struct msg_lookup_count {
    CHAN_FIELD(unsigned, lookup_count);
    CHAN_FIELD(unsigned, member_count);
};

struct msg_inserted_count {
    CHAN_FIELD(unsigned, inserted_count);
};

struct msg_member_count {
    CHAN_FIELD(unsigned, member_count);
};

TASK(1,  task_init)
TASK(2,  task_generate_key)
TASK(3,  task_insert)
TASK(4,  task_calc_indexes)
TASK(15,  task_calc_indexes_index_1)
TASK(6,  task_calc_indexes_index_2)
TASK(7,  task_add) // TODO: rename: add 'insert' prefix
TASK(8,  task_relocate)
TASK(9,  task_insert_done)
TASK(10, task_lookup)
TASK(11, task_lookup_search)
TASK(12, task_lookup_done)
TASK(13, task_print_stats)
TASK(14, task_done)

CHANNEL(task_init, task_generate_key, msg_genkey);
CHANNEL(task_init, task_insert_done, msg_insert_count);
CHANNEL(task_init, task_lookup_done, msg_lookup_count);
MULTICAST_CHANNEL(msg_key, ch_key, task_generate_key, task_insert, task_lookup);
SELF_CHANNEL(task_insert, msg_self_key);
MULTICAST_CHANNEL(msg_filter, ch_filter, task_init,
                  task_add, task_relocate, task_insert_done,
                  task_lookup_search, task_print_stats);
MULTICAST_CHANNEL(msg_filter, ch_filter_add, task_add,
                  tsk_relocate, task_insert_done, task_lookup_search,
                  task_print_stats);
MULTICAST_CHANNEL(msg_filter, ch_filter_relocate, task_relocate,
                  task_add, task_insert_done, task_lookup_search,
                  task_print_stats);
CALL_CHANNEL(ch_calc_indexes, msg_calc_indexes);
RET_CHANNEL(ch_calc_indexes, msg_indexes);
CHANNEL(task_calc_indexes, task_calc_indexes_index_2, msg_fingerprint);
CHANNEL(task_calc_indexes_index_1, task_calc_indexes_index_2, msg_index1);
CHANNEL(task_add, task_relocate, msg_victim);
SELF_CHANNEL(task_add, msg_self_filter);
CHANNEL(task_add, task_insert_done, msg_filter_insert_done);
MULTICAST_CHANNEL(msg_filter, ch_reloc_filter, task_relocate,
                  task_add, task_insert_done);
SELF_CHANNEL(task_relocate, msg_self_victim);
CHANNEL(task_relocate, task_add, msg_filter);
CHANNEL(task_relocate, task_insert_done, msg_filter_insert_done);
CHANNEL(task_lookup, task_lookup_done, msg_lookup_result);
SELF_CHANNEL(task_insert_done, msg_self_insert_count);
SELF_CHANNEL(task_lookup_done, msg_self_lookup_count);
CHANNEL(task_insert_done, task_generate_key, msg_genkey);
CHANNEL(task_lookup_done, task_generate_key, msg_genkey);
CHANNEL(task_insert_done, task_print_stats, msg_inserted_count);
CHANNEL(task_lookup_done, task_print_stats, msg_member_count);
SELF_CHANNEL(task_generate_key, msg_self_key);
CHANNEL(task_lookup_search, task_lookup_done, msg_member);

/*--------------------------rsa defs and channels-----------------------------*/
#define DIGIT_BITS 8
#define DIGIT_MASK 0x00ff
#define NUM_DIGITS (KEY_SIZE_BITS / DIGIT_BITS)
//Pay no attention to the hardcoded value behind the curtain... 
#define NUM_DIGITS_x2 32


typedef uint16_t digit_t;

typedef struct {
    uint8_t n[NUM_DIGITS]; // modulus
    digit_t e;  // exponent
} pubkey_t;

#if NUM_DIGITS < 2
#error The modular reduction implementation requires at least 2 digits
#endif

#define LED1 (1 << 0)
#define LED2 (1 << 1)

#define SEC_TO_CYCLES 4000000 /* 4 MHz */

#define BLINK_DURATION_BOOT (5 * SEC_TO_CYCLES)
#define BLINK_DURATION_TASK SEC_TO_CYCLES
#define BLINK_BLOCK_DONE    (1 * SEC_TO_CYCLES)
#define BLINK_MESSAGE_DONE  (2 * SEC_TO_CYCLES)

#define PRINT_HEX_ASCII_COLS 8

// #define SHOW_PROGRESS_ON_LED
// #define SHOW_COARSE_PROGRESS_ON_LED

// Blocks are padded with these digits (on the MSD side). Padding value must be
// chosen such that block value is less than the modulus. This is accomplished
// by any value below 0x80, because the modulus is restricted to be above
// 0x80 (see comments below).
static const uint8_t PAD_DIGITS[] = { 0x01 };
#define NUM_PAD_DIGITS (sizeof(PAD_DIGITS) / sizeof(PAD_DIGITS[0]))

// To generate a key pair: see scripts/

// modulus: byte order: LSB to MSB, constraint MSB>=0x80
static __ro_nv const pubkey_t pubkey = {
#include "../data/key.txt"
};

static __ro_nv const unsigned char PLAINTEXT[] =
#include "../data/plaintext.txt"
;

#define NUM_PLAINTEXT_BLOCKS (sizeof(PLAINTEXT) / (NUM_DIGITS - NUM_PAD_DIGITS) + 1)
#define CYPHERTEXT_SIZE (NUM_PLAINTEXT_BLOCKS * NUM_DIGITS)

// If you link-in wisp-base, then you have to define some symbols.
uint8_t usrBank[USRBANK_SIZE];

struct msg_mult_mod_args {
    CHAN_FIELD_ARRAY(digit_t, A, NUM_DIGITS);
    CHAN_FIELD_ARRAY(digit_t, B, NUM_DIGITS);
    CHAN_FIELD(task_t*, next_task);
};

struct msg_mult_mod_result {
    CHAN_FIELD_ARRAY(digit_t, R, NUM_DIGITS);
};

struct msg_mult{
    CHAN_FIELD_ARRAY(digit_t, A, NUM_DIGITS); 
    CHAN_FIELD_ARRAY(digit_t, B, NUM_DIGITS);
    CHAN_FIELD(unsigned, digit);
    CHAN_FIELD(unsigned, carry);
};

struct msg_reduce {
    CHAN_FIELD_ARRAY(digit_t, N, NUM_DIGITS);
    CHAN_FIELD_ARRAY(digit_t, M, NUM_DIGITS);
    CHAN_FIELD(task_t*, next_task);
};

struct msg_modulus {
    CHAN_FIELD_ARRAY(digit_t, N, NUM_DIGITS);
};

struct msg_exponent {
    CHAN_FIELD(digit_t, E);
};

struct msg_self_exponent {
    SELF_CHAN_FIELD(digit_t, E);
};
#define FIELD_INIT_msg_self_exponent { \
    SELF_FIELD_INITIALIZER \
}

struct msg_mult_digit {
    CHAN_FIELD(unsigned, digit);
    CHAN_FIELD(unsigned, carry);
};

struct msg_self_mult_digit {
    SELF_CHAN_FIELD(unsigned, digit);
    SELF_CHAN_FIELD(unsigned, carry);
};
#define FIELD_INIT_msg_self_mult_digit { \
    SELF_FIELD_INITIALIZER, \
    SELF_FIELD_INITIALIZER \
}

struct msg_product {
    CHAN_FIELD_ARRAY(digit_t, product, 32);
};

struct msg_self_product {
    SELF_CHAN_FIELD_ARRAY(digit_t, product, 32);
};
#define FIELD_INIT_msg_self_product { \
    SELF_FIELD_ARRAY_INITIALIZER(32) \
}

struct msg_base {
    CHAN_FIELD_ARRAY(digit_t, base, NUM_DIGITS_x2);
};

struct msg_block {
    CHAN_FIELD_ARRAY(digit_t, block, NUM_DIGITS_x2);
};

struct msg_base_block {
    CHAN_FIELD_ARRAY(digit_t, base, NUM_DIGITS_x2);
    CHAN_FIELD_ARRAY(digit_t, block, NUM_DIGITS_x2);
};

struct msg_cyphertext_len {
    CHAN_FIELD(unsigned, cyphertext_len);
};

struct msg_self_cyphertext_len {
    SELF_CHAN_FIELD(unsigned, cyphertext_len);
};
#define FIELD_INIT_msg_self_cyphertext_len { \
    SELF_FIELD_INITIALIZER \
}

struct msg_cyphertext {
    CHAN_FIELD_ARRAY(digit_t, cyphertext, CYPHERTEXT_SIZE);
    CHAN_FIELD(unsigned, cyphertext_len);
};

struct msg_divisor {
    CHAN_FIELD(unsigned, digit);
    CHAN_FIELD(digit_t, n_div);
};

struct msg_digit {
    CHAN_FIELD(unsigned, digit);
};

struct msg_self_digit {
    SELF_CHAN_FIELD(unsigned, digit);
};
#define FIELD_INIT_msg_self_digit { \
    SELF_FIELD_INITIALIZER \
}

struct msg_offset {
    CHAN_FIELD(unsigned, offset);
};

struct msg_block_offset {
    CHAN_FIELD(unsigned, block_offset);
};

struct msg_self_block_offset {
    SELF_CHAN_FIELD(unsigned, block_offset);
};
#define FIELD_INIT_msg_self_block_offset {\
    SELF_FIELD_INITIALIZER \
}

struct msg_message_info {
    CHAN_FIELD(unsigned, message_length);
    CHAN_FIELD(unsigned, block_offset);
    CHAN_FIELD(digit_t, E);
};

struct msg_quotient {
    CHAN_FIELD(digit_t, quotient);
};

struct msg_print {
    CHAN_FIELD_ARRAY(digit_t, product, NUM_DIGITS_x2);
    CHAN_FIELD(task_t*, next_task);
};

TASK(22,  task_pad)
TASK(23,  task_exp)
TASK(24,  task_mult_block)
TASK(25,  task_mult_block_get_result)
TASK(26,  task_square_base)
TASK(27,  task_square_base_get_result)
TASK(28,  task_print_cyphertext)
TASK(29,  task_mult_mod)
TASK(30,  task_mult)
TASK(31, task_reduce_digits)
TASK(16, task_reduce_normalizable)
TASK(17, task_reduce_normalize)
TASK(18, task_reduce_n_divisor)
TASK(19, task_reduce_quotient)
TASK(20, task_reduce_multiply)
TASK(21, task_reduce_compare)
//Use extension to chain task definition 
//TASK(32, task_reduce_add)
//TASK(33, task_reduce_subtract)
//TASK(34, task_print_product)
TASK_EXT(18, task_reduce_add)
TASK_EXT(19, task_reduce_subtract)
TASK_EXT(20, task_print_product)

MULTICAST_CHANNEL(msg_base, ch_base, task_init, task_square_base, task_mult_block);
CHANNEL(task_init, task_pad, msg_message_info);
CHANNEL(task_init, task_mult_block_get_result, msg_cyphertext_len);
CHANNEL(task_pad, task_exp, msg_exponent);
CHANNEL(task_pad, task_mult_block, msg_block);
SELF_CHANNEL(task_pad, msg_self_block_offset);
MULTICAST_CHANNEL(msg_base, ch_base, task_pad, task_mult_block, task_square_base);
SELF_CHANNEL(task_exp, msg_self_exponent);
CHANNEL(task_exp, task_mult_block_get_result, msg_exponent);
CHANNEL(task_mult_block_get_result, task_mult_block, msg_block);
SELF_CHANNEL(task_mult_block_get_result, msg_self_cyphertext_len);
CHANNEL(task_mult_block_get_result, task_print_cyphertext, msg_cyphertext);
MULTICAST_CHANNEL(msg_base, ch_square_base, task_square_base_get_result,
                  task_square_base, task_mult_block);
CALL_CHANNEL(ch_mult_mod, msg_mult_mod_args);
RET_CHANNEL(ch_mult_mod, msg_product);
CHANNEL(task_mult_mod, task_mult, msg_mult);
MULTICAST_CHANNEL(msg_modulus, ch_modulus, task_init,
                  task_reduce_normalizable, task_reduce_normalize,
                  task_reduce_n_divisor, task_reduce_quotient, task_reduce_multiply);
SELF_CHANNEL(task_mult, msg_self_mult_digit);
MULTICAST_CHANNEL(msg_product, ch_mult_product, task_mult,
                  task_reduce_normalizable, task_reduce_normalize,
                  task_reduce_quotient, task_reduce_compare,
                  task_reduce_add, task_reduce_subtract);
MULTICAST_CHANNEL(msg_digit, ch_digit, task_reduce_digits,
                  task_reduce_normalizable, task_reduce_quotient);
CHANNEL(task_reduce_normalizable, task_reduce_normalize, msg_offset);
// TODO: rename 'product' to 'block' or something
MULTICAST_CHANNEL(msg_product, ch_product, task_mult,
                  task_reduce_digits, task_reduce_n_divisor,
                  task_reduce_normalizable, task_reduce_normalize,
                  task_reduce_quotient, task_reduce_compare,
                  task_reduce_add, task_reduce_subtract);
MULTICAST_CHANNEL(msg_product, ch_normalized_product, task_reduce_normalize,
                  task_reduce_quotient, task_reduce_compare,
                  task_reduce_add, task_reduce_subtract);
CHANNEL(task_reduce_add, task_reduce_subtract, msg_product);
MULTICAST_CHANNEL(msg_product, ch_reduce_subtract_product, task_reduce_subtract,
                  task_reduce_quotient, task_reduce_compare, task_reduce_add);
SELF_CHANNEL(task_reduce_subtract, msg_self_product);
CHANNEL(task_reduce_n_divisor, task_reduce_quotient, msg_divisor);
SELF_CHANNEL(task_reduce_quotient, msg_self_digit);
MULTICAST_CHANNEL(msg_digit, ch_reduce_digit, task_reduce_quotient,
                  task_reduce_multiply, task_reduce_compare,
                  task_reduce_add, task_reduce_subtract);
CHANNEL(task_reduce_quotient, task_reduce_multiply, msg_quotient);
MULTICAST_CHANNEL(msg_product, ch_qn, task_reduce_multiply,
                  task_reduce_compare, task_reduce_subtract);
CALL_CHANNEL(ch_print_product, msg_print);



/*--------------------------cuckoo inits and functions----------------------------*/

static value_t init_key = 0x0001; // seeds the pseudo-random sequence of keys

static hash_t djb_hash(uint8_t* data, unsigned len)
{
   uint32_t hash = 5381;
   unsigned int i;

   for(i = 0; i < len; data++, i++)
      hash = ((hash << 5) + hash) + (*data);

   return hash & 0xFFFF;
}

static index_t hash_to_index(fingerprint_t fp)
{
    hash_t hash = djb_hash((uint8_t *)&fp, sizeof(fingerprint_t));
    return hash & (NUM_BUCKETS - 1); // NUM_BUCKETS must be power of 2
}

static fingerprint_t hash_to_fingerprint(value_t key)
{
    return djb_hash((uint8_t *)&key, sizeof(value_t));
}

/*----------------------------rsa  inits and functions----------------------------*/

#ifdef SHOW_PROGRESS_ON_LED
static void delay(uint32_t cycles)
{
    unsigned i;
    for (i = 0; i < cycles / (1U << 15); ++i)
        __delay_cycles(1U << 15);
}

static void blink(unsigned count, uint32_t duration, unsigned leds)
{
    unsigned i;
    for (i = 0; i < count; ++i) {
        GPIO(PORT_LED_1, OUT) |= (leds & LED1) ? BIT(PIN_LED_1) : 0x0;
        GPIO(PORT_LED_2, OUT) |= (leds & LED2) ? BIT(PIN_LED_2) : 0x0;
        delay(duraTIOn / 2);
        GPIO(PORT_LED_1, OUT) &= (leds & LED1) ? ~BIT(PIN_LED_1) : ~0x0;
        GPIO(PORT_LED_2, OUT) &= (leds & LED2) ? ~BIT(PIN_LED_2) : ~0x0;
        delay(duration / 2);
    }
}
#endif

static void print_hex_ascii(const uint8_t *m, unsigned len)
{
    int i, j;

    for (i = 0; i < len; i += PRINT_HEX_ASCII_COLS) {
        for (j = 0; j < PRINT_HEX_ASCII_COLS && i + j < len; ++j)
            printf("%02x ", m[i + j]);
        for (; j < PRINT_HEX_ASCII_COLS; ++j)
            printf("   ");
        printf(" ");
        for (j = 0; j < PRINT_HEX_ASCII_COLS && i + j < len; ++j) {
            char c = m[i + j];
            if (!(32 <= c && c <= 127)) // not printable
                c = '.';
            printf("%c", c);
        }
        printf("\r\n");
    }
}


/*-------------------------Joint init task -------------------------------*/

void task_init()
{
    task_prologue();
    unsigned i;
/*--------------------------thread_init call!!-----------------------------*/
    thread_init(); 

/*-----------------------Cuckoo app init start-----------------------------*/

    LOG("init\r\n");

    for (i = 0; i < NUM_BUCKETS; ++i) {
        fingerprint_t fp = 0;
        CHAN_OUT1(fingerprint_t, filter[i], fp, MC_OUT_CH(ch_filter, task_init,
                               task_add, task_relocate, task_insert_done,
                               task_lookup_search, task_print_stats));
    }

    unsigned count = 0;
    CHAN_OUT1(unsigned, insert_count, count, CH(task_init, task_insert_done));
    CHAN_OUT1(unsigned, lookup_count, count, CH(task_init, task_lookup_done));

    CHAN_OUT1(unsigned, inserted_count, count, CH(task_init, task_insert_done));
    CHAN_OUT1(unsigned, member_count, count, CH(task_init, task_lookup_done));

    CHAN_OUT1(value_t, key, init_key, CH(task_init, task_generate_key));
    task_t *next_task = TASK_REF(task_insert);
    CHAN_OUT1(task_t *, next_task, next_task, CH(task_init, task_generate_key));
/*-------------------------RSA  app init start----------------------------*/
    
    unsigned message_length = sizeof(PLAINTEXT) - 1; // skip the terminating null byte

    LOG("init\r\n");

#ifdef SHOW_COARSE_PROGRESS_ON_LED
    blink(1, BLINK_DURATION_BOOT, LED1 | LED2);
#endif

    printf("Message:\r\n"); print_hex_ascii(PLAINTEXT, message_length);
    printf("Public key: exp = 0x%x  N = \r\n", pubkey.e);
    print_hex_ascii(pubkey.n, NUM_DIGITS);

    LOG("init: out modulus\r\n");

    // TODO: consider passing pubkey as a structure type
    for (i = 0; i < NUM_DIGITS; ++i) {
        CHAN_OUT1(digit_t, N[i], pubkey.n[i], MC_OUT_CH(ch_modulus, task_init,
                 task_reduce_normalizable, task_reduce_normalize,
                 task_reduce_m_divisor, task_reduce_quotient,
                 task_reduce_multiply, task_reduce_add));
    }

    LOG("init: out exp\r\n");

    unsigned zero = 0;
    CHAN_OUT1(digit_t, E, pubkey.e, CH(task_init, task_pad));
    CHAN_OUT1(unsigned, message_length, message_length, CH(task_init, task_pad));
    CHAN_OUT1(unsigned, block_offset, zero, CH(task_init, task_pad));
    CHAN_OUT1(unsigned, cyphertext_len, zero, CH(task_init, task_mult_block_get_result));

    LOG("init: done\r\n");

/*-----------------------THREAD_CREATE calls to separate programs--------------------------*/
    THREAD_CREATE(task_generate_key); 
    THREAD_CREATE(task_pad); 
    TRANSITION_TO_MT(task_pad);
}


/*-----------------------cuckoo filter tasks start--------------------------------------*/ 
void task_generate_key()
{
    task_prologue();

    value_t key = *CHAN_IN4(value_t, key, CH(task_init, task_generate_key),
                                          CH(task_insert_done, task_generate_key),
                                          CH(task_lookup_done, task_generate_key),
                                          SELF_IN_CH(task_generate_key));

    // insert pseufo-random integers, for testing
    // If we use consecutive ints, they hash to consecutive DJB hashes...
    // NOTE: we are not using rand(), to have the sequence available to verify
    // that that are no false negatives (and avoid having to save the values).
    key = (key + 1) * 17;

    LOG("generate_key: key: %x\r\n", key);

    CHAN_OUT2(value_t, key, key, MC_OUT_CH(ch_key, task_generate_key,
                                           task_fingerprint, task_lookup),
                                 SELF_OUT_CH(task_generate_key));

    task_t *next_task = *CHAN_IN2(task_t *, next_task,
                                  CH(task_init, task_generate_key),
                                  CH(task_insert_done, task_generate_key));
    transition_to_mt(next_task);
}

void task_calc_indexes()
{
    task_prologue();

    value_t key = *CHAN_IN1(value_t, key, CALL_CH(ch_calc_indexes));

    fingerprint_t fp = hash_to_fingerprint(key);
    LOG("calc indexes: fingerprint: key %04x fp %04x\r\n", key, fp);

    CHAN_OUT2(fingerprint_t, fingerprint, fp,
              CH(task_calc_indexes, task_calc_indexes_index_2),
              RET_CH(ch_calc_indexes));

    TRANSITION_TO_MT(task_calc_indexes_index_1);
}

void task_calc_indexes_index_1()
{
    task_prologue();
    LOG("CALC_INDEXES_cuckoo\r\n"); 

    value_t key = *CHAN_IN1(value_t, key, CALL_CH(ch_calc_indexes));

    index_t index1 = hash_to_index(key);
    LOG("calc indexes: index1: key %04x idx1 %u\r\n", key, index1);

    CHAN_OUT2(index_t, index1, index1,
              CH(task_calc_indexes_index_1, task_calc_indexes_index_2),
              RET_CH(ch_calc_indexes));

    TRANSITION_TO_MT(task_calc_indexes_index_2);
}

void task_calc_indexes_index_2()
{
    task_prologue();
    LOG("CALC_INDEXES_2_cuckoo\r\n"); 
    fingerprint_t fp = *CHAN_IN1(fingerprint_t, fingerprint,
                                 CH(task_calc_indexes, task_calc_indexes_index_2));
    index_t index1 = *CHAN_IN1(index_t, index1,
                               CH(task_calc_indexes_index_1, task_calc_indexes_index_2));

    index_t fp_hash = hash_to_index(fp);
    index_t index2 = index1 ^ fp_hash;

    LOG("calc indexes: index2: fp hash: %04x idx1 %u idx2 %u\r\n",
        fp_hash, index1, index2);

    CHAN_OUT1(index_t, index2, index2, RET_CH(ch_calc_indexes));

    task_t *next_task = *CHAN_IN1(task_t *, next_task,
                                  CALL_CH(ch_calc_indexes));
    transition_to_mt(next_task);
}

// This task is a somewhat redundant proxy. But it will be a callable
// task and also be responsible for making the call to calc_index.
void task_insert()
{
    task_prologue();
    LOG("TASK_INSERT_cuckoo\r\n"); 
    value_t key = *CHAN_IN1(value_t, key,
                            MC_IN_CH(ch_key, task_generate_key, task_insert));

    LOG("insert: key %04x\r\n", key);

    CHAN_OUT1(value_t, key, key, CALL_CH(ch_calc_indexes));

    task_t *next_task = TASK_REF(task_add);
    CHAN_OUT1(task_t *, next_task, next_task, CALL_CH(ch_calc_indexes));
    TRANSITION_TO_MT(task_calc_indexes);
}


void task_add()
{
    task_prologue();
    LOG("TASK_ADD_cuckoo\r\n");

    bool success = true;

    // Fingerprint being inserted
    fingerprint_t fp = *CHAN_IN1(fingerprint_t, fingerprint,
                                 RET_CH(ch_calc_indexes));
    LOG("add: fp %04x\r\n", fp);

    // index1,fp1 and index2,fp2 are the two alternative buckets

    index_t index1 = *CHAN_IN1(index_t, index1, RET_CH(ch_calc_indexes));

    fingerprint_t fp1 = *CHAN_IN3(fingerprint_t, filter[index1],
                                 MC_IN_CH(ch_filter, task_init, task_add),
                                 CH(task_relocate, task_add),
                                 SELF_IN_CH(task_add));
    LOG("add: idx1 %u fp1 %04x\r\n", index1, fp1);

    if (!fp1) {
        LOG("add: filled empty slot at idx1 %u\r\n", index1);

        CHAN_OUT2(fingerprint_t, filter[index1], fp,
                  MC_OUT_CH(ch_filter_add, task_add,
                            task_relocate, task_insert_done,
                            task_lookup_search, task_print_stats),
                  SELF_OUT_CH(task_add));

        CHAN_OUT1(bool, success, success, CH(task_add, task_insert_done));
        TRANSITION_TO_MT(task_insert_done);
    } else {
        index_t index2 = *CHAN_IN1(index_t, index2, RET_CH(ch_calc_indexes));
        fingerprint_t fp2 = *CHAN_IN3(fingerprint_t, filter[index2],
                                     MC_IN_CH(ch_filter, task_init, task_add),
                                     CH(task_relocate, task_add),
                                     SELF_IN_CH(task_add));
        LOG("add: fp2 %04x\r\n", fp2);

        if (!fp2) {
            LOG("add: filled empty slot at idx2 %u\r\n", index2);

            CHAN_OUT2(fingerprint_t, filter[index2], fp,
                      MC_OUT_CH(ch_filter_add, task_add,
                                task_relocate, task_insert_done, task_lookup_search),
                      SELF_OUT_CH(task_add));

            CHAN_OUT1(bool, success, success, CH(task_add, task_insert_done));
            TRANSITION_TO_MT(task_insert_done);
        } else { // evict one of the two entries
            fingerprint_t fp_victim;
            index_t index_victim;

            if (rand() % 2) {
                index_victim = index1;
                fp_victim = fp1;
            } else {
                index_victim = index2;
                fp_victim = fp2;
            }

            LOG("add: evict [%u] = %04x\r\n", index_victim, fp_victim);

            // Evict the victim
            CHAN_OUT2(fingerprint_t, filter[index_victim], fp,
                      MC_OUT_CH(ch_filter_add, task_add,
                                task_relocate, task_insert_done, task_lookup_search),
                      SELF_OUT_CH(task_add));

            CHAN_OUT1(index_t, index_victim, index_victim, CH(task_add, task_relocate));
            CHAN_OUT1(fingerprint_t, fp_victim, fp_victim, CH(task_add, task_relocate));
            unsigned relocation_count = 0;
            CHAN_OUT1(unsigned, relocation_count, relocation_count,
                      CH(task_add, task_relocate));

            TRANSITION_TO_MT(task_relocate);
        }
    }
}

void task_relocate()
{
    task_prologue();
    LOG("TASK_RELOCATE_cuckoo\r\n");

    fingerprint_t fp_victim = *CHAN_IN2(fingerprint_t, fp_victim,
                                        CH(task_add, task_relocate),
                                        SELF_IN_CH(task_relocate));

    index_t index1_victim = *CHAN_IN2(index_t, index_victim,
                                      CH(task_add, task_relocate),
                                      SELF_IN_CH(task_relocate));

    index_t fp_hash_victim = hash_to_index(fp_victim);
    index_t index2_victim = index1_victim ^ fp_hash_victim;

    LOG("relocate: victim fp hash %04x idx1 %u idx2 %u\r\n",
        fp_hash_victim, index1_victim, index2_victim);

    fingerprint_t fp_next_victim =
        *CHAN_IN3(fingerprint_t, filter[index2_victim],
                  MC_IN_CH(ch_filter, task_init, task_relocate),
                  MC_IN_CH(ch_filter_add, task_add, task_relocate),
                  SELF_IN_CH(task_relocate));

    LOG("relocate: next victim fp %04x\r\n", fp_next_victim);

    // Take victim's place
    CHAN_OUT2(fingerprint_t, filter[index2_victim], fp_victim,
             MC_OUT_CH(ch_filter_relocate, task_relocate,
                       task_add, task_insert_done, task_lookup_search,
                       task_print_stats),
             SELF_OUT_CH(task_relocate));

    if (!fp_next_victim) { // slot was free
        bool success = true;
        CHAN_OUT1(bool, success, success, CH(task_relocate, task_insert_done));
        TRANSITION_TO_MT(task_insert_done);
    } else { // slot was occupied, rellocate the next victim

        unsigned relocation_count = *CHAN_IN2(unsigned, relocation_count,
                                              CH(task_add, task_relocate),
                                              SELF_IN_CH(task_relocate));

        LOG("relocate: relocs %u\r\n", relocation_count);

        if (relocation_count >= MAX_RELOCATIONS) { // insert failed
            LOG("relocate: max relocs reached: %u\r\n", relocation_count);
            PRINTF("insert: lost fp %04x\r\n", fp_next_victim);
            bool success = false;
            CHAN_OUT1(bool, success, success, CH(task_relocate, task_insert_done));
            TRANSITION_TO_MT(task_insert_done);
        }

        relocation_count++;
        CHAN_OUT1(unsigned, relocation_count, relocation_count,
                 SELF_OUT_CH(task_relocate));

        CHAN_OUT1(index_t, index_victim, index2_victim, SELF_OUT_CH(task_relocate));
        CHAN_OUT1(fingerprint_t, fp_victim, fp_next_victim, SELF_OUT_CH(task_relocate));

        TRANSITION_TO_MT(task_relocate);
    }
}

void task_insert_done()
{
    task_prologue();
    LOG("TASK_INSERT_DONE_cuckoo\r\n"); 

//#if VERBOSE > 0
    unsigned i;

    LOG("insert done: filter:\r\n");
    for (i = 0; i < NUM_BUCKETS; ++i) {
        fingerprint_t fp = *CHAN_IN3(fingerprint_t, filter[i],
                 MC_IN_CH(ch_filter, task_init, task_insert_done),
                 MC_IN_CH(ch_filter_add, task_add, task_insert_done),
                 MC_IN_CH(ch_filter_relocate, task_relocate, task_insert_done));

        LOG("%04x ", fp);
        if (i > 0 && (i + 1) % 8 == 0)
            LOG("\r\n");
    }
    LOG("\r\n");
//#endif

    unsigned insert_count = *CHAN_IN2(unsigned, insert_count,
                                      CH(task_init, task_insert_done),
                                      SELF_IN_CH(task_insert_done));
    insert_count++;
    CHAN_OUT1(unsigned, insert_count, insert_count, SELF_OUT_CH(task_insert_done));

    bool success = *CHAN_IN2(bool, success,
                             CH(task_add, task_insert_done),
                             CH(task_relocate, task_insert_done));

    unsigned inserted_count = *CHAN_IN2(unsigned, inserted_count,
                                        CH(task_init, task_insert_done),
                                        SELF_IN_CH(task_insert_done));
    inserted_count += success;
    CHAN_OUT1(unsigned, inserted_count, inserted_count, SELF_OUT_CH(task_insert_done));

    LOG("insert done: insert %u inserted %u\r\n", insert_count, inserted_count);

#ifdef CONT_POWER
    volatile uint32_t delay = 0x8ffff;
    while (delay--);
#endif

    if (insert_count < NUM_INSERTS) {
        task_t *next_task = TASK_REF(task_insert);
        CHAN_OUT1(task_t *, next_task, next_task, CH(task_insert_done, task_generate_key));
        TRANSITION_TO_MT(task_generate_key);
    } else {
        CHAN_OUT1(unsigned, inserted_count, inserted_count,
                  CH(task_insert_done, task_print_stats));

        task_t *next_task = TASK_REF(task_lookup);
        CHAN_OUT1(value_t, key, init_key, CH(task_insert_done, task_generate_key));
        CHAN_OUT1(task_t *, next_task, next_task, CH(task_insert_done, task_generate_key));
        TRANSITION_TO_MT(task_generate_key);
    }
}

void task_lookup()
{
    task_prologue();
    LOG("TASK_LOOKUP_cuckoo\r\n"); 

    value_t key = *CHAN_IN1(value_t, key,
                            MC_IN_CH(ch_key, task_generate_key,task_lookup));
    LOG("lookup: key %04x\r\n", key);

    CHAN_OUT2(value_t, key, key, CALL_CH(ch_calc_indexes),
                                 CH(task_lookup, task_lookup_done));
    
    task_t *next_task = TASK_REF(task_lookup_search);
    CHAN_OUT1(task_t *, next_task, next_task, CALL_CH(ch_calc_indexes));
    TRANSITION_TO_MT(task_calc_indexes);
}

void task_lookup_search()
{
    task_prologue();
    LOG("TASK_LOOKUP_SEARCH_cuckoo\r\n"); 

    fingerprint_t fp1, fp2;
    bool member = false;

    index_t index1 = *CHAN_IN1(index_t, index1, RET_CH(ch_calc_indexes));
    index_t index2 = *CHAN_IN1(index_t, index2, RET_CH(ch_calc_indexes));
    fingerprint_t fp = *CHAN_IN1(fingerprint_t, fingerprint, RET_CH(ch_calc_indexes));

    LOG("lookup search: fp %04x idx1 %u idx2 %u\r\n", fp, index1, index2);

    fp1 = *CHAN_IN3(fingerprint_t, filter[index1],
                    MC_IN_CH(ch_filter, task_init, task_lookup_search),
                    MC_IN_CH(ch_filter_add, task_add, task_lookup_search),
                    MC_IN_CH(ch_filter_relocate, task_relocate, task_lookup_search));
    LOG("lookup search: fp1 %04x\r\n", fp1);

    if (fp1 == fp) {
        member = true;
    } else {
        fp2 = *CHAN_IN3(fingerprint_t, filter[index2],
                MC_IN_CH(ch_filter, task_init, task_lookup_search),
                MC_IN_CH(ch_filter_add, task_add, task_lookup_search),
                MC_IN_CH(ch_filter_relocate, task_relocate, task_lookup_search));
        LOG("lookup search: fp2 %04x\r\n", fp2);

        if (fp2 == fp) {
            member = true;
        }
    }

    LOG("lookup search: fp %04x member %u\r\n", fp, member);
    CHAN_OUT1(bool, member, member, CH(task_lookup_search, task_lookup_done));

    if (!member) {
        PRINTF("lookup: key %04x not member\r\n", fp);
    }

    TRANSITION_TO_MT(task_lookup_done);
}

void task_lookup_done()
{
    task_prologue();
    LOG("TASK_LOOKUP_DONE_cuckoo\r\n"); 

    bool member = *CHAN_IN1(bool, member, CH(task_lookup_search, task_lookup_done));

    unsigned lookup_count = *CHAN_IN2(unsigned, lookup_count,
                                      CH(task_init, task_lookup_done),
                                      SELF_IN_CH(task_lookup_done));


    lookup_count++;
    CHAN_OUT1(unsigned, lookup_count, lookup_count, SELF_OUT_CH(task_lookup_done));

//#if VERBOSE > 1
    value_t key = *CHAN_IN1(value_t, key, CH(task_lookup, task_lookup_done));
    LOG("lookup done [%u]: key %04x member %u\r\n", lookup_count, key, member);
//#endif

    unsigned member_count = *CHAN_IN2(bool, member_count,
                                      CH(task_init, task_lookup_done),
                                      SELF_IN_CH(task_lookup_done));


    member_count += member;
    CHAN_OUT1(unsigned, member_count, member_count, SELF_OUT_CH(task_lookup_done));

    LOG("lookup done: lookups %u members %u\r\n", lookup_count, member_count);

#ifdef CONT_POWER
    volatile uint32_t delay = 0x8ffff;
    while (delay--);
#endif

    if (lookup_count < NUM_LOOKUPS) {
        task_t *next_task = TASK_REF(task_lookup);
        CHAN_OUT1(task_t *, next_task, next_task, CH(task_lookup_done, task_generate_key));
        TRANSITION_TO_MT(task_generate_key);
    } else {
        CHAN_OUT1(unsigned, member_count, member_count,
                  CH(task_lookup_done, task_print_stats));
        TRANSITION_TO_MT(task_print_stats);
    }
}

void task_print_stats()
{
    task_prologue();
    LOG("TASK_PRINT_STATS_cuckoo\r\n"); 

    unsigned i;

    unsigned inserted_count = *CHAN_IN1(unsigned, inserted_count,
                                     CH(task_insert_done, task_print_stats));
    unsigned member_count = *CHAN_IN1(unsigned, member_count,
                                     CH(task_lookup_done, task_print_stats));

    PRINTF("stats: inserts %u members %u total %u\r\n",
           inserted_count, member_count, NUM_INSERTS);

    BLOCK_PRINTF_BEGIN();
    BLOCK_PRINTF("filter:\r\n");
    for (i = 0; i < NUM_BUCKETS; ++i) {
        fingerprint_t fp = *CHAN_IN3(fingerprint_t, filter[i],
                 MC_IN_CH(ch_filter, task_init, task_print_stats),
                 MC_IN_CH(ch_filter_add, task_add, task_print_stats),
                 MC_IN_CH(ch_filter_relocate, task_relocate, task_print_stats));

        BLOCK_PRINTF("%04x ", fp);
        if (i > 0 && (i + 1) % 8 == 0)
            BLOCK_PRINTF("\r\n");
    }
    BLOCK_PRINTF_END();

    TRANSITION_TO_MT(task_done);
}
/*-------------------------------RSA tasks--------------------------------*/

void task_pad()
{
    int i;
    unsigned block_offset, message_length;
    digit_t m, e;

#ifdef SHOW_COARSE_PROGRESS_ON_LED
    GPIO(PORT_LED_1, OUT) &= ~BIT(PIN_LED_1);
#endif

    block_offset = *CHAN_IN2(unsigned, block_offset, CH(task_init, task_pad),
                                           SELF_IN_CH(task_pad));

    message_length = *CHAN_IN1(unsigned, message_length, CH(task_init, task_pad));

    LOG("pad: len=%u offset=%u\r\n", message_length, block_offset);

    if (block_offset >= message_length) {
        LOG("pad: message done\r\n");
        TRANSITION_TO_MT(task_print_cyphertext);
    }

    LOG("process block: padded block at offset=%u: ", block_offset);
    for (i = 0; i < NUM_PAD_DIGITS; ++i)
        LOG("%x ", PAD_DIGITS[i]);
    LOG("'");
    for (i = NUM_DIGITS - NUM_PAD_DIGITS - 1; i >= 0; --i)
        LOG("%x ", PLAINTEXT[block_offset + i]);
    LOG("\r\n");

    for (i = 0; i < NUM_DIGITS - NUM_PAD_DIGITS; ++i) {
        m = (block_offset + i < message_length) ? PLAINTEXT[block_offset + i] : 0xFF;
        LOG("For iteration %u m = %u \r\n",i,m); 
        CHAN_OUT1(digit_t, base[i], m, MC_OUT_CH(ch_base, task_pad, task_mult_block,
                                                                  task_square_base));
    }
    LOG("next loop: \r\n"); 
    for (i = NUM_DIGITS - NUM_PAD_DIGITS; i < NUM_DIGITS; ++i) {
        LOG("For iteration %u m = %u \r\n",i,PAD_DIGITS[i]); 
        CHAN_OUT1(digit_t, base[i], PAD_DIGITS[i],
                 MC_OUT_CH(ch_base, task_pad, task_mult_block, task_square_base));
    }

    digit_t one = 1;
    digit_t zero = 0;
    CHAN_OUT1(digit_t, block[0], one, CH(task_pad, task_mult_block));
    for (i = 1; i < NUM_DIGITS; ++i)
        CHAN_OUT1(digit_t, block[i], zero, CH(task_pad, task_mult_block));

    e = *CHAN_IN1(digit_t, E, CH(task_init, task_pad));
    CHAN_OUT1(digit_t, E, e, CH(task_pad, task_exp));

    block_offset += NUM_DIGITS - NUM_PAD_DIGITS;
    CHAN_OUT1(unsigned, block_offset, block_offset, SELF_OUT_CH(task_pad));

#ifdef SHOW_COARSE_PROGRESS_ON_LED
    GPIO(PORT_LED_1, OUT) |= BIT(PIN_LED_1);
#endif
    TRANSITION_TO_MT(task_exp);
}

void task_exp()
{
    digit_t e;
    bool multiply;

    e = *CHAN_IN2(digit_t, E, CH(task_pad, task_exp), SELF_IN_CH(task_exp));
    LOG("exp: e=%x\r\n", e);

    // ASSERT: e > 0

    multiply = e & 0x1;

    e >>= 1;
    CHAN_OUT1(digit_t, E, e, SELF_OUT_CH(task_exp));
    CHAN_OUT1(digit_t, E, e, CH(task_exp, task_mult_block_get_result));

    if (multiply) {
        TRANSITION_TO_MT(task_mult_block);
    } else {
        TRANSITION_TO_MT(task_square_base);
    }
}

// TODO: is this task strictly necessary? it only makes a call. Can this call
// be rolled into task_exp?
void task_mult_block()
{
    int i;
    digit_t b, m;

    LOG("mult block\r\n");
    //LOG("WRITING FROM %x and %x with offset %x \r\n",
    //  MC_IN_CH(ch_base,task_pad,task_mult_block) + 1, 
    //  MC_IN_CH(ch_square_base, task_square_base_get_result, task_mult_block),
    //  offsetof(struct msg_base,base));
    // TODO: pass args to mult: message * base
    for (i = 0; i < NUM_DIGITS; ++i) {
        b = *CHAN_IN2(digit_t, base[i], MC_IN_CH(ch_base, task_pad, task_mult_block),
                        MC_IN_CH(ch_square_base, task_square_base_get_result, task_mult_block));
        m = *CHAN_IN2(digit_t, block[i], CH(task_pad, task_mult_block),
                                CH(task_mult_block_get_result, task_mult_block));
        
        CHAN_OUT1(digit_t, A[i], b, CALL_CH(ch_mult_mod));

        CHAN_OUT1(digit_t, B[i], m, CALL_CH(ch_mult_mod));

        LOG("mult block: a[%u]=%x b[%u]=%x\r\n", i, b, i, m);
    }
    task_t *next_task =TASK_REF(task_mult_block_get_result); 
    CHAN_OUT1(task_t*, next_task, next_task, CALL_CH(ch_mult_mod));
    TRANSITION_TO_MT(task_mult_mod);
}

void task_mult_block_get_result()
{
    int i;
    digit_t m, e;
    unsigned cyphertext_len;
    //LOG("TASK_MULT_BLOCK_rsa\r\n"); 

    LOG("mult block get result: block: ");
    for (i = NUM_DIGITS - 1; i >= 0; --i) { // reverse for printing
        m = *CHAN_IN1(digit_t, product[i], RET_CH(ch_mult_mod));
        LOG("%x ", m);
        CHAN_OUT1(digit_t, block[i], m, CH(task_mult_block_get_result, task_mult_block));
    }
    LOG("\r\n");

    e = *CHAN_IN1(digit_t, E, CH(task_exp, task_mult_block_get_result));

    // On last iteration we don't need to square base
    if (e > 0) {

        // TODO: current implementation restricts us to send only to the next instantiation
        // of self, so for now, as a workaround, we proxy the value in every instantiation
        cyphertext_len = *CHAN_IN2(unsigned, cyphertext_len,
                                   CH(task_init, task_mult_block_get_result),
                                   SELF_IN_CH(task_mult_block_get_result));
        CHAN_OUT1(unsigned, cyphertext_len, cyphertext_len, 
                                   SELF_OUT_CH(task_mult_block_get_result));

        TRANSITION_TO_MT(task_square_base);

    } else { // block is finished, save it

        cyphertext_len = *CHAN_IN2(unsigned, cyphertext_len,
                                   CH(task_init, task_mult_block_get_result),
                                   SELF_IN_CH(task_mult_block_get_result));
        LOG("mult block get result: cyphertext len=%u\r\n", cyphertext_len);

        if (cyphertext_len + NUM_DIGITS <= CYPHERTEXT_SIZE) {

            for (i = 0; i < NUM_DIGITS; ++i) { // reverse for printing
                // TODO: we could save this read by rolling this loop into the
                // above loop, by paying with an extra conditional in the
                // above-loop.
                m = *CHAN_IN1(digit_t, product[i], RET_CH(ch_mult_mod));
                CHAN_OUT1(digit_t, cyphertext[cyphertext_len], m,
                         CH(task_mult_block_get_result, task_print_cyphertext));
                cyphertext_len++;
            }

        } else {
            printf("WARN: block dropped: cyphertext overlow [%u > %u]\r\n",
                   cyphertext_len + NUM_DIGITS, CYPHERTEXT_SIZE);
            // carry on encoding, though
        }

        // TODO: implementation limitation: cannot multicast and send to self
        // in the same macro
        CHAN_OUT1(unsigned, cyphertext_len, cyphertext_len, 
                                  SELF_OUT_CH(task_mult_block_get_result));
        CHAN_OUT1(unsigned, cyphertext_len, cyphertext_len,
                 CH(task_mult_block_get_result, task_print_cyphertext));

        LOG("mult block get results: block done, cyphertext_len=%u\r\n", cyphertext_len);
        TRANSITION_TO_MT(task_pad);
    }

}

// TODO: is this task necessary? it seems to act as nothing but a proxy
// TODO: is there opportunity for special zero-copy optimization here
void task_square_base()
{
    int i;
    digit_t b;
    //LOG("TASK_SQUARE_BASE__rsa\r\n"); 

    LOG("square base\r\n");

    for (i = 0; i < NUM_DIGITS; ++i) {
        b = *CHAN_IN2(digit_t, base[i], MC_IN_CH(ch_base, task_pad, task_square_base),
                               MC_IN_CH(ch_square_base, task_square_base_get_result, 
                               task_square_base));
        CHAN_OUT1(digit_t, A[i], b, CALL_CH(ch_mult_mod));
        CHAN_OUT1(digit_t, B[i], b, CALL_CH(ch_mult_mod));

        LOG("square base: b[%u]=%x\r\n", i, b);
    }
    task_t * next_task =TASK_REF(task_square_base_get_result); 
    CHAN_OUT1(task_t*, next_task, next_task, CALL_CH(ch_mult_mod));
    TRANSITION_TO_MT(task_mult_mod);
}

// TODO: is there opportunity for special zero-copy optimization here
void task_square_base_get_result()
{
    int i;
    digit_t b;
    //LOG("TASK_SQUARE_BASE_GET_RESULT_rsa\r\n"); 

    LOG("square base get result\r\n");

    for (i = 0; i < NUM_DIGITS; ++i) {
        b = *CHAN_IN1(digit_t, product[i], RET_CH(ch_mult_mod));
        LOG("suqare base get result: base[%u]=%x\r\n", i, b);
        CHAN_OUT1(digit_t, base[i], b, MC_OUT_CH(ch_square_base, task_square_base_get_result,
                                       task_square_base, task_mult_block));
    }

    TRANSITION_TO_MT(task_exp);
}

void task_print_cyphertext()
{
    int i, j = 0;
    unsigned cyphertext_len;
    digit_t c;
    char line[PRINT_HEX_ASCII_COLS];
    //LOG("TASK_PRINT_CYPHERTEXT_rsa\r\n"); 

    cyphertext_len = *CHAN_IN1(unsigned, cyphertext_len,
                               CH(task_mult_block_get_result, task_print_cyphertext));
    LOG("print cyphertext: len=%u\r\n", cyphertext_len);

    printf("Cyphertext:\r\n");
    for (i = 0; i < cyphertext_len; ++i) {
        c = *CHAN_IN1(digit_t, cyphertext[i], CH(task_mult_block_get_result, task_print_cyphertext));
        printf("%02x ", c);
        line[j++] = c;
        if ((i + 1) % PRINT_HEX_ASCII_COLS == 0) {
            printf(" ");
            for (j = 0; j < PRINT_HEX_ASCII_COLS; ++j) {
                c = line[j];
                if (!(32 <= c && c <= 127)) // not printable
                    c = '.';
                printf("%c", c);
            }
            j = 0;
            printf("\r\n");
        }
    }
    printf("\r\n");

#ifdef SHOW_COARSE_PROGRESS_ON_LED
    blink(1, BLINK_MESSAGE_DONE, LED2);
#endif
    THREAD_END(); 
    TRANSITION_TO_MT(task_print_cyphertext);
}

// TODO: this task also looks like a proxy: is it avoidable?
void task_mult_mod()
{
    int i;
    digit_t a, b;
    //LOG("TASK_MULT_MOD_rsa\r\n"); 

    LOG("mult mod\r\n");

    for (i = 0; i < NUM_DIGITS; ++i) {
        a = *CHAN_IN1(digit_t, A[i], CALL_CH(ch_mult_mod));
        b = *CHAN_IN1(digit_t, B[i], CALL_CH(ch_mult_mod));

        LOG("mult mod: i=%u a=%x b=%x\r\n", i, a, b);

        CHAN_OUT1(digit_t, A[i], a, CH(task_mult_mod, task_mult));
        CHAN_OUT1(digit_t, B[i], b, CH(task_mult_mod, task_mult));
    }
    unsigned dummy = 0; 
    CHAN_OUT1(unsigned, digit, dummy , CH(task_mult_mod, task_mult));
    CHAN_OUT1(unsigned, carry, dummy, CH(task_mult_mod, task_mult));

    TRANSITION_TO_MT(task_mult);
}

void task_mult()
{
    int i;
    digit_t a, b, c;
    digit_t dp, p, carry;
    int digit;
    //LOG("TASK_MULT_rsa\r\n"); 

#ifdef SHOW_PROGRESS_ON_LED
    blink(1, BLINK_DURATION_TASK / 4, LED1);
#endif

    digit = *CHAN_IN2(int, digit, CH(task_mult_mod, task_mult), SELF_IN_CH(task_mult));
    carry = *CHAN_IN2(digit_t, carry, CH(task_mult_mod, task_mult), SELF_IN_CH(task_mult));

    LOG("mult: digit=%u carry=%x\r\n", digit, carry);

    p = carry;
    c = 0;
    for (i = 0; i < NUM_DIGITS; ++i) {
        if (digit - i >= 0 && digit - i < NUM_DIGITS) {
            a = *CHAN_IN1(digit_t, A[digit - i], CH(task_mult_mod, task_mult));
            b = *CHAN_IN1(digit_t, B[i], CH(task_mult_mod, task_mult));
            dp = a * b;

            c += dp >> DIGIT_BITS;
            p += dp & DIGIT_MASK;

            LOG("mult: i=%u a=%x b=%x p=%x\r\n", i, a, b, p);
        }
    }

    c += p >> DIGIT_BITS;
    p &= DIGIT_MASK;

    LOG("mult: c=%x p=%x\r\n", c, p);

    CHAN_OUT1(digit_t, product[digit], p, MC_OUT_CH(ch_product, task_mult,
             task_reduce_digits,
             task_reduce_n_divisor, task_reduce_normalizable, task_reduce_normalize));

    CHAN_OUT1(digit_t, product[digit], p, CALL_CH(ch_print_product));

    digit++;

    if (digit < NUM_DIGITS_x2) {
        CHAN_OUT1(digit_t, carry, c, SELF_OUT_CH(task_mult));
        CHAN_OUT1(int, digit, digit, SELF_OUT_CH(task_mult));
        TRANSITION_TO_MT(task_mult);
    } else {
        task_t *next_task =TASK_REF(task_reduce_digits);  
        CHAN_OUT1(task_t *, next_task, next_task , CALL_CH(ch_print_product));
        TRANSITION_TO_MT(task_print_product);
    }
}

void task_reduce_digits()
{
    int d;
    digit_t m;
    //LOG("TASK_REDUCE_DIGITS_rsa\r\n"); 

    LOG("reduce: digits\r\n");

    // Start reduction loop at most significant non-zero digit
    d = 2 * NUM_DIGITS;
    do {
        d--;
        m = *CHAN_IN1(digit_t, product[d], MC_IN_CH(ch_product, task_mult, task_reduce_digits));
        LOG("reduce digits: p[%u]=%x\r\n", d, m);
    } while (m == 0 && d > 0);

    if (m == 0) {
        LOG("reduce: digits: all digits of message are zero\r\n");
        TRANSITION_TO_MT(task_init);
    }
    LOG("reduce: digits: d = %u\r\n", d);

    CHAN_OUT1(int, digit, d, MC_OUT_CH(ch_digit, task_reduce_digits,
                                 task_reduce_normalizable, task_reduce_normalize,
                                 task_reduce_quotient));

    TRANSITION_TO_MT(task_reduce_normalizable);
}

void task_reduce_normalizable()
{
    int i;
    unsigned m, n, d, offset;
    bool normalizable = true;
    //LOG("TASK_REDUCE_NORMALIZABLE_rsa\r\n"); 

    LOG("reduce: normalizable\r\n");

    // Variables:
    //   m: message
    //   n: modulus
    //   b: digit base (2**8)
    //   l: number of digits in the product (2 * NUM_DIGITS)
    //   k: number of digits in the modulus (NUM_DIGITS)
    //
    // if (m > n b^(l-k)
    //     m = m - n b^(l-k)
    //
    // NOTE: It's temptimg to do the subtraction opportunistically, and if
    // the result is negative, then the condition must have been false.
    // However, we can't do that because under this approach, we must
    // write to the output channel zero digits for digits that turn
    // out to be equal, but if a later digit pair is such that condition
    // is false (p < m), then those rights are invalid, but we have no
    // good way of exluding them from being picked up by the later
    // task. One possiblity is to transmit a flag to that task that
    // tells it whether to include our output channel into its input sync
    // statement. However, this seems less elegant than splitting the
    // normalization into two tasks: the condition and the subtraction.
    //
    // Multiplication by a power of radix (b) is a shift, so when we do the
    // comparison/subtraction of the digits, we offset the index into the
    // product digits by (l-k) = NUM_DIGITS.

    d = *CHAN_IN1(unsigned, digit, 
                    MC_IN_CH(ch_digit, task_reduce_digits, task_reduce_noramlizable));

    offset = d + 1 - NUM_DIGITS; // TODO: can this go below zero
    LOG("reduce: normalizable: d=%u offset=%u\r\n", d, offset);

    CHAN_OUT1(unsigned, offset, offset, CH(task_reduce_normalizable, task_reduce_normalize));

    for (i = d; i >= 0; --i) {
        m = *CHAN_IN1(unsigned, product[i],
                      MC_IN_CH(ch_product, task_mult, task_reduce_normalizable));
        n = *CHAN_IN1(unsigned, N[i - offset], MC_IN_CH(ch_modulus, task_init,
                                              task_reduce_normalizable));

        LOG("normalizable: m[%u]=%x n[%u]=%x\r\n", i, m, i - offset, n);

        if (m > n) {
            break;
        } else if (m < n) {
            normalizable = false;
            break;
        }
    }

    if (!normalizable && d == NUM_DIGITS - 1) {
        LOG("reduce: normalizable: reduction done: message < modulus\r\n");

        // TODO: is this copy avoidable? a 'mult mod done' task doesn't help
        // because we need to ship the data to it.
        for (i = 0; i < NUM_DIGITS; ++i) {
            m = *CHAN_IN1(unsigned, product[i],
                          MC_IN_CH(ch_product, task_mult, task_reduce_normalizable));
            CHAN_OUT1(unsigned, product[i], m, RET_CH(ch_mult_mod));
        }

        const task_t *next_task = *CHAN_IN1(task_t *, next_task, CALL_CH(ch_mult_mod));
        transition_to_mt(next_task);
    }

    LOG("normalizable: %u\r\n", normalizable);

    if (normalizable) {
        TRANSITION_TO_MT(task_reduce_normalize);
    } else {
        TRANSITION_TO_MT(task_reduce_n_divisor);
    }
}

// TODO: consider decomposing into subtasks
void task_reduce_normalize()
{
    int i;
    digit_t m, n, d, s;
    unsigned borrow, offset;
    const task_t *next_task;
    //LOG("TASK_REDUCE_NORMALIZE_rsa\r\n"); 

    LOG("normalize\r\n");

    offset = *CHAN_IN1(unsigned, offset, CH(task_reduce_normalizable, task_reduce_normalize));

    // To call the print task, we need to proxy the values we don't touch
    for (i = 0; i < offset; ++i) {
        m = *CHAN_IN1(digit_t, product[i], MC_IN_CH(ch_product, task_mult, task_reduce_normalize));
        CHAN_OUT1(digit_t, product[i], m, CALL_CH(ch_print_product));
    }

    borrow = 0;
    for (i = 0; i < NUM_DIGITS; ++i) {
        m = *CHAN_IN1(digit_t, product[i + offset],
                      MC_IN_CH(ch_product, task_mult, task_reduce_normalize));
        n = *CHAN_IN1(digit_t, N[i], MC_IN_CH(ch_modulus, task_init, task_reduce_normalize));

        s = n + borrow;
        if (m < s) {
            m += 1 << DIGIT_BITS;
            borrow = 1;
        } else {
            borrow = 0;
        }
        d = m - s;

        LOG("normalize: m[%u]=%x n[%u]=%x b=%u d=%x\r\n",
                i + offset, m, i, n, borrow, d);

        CHAN_OUT1(digit_t, product[i + offset], d,
                 MC_OUT_CH(ch_normalized_product, task_reduce_normalize,
                           task_reduce_quotient, task_reduce_compare,
                           task_reduce_add, task_reduce_subtract));

        CHAN_OUT1(digit_t, product[i + offset], d, CALL_CH(ch_print_product));
    }

    // To call the print task, we need to proxy the values we don't touch
    for (i = offset + NUM_DIGITS; i < NUM_DIGITS_x2; ++i) {
        digit_t dummy = 0; 
        CHAN_OUT1(digit_t, product[i], dummy, CALL_CH(ch_print_product));
    }

    if (offset > 0) { // l-1 > k-1 (loop bounds), where offset=l-k, where l=|m|,k=|n|
        next_task = TASK_REF(task_reduce_n_divisor);
    } else {
        LOG("reduce: normalize: reduction done: no digits to reduce\r\n");
        // TODO: is this copy avoidable?
        for (i = 0; i < NUM_DIGITS; ++i) {
            m = *CHAN_IN1(digit_t, product[i],
                          MC_IN_CH(ch_product, task_mult, task_reduce_normalize));
            CHAN_OUT1(digit_t, product[i], m, RET_CH(ch_mult_mod));
        }
        next_task = *CHAN_IN1(task_t *, next_task, CALL_CH(ch_mult_mod));
    }

    CHAN_OUT1(task_t *, next_task, next_task, CALL_CH(ch_print_product));
    TRANSITION_TO_MT(task_print_product);
}

void task_reduce_n_divisor()
{
    digit_t n[2]; // [1]=N[msd], [0]=N[msd-1]
    digit_t n_div;

#ifdef SHOW_PROGRESS_ON_LED
    blink(1, SEC_TO_CYCLES, LED2);
#endif

    LOG("reduce: n divisor\r\n");

    n[1]  = *CHAN_IN1(digit_t, N[NUM_DIGITS - 1],
                      MC_IN_CH(ch_modulus, task_init, task_reduce_n_divisor));
    n[0] = *CHAN_IN1(digit_t, N[NUM_DIGITS - 2], MC_IN_CH(ch_modulus, task_init, task_n_divisor));

    // Divisor, derived from modulus, for refining quotient guess into exact value
    n_div = ((n[1]<< DIGIT_BITS) + n[0]);

    LOG("reduce: n divisor: n[1]=%x n[0]=%x n_div=%x\r\n", n[1], n[0], n_div);

    CHAN_OUT1(digit_t, n_div, n_div, CH(task_reduce_n_divisor, task_reduce_quotient));

    TRANSITION_TO_MT(task_reduce_quotient);
}

void task_reduce_quotient()
{
    unsigned d;
    digit_t m[3]; // [2]=m[d], [1]=m[d-1], [0]=m[d-2]
    digit_t m_n, n_div, q;
    uint32_t qn, n_q; // must hold at least 3 digits

#ifdef SHOW_PROGRESS_ON_LED
    blink(1, BLINK_DURATION_TASK, LED2);
#endif

    d = *CHAN_IN2(unsigned, digit, MC_IN_CH(ch_digit, task_reduce_digits, task_reduce_quotient),
                         SELF_IN_CH(task_reduce_quotient));

    LOG("reduce: quotient: d=%x\r\n", d);

    m[2] = *CHAN_IN3(digit_t, product[d],
                     MC_IN_CH(ch_product, task_mult, task_reduce_quotient),
                     MC_IN_CH(ch_normalized_product, task_reduce_normalize, task_reduce_quotient),
                     MC_IN_CH(ch_reduce_subtract_product, task_reduce_subtract,
                              task_reduce_quotient));

    m[1] = *CHAN_IN3(digit_t,product[d - 1],
                     MC_IN_CH(ch_product, task_mult, task_reduce_quotient),
                     MC_IN_CH(ch_normalized_product, task_reduce_normalize, task_reduce_quotient),
                     MC_IN_CH(ch_reduce_subtract_product, task_reduce_subtract,
                              task_reduce_quotient));
    m[0] = *CHAN_IN3(digit_t,product[d - 2],
                     MC_IN_CH(ch_product, task_mult, task_reduce_quotient),
                     MC_IN_CH(ch_normalized_product, task_reduce_normalize, task_reduce_quotient),
                     MC_IN_CH(ch_reduce_subtract_product, task_reduce_subtract,
                              task_reduce_quotient));
    // NOTE: we asserted that NUM_DIGITS >= 2, so p[d-2] is safe

    m_n = *CHAN_IN1(digit_t,N[NUM_DIGITS - 1],
                    MC_IN_CH(ch_modulus, task_init, task_reduce_quotient));

    LOG("reduce: quotient: m_n=%x m[d]=%x\r\n", m_n, m[2]);

    // Choose an initial guess for quotient
    if (m[2] == m_n) {
        q = (1 << DIGIT_BITS) - 1;
    } else {
        q = ((m[2] << DIGIT_BITS) + m[1]) / m_n;
    }

    LOG("reduce: quotient: q0=%x\r\n", q);

    // Refine quotient guess

    // NOTE: An alternative to composing the digits into one variable, is to
    // have a loop that does the comparison digit by digit to implement the
    // condition of the while loop below.
    n_q = ((uint32_t)m[2] << (2 * DIGIT_BITS)) + (m[1] << DIGIT_BITS) + m[0];

    LOG("reduce: quotient: m[d]=%x m[d-1]=%x m[d-2]=%x n_q=%x%x\r\n",
           m[2], m[1], m[0], (uint16_t)((n_q >> 16) & 0xffff), (uint16_t)(n_q & 0xffff));

    n_div = *CHAN_IN1(digit_t,n_div, CH(task_reduce_n_divisor, task_reduce_quotient));

    LOG("reduce: quotient: n_div=%x q0=%x\r\n", n_div, q);

    q++;
    do {
        q--;
        qn = mult16(n_div, q);
        LOG("reduce: quotient: q=%x qn=%x%x\r\n", q,
              (uint16_t)((qn >> 16) & 0xffff), (uint16_t)(qn & 0xffff));
    } while (qn > n_q);

    // This is still not the final quotient, it may be off by one,
    // which we determine and fix in the 'compare' and 'add' steps.
    LOG("reduce: quotient: q=%x\r\n", q);

    CHAN_OUT1(digit_t, quotient, q, CH(task_reduce_quotient, task_reduce_multiply));

    CHAN_OUT1(unsigned, digit, d, MC_OUT_CH(ch_reduce_digit, task_reduce_quotient,
                                 task_reduce_multiply, task_reduce_add,
                                 task_reduce_subtract));

    d--;
    CHAN_OUT1(unsigned, digit, d, SELF_OUT_CH(task_reduce_quotient));

    TRANSITION_TO_MT(task_reduce_multiply);
}

// NOTE: this is multiplication by one digit, hence not re-using mult task
void task_reduce_multiply()
{
    int i;
    digit_t m, q, n;
    unsigned c, d, offset;

#ifdef SHOW_PROGRESS_ON_LED
    blink(1, BLINK_DURATION_TASK, LED2);
#endif

    d = *CHAN_IN1(unsigned,digit, MC_IN_CH(ch_reduce_digit,
                                  task_reduce_quotient, task_reduce_multiply));
    q = *CHAN_IN1(digit_t, quotient, CH(task_reduce_quotient, task_reduce_multiply));

    //LOG("reduce: multiply: d=%x q=%x\r\n", d, q);

    // As part of this task, we also perform the left-shifting of the q*m
    // product by radix^(digit-NUM_DIGITS), where NUM_DIGITS is the number
    // of digits in the modulus. We implement this by fetching the digits
    // of number being reduced at that offset.
    offset = d - NUM_DIGITS;
    //LOG("reduce: multiply: offset=%u\r\n", offset);

    // For calling the print task we need to proxy to it values that
    // we do not modify
    for (i = 0; i < offset; ++i) {
        digit_t dummy = 0; 
        CHAN_OUT1(digit_t, product[i], dummy, CALL_CH(ch_print_product));
    }

    // TODO: could convert the loop into a self-edge
    c = 0;
    for (i = offset; i < 2 * NUM_DIGITS; ++i) {

        // This condition creates the left-shifted zeros.
        // TODO: consider adding number of digits to go along with the 'product' field,
        // then we would not have to zero out the MSDs
        m = c;
        if (i < offset + NUM_DIGITS) {
            n = *CHAN_IN1(digit_t, N[i - offset],
                          MC_IN_CH(ch_modulus, task_init, task_reduce_multiply));
            m += q * n;
        } else {
            n = 0;
            // TODO: could break out of the loop  in this case (after CHAN_OUT)
        }

        LOG("reduce: multiply: n[%u]=%x q=%x c=%x m[%u]=%x\r\n",
               i - offset, n, q, c, i, m);

        c = m >> DIGIT_BITS;
        m &= DIGIT_MASK;

        CHAN_OUT1(digit_t, product[i], m, MC_OUT_CH(ch_qn, task_reduce_multiply,
                                          task_reduce_compare, task_reduce_subtract));

        CHAN_OUT1(digit_t, product[i], m, CALL_CH(ch_print_product));
    }
    task_t *next_task =TASK_REF(task_reduce_compare);  
    CHAN_OUT1(task_t *,next_task, next_task , CALL_CH(ch_print_product));
    TRANSITION_TO_MT(task_print_product);
}

void task_reduce_compare()
{
    int i;
    digit_t m, qn;
    char relation = '=';

#ifdef SHOW_PROGRESS_ON_LED
    blink(1, BLINK_DURATION_TASK, LED2);
#endif

    //LOG("reduce: compare\r\n");

    // TODO: could transform this loop into a self-edge
    // TODO: this loop might not have to go down to zero, but to NUM_DIGITS
    // TODO: consider adding number of digits to go along with the 'product' field
    for (i = NUM_DIGITS_x2 - 1; i >= 0; --i) {
        m = *CHAN_IN3(digit_t, product[i],
                      MC_IN_CH(ch_product, task_mult, task_reduce_compare),
                      MC_IN_CH(ch_normalized_product, task_reduce_normalize, task_reduce_compare),
                      // TODO: do we need 'ch_reduce_add_product' here? We do not if
                      // the 'task_reduce_subtract' overwrites all values written by
                      // 'task_reduce_add', which, I think, is the case.
                      MC_IN_CH(ch_reduce_subtract_product, task_reduce_subtract,
                               task_reduce_compare));
        qn = *CHAN_IN1(digit_t, product[i],
                       MC_IN_CH(ch_qn, task_reduce_multiply, task_reduce_compare));

        LOG("reduce: compare: m[%u]=%x qn[%u]=%x\r\n", i, m, i, qn);

        if (m > qn) {
            relation = '>';
            break;
        } else if (m < qn) {
            relation = '<';
            break;
        }
    }

    //LOG("reduce: compare: relation %c\r\n", relation);

    if (relation == '<') {
        TRANSITION_TO_MT(task_reduce_add);
    } else {
        TRANSITION_TO_MT(task_reduce_subtract);
    }
}

// TODO: this addition and subtraction can probably be collapsed
// into one loop that always subtracts the digits, but, conditionally, also
// adds depending on the result from the 'compare' task. For now,
// we keep them separate for clarity.

void task_reduce_add()
{
    int i, j;
    digit_t m, n, c, r;
    unsigned d, offset;

#ifdef SHOW_PROGRESS_ON_LED
    blink(1, BLINK_DURATION_TASK, LED2);
#endif

    d = *CHAN_IN1(unsigned, digit, MC_IN_CH(ch_reduce_digit,
                                  task_reduce_quotient, task_reduce_compare));

    // Part of this task is to shift modulus by radix^(digit - NUM_DIGITS)
    offset = d - NUM_DIGITS;
    digit_t dummy = 0; 
    //LOG("reduce: add: d=%u offset=%u\r\n", d, offset);

    // For calling the print task we need to proxy to it values that
    // we do not modify
    for (i = 0; i < offset; ++i) {
        CHAN_OUT1(digit_t, product[i], dummy, CALL_CH(ch_print_product));
    }

    // For calling the print task we need to proxy to it values that
    // we do not modify
    for (i = 0; i < offset; ++i) {
        CHAN_OUT1(digit_t, product[i], dummy, CALL_CH(ch_print_product));
    }

    // TODO: coult transform this loop into a self-edge
    c = 0;
    for (i = offset; i < 2 * NUM_DIGITS; ++i) {
        m = *CHAN_IN3(digit_t, product[i],
                      MC_IN_CH(ch_product, task_mult, task_reduce_add),
                      MC_IN_CH(ch_normalized_product, task_reduce_normalize, task_reduce_add),
                      MC_IN_CH(ch_reduce_subtract_product,
                               task_reduce_subtract, task_reduce_add));

        // Shifted index of the modulus digit
        j = i - offset;

        if (i < offset + NUM_DIGITS) {
            n = *CHAN_IN1(digit_t, N[j], MC_IN_CH(ch_modulus, task_init, task_reduce_add));
        } else {
            n = 0;
            j = 0; // a bit ugly, we want 'nan', but ok, since for output only
            // TODO: could break out of the loop in this case (after CHAN_OUT)
        }

        r = c + m + n;

        LOG("reduce: add: m[%u]=%x n[%u]=%x c=%x r=%x\r\n", i, m, j, n, c, r);

        c = r >> DIGIT_BITS;
        r &= DIGIT_MASK;

        CHAN_OUT1(digit_t, product[i], r, CH(task_reduce_add, task_reduce_subtract));
        CHAN_OUT1(digit_t, product[i], r, CALL_CH(ch_print_product));
    }
    task_t *next_task =TASK_REF(task_reduce_subtract);  
    CHAN_OUT1(task_t *,next_task, next_task , CALL_CH(ch_print_product));
    TRANSITION_TO_MT(task_print_product);
}

// TODO: re-use task_reduce_normalize?
void task_reduce_subtract()
{
    int i;
    digit_t m, s, r, qn;
    unsigned d, borrow, offset;

#ifdef SHOW_PROGRESS_ON_LED
    blink(1, BLINK_DURATION_TASK, LED2);
#endif

    d = *CHAN_IN1(unsigned, digit, MC_IN_CH(ch_reduce_digit, task_reduce_quotient,
                                  task_reduce_subtract));

    // The qn product had been shifted by this offset, no need to subtract the zeros
    offset = d - NUM_DIGITS;

    //LOG("reduce: subtract: d=%u offset=%u\r\n", d, offset);

    // For calling the print task we need to proxy to it values that
    // we do not modify
    for (i = 0; i < offset; ++i) {
        m = *CHAN_IN4(digit_t, product[i],
                      MC_IN_CH(ch_product, task_mult, task_reduce_subtract),
                      MC_IN_CH(ch_normalized_product, task_reduce_normalize, task_reduce_subtract),
                      CH(task_reduce_add, task_reduce_subtract),
                      SELF_IN_CH(task_reduce_subtract));
        digit_t dummy = 0; 
        CHAN_OUT1(digit_t, product[i], dummy, CALL_CH(ch_print_product));
    }

    // TODO: could transform this loop into a self-edge
    borrow = 0;
    for (i = 0; i < 2 * NUM_DIGITS; ++i) {
        m = *CHAN_IN4(digit_t, product[i],
                      MC_IN_CH(ch_product, task_mult, task_reduce_subtract),
                      MC_IN_CH(ch_normalized_product, task_reduce_normalize, task_reduce_subtract),
                      CH(task_reduce_add, task_reduce_subtract),
                      SELF_IN_CH(task_reduce_subtract));

        // For calling the print task we need to proxy to it values that we do not modify
        if (i >= offset) {
            qn = *CHAN_IN1(digit_t, product[i],
                           MC_IN_CH(ch_qn, task_reduce_multiply, task_reduce_subtract));

            s = qn + borrow;
            if (m < s) {
                m += 1 << DIGIT_BITS;
                borrow = 1;
            } else {
                borrow = 0;
            }
            r = m - s;

            LOG("reduce: subtract: m[%u]=%x qn[%u]=%x b=%u r=%x\r\n",
                   i, m, i, qn, borrow, r);

            CHAN_OUT1(digit_t, product[i], r, 
                      MC_OUT_CH(ch_reduce_subtract_product, task_reduce_subtract,
                                              task_reduce_quotient, task_reduce_compare));
            CHAN_OUT1(digit_t, product[i], r, SELF_OUT_CH(task_reduce_subtract));
        } else {
            r = m;
        }
        CHAN_OUT1(digit_t, product[i], r, CALL_CH(ch_print_product));

        if (d == NUM_DIGITS) // reduction done
            CHAN_OUT1(digit_t, product[i], r, RET_CH(ch_mult_mod));
    }

    if (d > NUM_DIGITS) {
        task_t *next_task =TASK_REF(task_reduce_quotient);  
        CHAN_OUT1(task_t *, next_task, next_task , CALL_CH(ch_print_product));
    } else { // reduction finished: exit from the reduce hypertask (after print)
        LOG("reduce: subtract: reduction done\r\n");

        // TODO: Is it ok to get the next task directly from call channel?
        //       If not, all we have to do is have reduce task proxy it.
        //       Also, do we need a dedicated epilogue task?
        const task_t *next_task = *CHAN_IN1(task_t *, next_task, CALL_CH(ch_mult_mod));
        CHAN_OUT1(task_t *, next_task, next_task, CALL_CH(ch_print_product));
    }

    TRANSITION_TO_MT(task_print_product);
}

// TODO: eliminate from control graph when not verbose
void task_print_product()
{
    const task_t* next_task;
    //LOG("TASK_PRINT_PRODUCT_rsa\r\n"); 
#ifdef VERBOSE
    int i;
    digit_t m;

    LOG("print: P=");
    for (i = (NUM_DIGITS_x2) - 1; i >= 0; --i) {
        m = *CHAN_IN1(digit_t, product[i], CALL_CH(ch_print_product));
        LOG("%x ", m);
    }
    LOG("\r\n");
#endif

    next_task = *CHAN_IN1(task_t *, next_task, CALL_CH(ch_print_product));
    transition_to_mt(next_task);
}



/*---------------------------Common tasks/init func------------------------*/
void task_done()
{
    task_prologue();
#if defined(BOARD_WISP) || defined(BOARD_MSP_TS430)
    GPIO(PORT_AUX, OUT) |= BIT(PIN_AUX_1); 
    GPIO(PORT_LED_1, OUT) |= BIT(PIN_LED_1); 
#elif defined(BOARD_CAPYBARA)
    GPIO(PORT_DEBUG, OUT) |= BIT(PIN_DEBUG_1); 
#endif
    THREAD_END(); 
    TRANSITION_TO_MT(task_done);
}

void init()
{
    WISP_init();

#ifdef CONFIG_EDB
    debug_setup();
#endif

    INIT_CONSOLE();
#ifndef BOARD_CAPYBARA
    GPIO(PORT_AUX, DIR)   |= BIT(PIN_AUX_1); 
    GPIO(PORT_LED_1, DIR) |= BIT(PIN_LED_1);
    GPIO(PORT_LED_2, DIR) |= BIT(PIN_LED_2);
#if defined(PORT_LED_3)
        GPIO(PORT_LED_3, DIR) |= BIT(PIN_LED_3);
#endif
#endif
        
    __enable_interrupt();

#if defined(PORT_LED_3) // when available, this LED indicates power-on
    GPIO(PORT_LED_3, OUT) |= BIT(PIN_LED_3);
    GPIO(PORT_LED_1, OUT) &= ~BIT(PIN_LED_1); 
    GPIO(PORT_AUX, OUT)   &= ~BIT(PIN_AUX_1); 
#endif

#if defined(PORT_DEBUG)
    GPIO(PORT_DEBUG, DIR) |= BIT(PIN_DEBUG_1) ; 
    GPIO(PORT_DEBUG, OUT) &= ~BIT(PIN_DEBUG_1); 
#endif
    PRINTF(".%u.\r\n", curctx->task->idx);
}

ENTRY_TASK(task_init)
INIT_FUNC(init)
