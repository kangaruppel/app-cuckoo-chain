#include <msp430.h>

#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>

#include <libmsp/mem.h>
#include <wisp-base.h>
#include <msp-math.h>
#include <libio/log.h>

#include <libchain/chain.h>

#ifdef CONFIG_EDB
#include <libedb/edb.h>
#endif

#include "pins.h"

// If you link-in wisp-base, then you have to define some symbols.
uint8_t usrBank[USRBANK_SIZE];

#define NUM_INSERTS 10
#define NUM_LOOKUPS 10
#define NUM_BUCKETS 32 // must be a power of 2
#define MAX_RELOCATIONS 5

typedef uint16_t value_t;
typedef uint16_t hash_t;
typedef uint16_t fingerprint_t;
typedef uint16_t index_t; // bucket index

struct msg_key {
    CHAN_FIELD(value_t, key);
};

struct msg_genkey {
    CHAN_FIELD(value_t, key);
    CHAN_FIELD(const task_t*, next_task);
};

struct msg_calc_indexes {
    CHAN_FIELD(value_t, key);
    CHAN_FIELD(const task_t*, next_task);
};

struct msg_self_key {
    SELF_CHAN_FIELD(value_t, key);
};

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

struct msg_hash_args {
    CHAN_FIELD(value_t, data);
    CHAN_FIELD(const task_t*, next_task);
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

struct msg_insert_count {
    CHAN_FIELD(unsigned, insert_count);
};

struct msg_lookup_count {
    CHAN_FIELD(unsigned, lookup_count);
};

TASK(1,  task_init)
TASK(2,  task_generate_key)
TASK(3,  task_insert)
TASK(4,  task_calc_indexes)
TASK(5,  task_calc_indexes_index_1)
TASK(6,  task_calc_indexes_index_2)
TASK(7,  task_add) // TODO: rename: add 'insert' prefix
TASK(8,  task_relocate)
TASK(9,  task_insert_done)
TASK(10, task_lookup)
TASK(11, task_lookup_search)
TASK(12, task_lookup_done)

CHANNEL(task_init, task_generate_key, msg_genkey);
CHANNEL(task_init, task_insert_done, msg_insert_count);
CHANNEL(task_init, task_lookup_done, msg_lookup_count);
MULTICAST_CHANNEL(msg_key, ch_key, task_generate_key, task_insert, task_lookup);
SELF_CHANNEL(task_insert, msg_self_key);
MULTICAST_CHANNEL(msg_filter, ch_filter, task_init,
                  task_add, task_relocate, task_insert_done,
                  task_lookup_search);
MULTICAST_CHANNEL(msg_filter, ch_filter_add, task_add,
                  task_relocate, task_insert_done, task_lookup_search);
MULTICAST_CHANNEL(msg_filter, ch_filter_relocate, task_relocate,
                  task_add, task_insert_done, task_lookup_search);
CALL_CHANNEL(ch_calc_indexes, msg_calc_indexes);
RET_CHANNEL(ch_calc_indexes, msg_indexes);
CHANNEL(task_calc_indexes, task_calc_indexes_index_2, msg_fingerprint);
CHANNEL(task_calc_indexes_index_1, task_calc_indexes_index_2, msg_index1);
CHANNEL(task_add, task_relocate, msg_victim);
SELF_CHANNEL(task_add, msg_self_filter);
CHANNEL(task_add, task_insert_done, msg_filter);
MULTICAST_CHANNEL(msg_filter, ch_reloc_filter, task_relocate,
                  task_add, task_insert_done);
SELF_CHANNEL(task_relocate, msg_self_victim);
CHANNEL(task_relocate, task_add, msg_filter);
CHANNEL(task_relocate, task_insert_done, msg_filter);
CHANNEL(task_lookup, task_lookup_done, msg_lookup_result);
SELF_CHANNEL(task_insert_done, msg_insert_count);
SELF_CHANNEL(task_lookup_done, msg_lookup_count);
CHANNEL(task_insert_done, task_generate_key, msg_genkey);
CHANNEL(task_lookup_done, task_generate_key, msg_genkey);
SELF_CHANNEL(task_generate_key, msg_key);
CHANNEL(task_lookup_search, task_lookup_done, msg_member);

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

void task_init()
{
    unsigned i;

    LOG("init\r\n");

    for (i = 0; i < NUM_BUCKETS; ++i) {
        fingerprint_t fp = 0;
        CHAN_OUT1(fingerprint_t, filter[i], fp, MC_OUT_CH(ch_filter, task_init,
                               task_add, task_relocate, task_insert_done));
    }

    unsigned count = 0;
    CHAN_OUT1(unsigned, insert_count, count, CH(task_init, task_insert_done));
    CHAN_OUT1(unsigned, lookup_count, count, CH(task_init, task_lookup_done));

    CHAN_OUT1(value_t, key, init_key, CH(task_init, task_generate_key));
    const task_t *next_task = TASK_REF(task_insert);
    CHAN_OUT1(const task_t *, next_task, next_task, CH(task_init, task_generate_key));
    TRANSITION_TO(task_generate_key);
}

void task_generate_key()
{
    value_t key = *CHAN_IN3(value_t, key, CH(task_init, task_generate_key),
                                          CH(task_insert_done, task_generate_key),
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

    const task_t *next_task = *CHAN_IN2(const task_t *, next_task,
                                        CH(task_init, task_generate_key),
                                        CH(task_insert_done, task_generate_key));
    transition_to(next_task);
}

void task_calc_indexes()
{
    value_t key = *CHAN_IN1(value_t, key, CALL_CH(ch_calc_indexes));

    fingerprint_t fp = hash_to_fingerprint(key);
    LOG("calc indexes: fingerprint: key %04x fp %04x\r\n", key, fp);

    CHAN_OUT2(fingerprint_t, fingerprint, fp,
              CH(task_calc_indexes, task_calc_indexes_index_2),
              RET_CH(ch_calc_indexes));

    TRANSITION_TO(task_calc_indexes_index_1);
}

void task_calc_indexes_index_1()
{
    value_t key = *CHAN_IN1(value_t, key, CALL_CH(ch_calc_indexes));

    index_t index1 = hash_to_index(key);
    LOG("calc indexes: index1: key %04x idx1 %u\r\n", key, index1);

    CHAN_OUT2(index_t, index1, index1,
              CH(task_calc_indexes_index_1, task_calc_indexes_index_2),
              RET_CH(ch_calc_indexes));

    TRANSITION_TO(task_calc_indexes_index_2);
}

void task_calc_indexes_index_2()
{
    fingerprint_t fp = *CHAN_IN1(fingerprint_t, fingerprint,
                                 CH(task_calc_indexes, task_calc_indexes_index_2));
    index_t index1 = *CHAN_IN1(index_t, index1,
                               CH(task_calc_indexes_index_1, task_calc_indexes_index_2));

    index_t fp_hash = hash_to_index(fp);
    index_t index2 = index1 ^ fp_hash;

    LOG("calc indexes: index2: fp hash: %04x idx1 %u idx2 %u\r\n",
        fp_hash, index1, index2);

    CHAN_OUT1(index_t, index2, index2, RET_CH(ch_calc_indexes));

    const task_t *next_task = *CHAN_IN1(const task_t *, next_task,
                                        CALL_CH(ch_calc_indexes));
    transition_to(next_task);
}

// This task is a somewhat redundant proxy. But it will be a callable
// task and also be responsible for making the call to calc_index.
void task_insert()
{
    value_t key = *CHAN_IN1(value_t, key,
                            MC_IN_CH(ch_key, task_generate_key, task_insert));

    CHAN_OUT1(value_t, key, key, CALL_CH(ch_calc_indexes));

    const task_t *next_task = TASK_REF(task_add);
    CHAN_OUT1(const task_t *, next_task, next_task, CALL_CH(ch_calc_indexes));
    TRANSITION_TO(task_calc_indexes);
}


void task_add()
{
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
                            task_relocate, task_insert_done, task_lookup_search),
                  SELF_OUT_CH(task_add));

        TRANSITION_TO(task_insert_done);
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

            TRANSITION_TO(task_insert_done);
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

            TRANSITION_TO(task_relocate);
        }
    }
}

void task_relocate()
{
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
                       task_add, task_insert_done, task_lookup_search),
             SELF_OUT_CH(task_relocate));

    if (!fp_next_victim) { // slot was free
        TRANSITION_TO(task_insert_done);
    } else { // slot was occupied, rellocate the next victim

        unsigned relocation_count = *CHAN_IN2(unsigned, relocation_count,
                                              CH(task_add, task_relocate),
                                              SELF_IN_CH(task_relocate));

        LOG("relocate: relocs %u\r\n", relocation_count);

        if (relocation_count >= MAX_RELOCATIONS) { // insert failed
            LOG("relocate: max relocs reached: %u\r\n", relocation_count);
            TRANSITION_TO(task_insert_done);
        }

        relocation_count++;
        CHAN_OUT1(unsigned, relocation_count, relocation_count,
                 SELF_OUT_CH(task_relocate));

        CHAN_OUT1(index_t, index_victim, index2_victim, SELF_OUT_CH(task_relocate));
        CHAN_OUT1(fingerprint_t, fp_victim, fp_next_victim, SELF_OUT_CH(task_relocate));

        TRANSITION_TO(task_relocate);
    }
}

void task_insert_done()
{
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

    unsigned insert_count = *CHAN_IN2(unsigned, insert_count,
                                      CH(task_init, task_insert_done),
                                      SELF_IN_CH(task_insert_done));
    insert_count++;

    CHAN_OUT1(unsigned, insert_count, insert_count, SELF_OUT_CH(task_insert_done));

    volatile uint32_t delay = 0x8ffff;
    while (delay--);

    if (insert_count < NUM_INSERTS) {
        const task_t *next_task = TASK_REF(task_insert);
        CHAN_OUT1(const task_t *, next_task, next_task, CH(task_insert_done, task_generate_key));
        TRANSITION_TO(task_generate_key);
    } else {
        const task_t *next_task = TASK_REF(task_lookup);
        CHAN_OUT1(value_t, key, init_key, CH(task_insert_done, task_generate_key));
        CHAN_OUT1(const task_t *, next_task, next_task, CH(task_insert_done, task_generate_key));
        TRANSITION_TO(task_generate_key);
    }
}

void task_lookup()
{
    value_t key = *CHAN_IN1(value_t, key,
                            MC_IN_CH(ch_key, task_generate_key,task_lookup));
    LOG("lookup: key %04x\r\n", key);

    CHAN_OUT2(value_t, key, key, CALL_CH(ch_calc_indexes),
                                 CH(task_lookup, task_lookup_done));
    
    const task_t *next_task = TASK_REF(task_lookup_search);
    CHAN_OUT1(const task_t *, next_task, next_task, CALL_CH(ch_calc_indexes));
    TRANSITION_TO(task_calc_indexes);
}

void task_lookup_search()
{
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
    TRANSITION_TO(task_lookup_done);
}

void task_lookup_done()
{
    value_t key = *CHAN_IN1(value_t, key, CH(task_lookup, task_lookup_done));
    bool member = *CHAN_IN1(bool, member, CH(task_lookup_search, task_lookup_done));

    unsigned lookup_count = *CHAN_IN2(unsigned, lookup_count,
                                      CH(task_init, task_lookup_done),
                                      SELF_IN_CH(task_lookup_done));


    lookup_count++;
    CHAN_OUT1(unsigned, lookup_count, lookup_count, SELF_OUT_CH(task_lookup_done));

    LOG("lookup done [%u]: key %04x member %u\r\n", lookup_count, key, member);

    volatile uint32_t delay = 0x8ffff;
    while (delay--);

    if (lookup_count < NUM_LOOKUPS) {
        const task_t *next_task = TASK_REF(task_lookup);
        CHAN_OUT1(const task_t *, next_task, next_task, CH(task_lookup_done, task_generate_key));
        TRANSITION_TO(task_generate_key);
    } else {
        LOG("program done\r\n");
        TRANSITION_TO(task_init); // start over
    }
}

void init()
{
    WISP_init();

#ifdef CONFIG_EDB
    debug_setup();
#endif

    INIT_CONSOLE();

    GPIO(PORT_LED_1, DIR) |= BIT(PIN_LED_1);
    GPIO(PORT_LED_2, DIR) |= BIT(PIN_LED_2);
#if defined(PORT_LED_3)
    GPIO(PORT_LED_3, DIR) |= BIT(PIN_LED_3);
#endif

    __enable_interrupt();

#if defined(PORT_LED_3) // when available, this LED indicates power-on
    GPIO(PORT_LED_3, OUT) |= BIT(PIN_LED_3);
#endif

    PRINTF(".%u.\r\n", curctx->task->idx);
}

ENTRY_TASK(task_init)
INIT_FUNC(init)
