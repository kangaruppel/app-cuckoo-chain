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

#define NUM_BUCKETS 32 // must be a power of 2
#define MAX_RELOCATIONS 5

typedef uint16_t value_t;
typedef uint16_t hash_t;
typedef uint16_t fingerprint_t;
typedef uint16_t index_t; // bucket index

struct msg_key {
    CHAN_FIELD(value_t, key);
};

struct msg_self_key {
    SELF_CHAN_FIELD(value_t, key);
};

struct msg_fingerprint {
    CHAN_FIELD(fingerprint_t, fingerprint);
};

struct msg_index {
    CHAN_FIELD(index_t, index);
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

TASK(1,  task_init)
TASK(2,  task_insert)
TASK(3,  task_fingerprint)
TASK(4,  task_index_1)
TASK(5,  task_index_2)
TASK(6,  task_add)
TASK(7,  task_relocate)
TASK(8,  task_insert_done)

CHANNEL(task_init, task_insert, msg_key);
MULTICAST_CHANNEL(msg_key, ch_key, task_insert, task_fingerprint, task_index_1);
MULTICAST_CHANNEL(msg_filter, ch_filter, task_init,
                  task_add, task_relocate, task_insert_done);
MULTICAST_CHANNEL(msg_fingerprint, ch_fingerprint, task_fingerprint,
                  task_index_2, task_add);
MULTICAST_CHANNEL(msg_index, ch_index, task_index_1,
                  task_index_2, task_add);
CHANNEL(task_index_2, task_add, msg_index);
CHANNEL(task_add, task_relocate, msg_victim);
SELF_CHANNEL(task_add, msg_self_filter);
CHANNEL(task_add, task_insert_done, msg_filter);
MULTICAST_CHANNEL(msg_filter, ch_reloc_filter, task_relocate,
                  task_add, task_insert_done);
SELF_CHANNEL(task_relocate, msg_self_victim);
CHANNEL(task_relocate, task_add, msg_filter);
CHANNEL(task_relocate, task_insert_done, msg_filter);

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

void task_init()
{
    value_t key = 0x1;
    unsigned i;

    PRINTF("init: key: %x\r\n", key);

    CHAN_OUT1(value_t, key, key, CH(task_init, task_insert));

    for (i = 0; i < NUM_BUCKETS; ++i) {
        fingerprint_t fp = 0;
        CHAN_OUT1(fingerprint_t, filter[i], fp, MC_OUT_CH(ch_filter, task_init,
                               task_add, task_relocate, task_insert_done));
    }

    TRANSITION_TO(task_insert);
}

void task_insert()
{
    value_t key = rand(); // insert pseudo-random integers, for testing
    LOG("insert: key: %x\r\n", key);

    CHAN_OUT1(value_t, key, key,
              MC_OUT_CH(ch_key, task_insert, task_fingerprint, task_index_1));

    TRANSITION_TO(task_fingerprint);
}

void task_fingerprint()
{
    value_t key = *CHAN_IN1(value_t, key, MC_IN_CH(ch_key, task_insert,
                                                   task_fingerprint));

    fingerprint_t fp = djb_hash((uint8_t *)&key, sizeof(value_t));
    LOG("fingerprint: key %04x fp %04x\r\n", key, fp);

    CHAN_OUT1(fingerprint_t, fingerprint, fp,
             MC_OUT_CH(ch_fingerprint, task_fingerprint,
                       task_index_2, task_add));

    TRANSITION_TO(task_index_1);
}

void task_index_1()
{
    value_t key = *CHAN_IN1(value_t, key, MC_IN_CH(ch_key, task_insert,
                                                   task_index_1));

    index_t index1 = hash_to_index(key);
    LOG("index1: key %04x idx1 %u\r\n", key, index1);

    CHAN_OUT1(index_t, index, index1, MC_OUT_CH(ch_index, task_index_1,
                                      task_index_2, task_add));

    TRANSITION_TO(task_index_2);
}

void task_index_2()
{
    fingerprint_t fp = *CHAN_IN1(fingerprint_t, fingerprint,
                                 MC_IN_CH(ch_fingerprint,
                                          task_fingerprint, task_index_2));
    index_t index1 = *CHAN_IN1(index_t, index,
                      MC_IN_CH(ch_index, task_index_1, task_index_2));

    index_t fp_hash = hash_to_index(fp);
    index_t index2 = index1 ^ fp_hash;

    LOG("index2: fp hash: %04x idx1 %u idx2 %u\r\n",
        fp_hash, index1, index2);

    CHAN_OUT1(index_t, index, index2, CH(task_index_2, task_add));
    TRANSITION_TO(task_add);
}

void task_add()
{
    // Fingerprint being inserted
    fingerprint_t fp = *CHAN_IN1(fingerprint_t, fingerprint,
                                 MC_IN_CH(ch_fingerprint,
                                          task_fingerprint, task_add));
    LOG("add: fp %04x\r\n", fp);

    // index1,fp1 and index2,fp2 are the two alternative buckets

    index_t index1 = *CHAN_IN1(index_t, index,
                               MC_IN_CH(ch_index, task_index_1, task_add));

    fingerprint_t fp1 = *CHAN_IN3(fingerprint_t, filter[index1],
                                 MC_IN_CH(ch_filter, task_init, task_add),
                                 CH(task_relocate, task_add),
                                 SELF_IN_CH(task_add));
    LOG("add: idx1 %u fp1 %04x\r\n", index1, fp1);

    if (!fp1) {
        LOG("add: filled empty slot at idx1 %u\r\n", index1);

        CHAN_OUT3(fingerprint_t, filter[index1], fp,
                  CH(task_add, task_relocate), SELF_OUT_CH(task_add),
                  CH(task_add, task_insert_done));

        TRANSITION_TO(task_insert_done);
    } else {
        index_t index2 = *CHAN_IN1(index_t, index, CH(task_index_2, task_add));
        fingerprint_t fp2 = *CHAN_IN3(fingerprint_t, filter[index2],
                                     MC_IN_CH(ch_filter, task_init, task_add),
                                     CH(task_relocate, task_add),
                                     SELF_IN_CH(task_add));
        LOG("add: fp2 %04x\r\n", fp2);

        if (!fp2) {
            LOG("add: filled empty slot at idx2 %u\r\n", index2);

            CHAN_OUT3(fingerprint_t, filter[index2], fp,
                      CH(task_add, task_relocate), SELF_OUT_CH(task_add),
                      CH(task_add, task_insert_done));

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
            CHAN_OUT3(fingerprint_t, filter[index_victim], fp,
                     CH(task_add, task_relocate), SELF_OUT_CH(task_add),
                     CH(task_add, task_insert_done));

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
                  CH(task_add, task_relocate), SELF_IN_CH(task_relocate));

    LOG("relocate: next victim fp %04x\r\n", fp_next_victim);

    // Take victim's place
    CHAN_OUT3(fingerprint_t, filter[index2_victim], fp_victim,
             CH(task_relocate, task_add), SELF_OUT_CH(task_relocate),
             CH(task_relocate, task_insert_done));

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
                                     MC_IN_CH(ch_filter, task_init,
                                              task_insert_done),
                                     CH(task_add, task_insert_done),
                                     CH(task_relocate, task_insert_done));
        LOG("%04x ", fp);
        if (i > 0 && (i + 1) % 8 == 0)
            LOG("\r\n");
    }
    LOG("\r\n");

    volatile uint32_t delay = 0xfffff;
    while (delay--);

    TRANSITION_TO(task_insert);
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
