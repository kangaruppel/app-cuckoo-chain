#include <msp430.h>

#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>

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

typedef uint16_t value_t;
typedef uint16_t hash_t;
typedef uint16_t fingerprint_t;
typedef uint16_t index_t; // bucket index

struct msg_key {
    CHAN_FIELD(value_t, key);
};

struct msg_fingerprint {
    CHAN_FIELD(fingerprint_t, fingerprint);
};

struct msg_index {
    CHAN_FIELD(index_t, index);
};

struct msg_hash_args {
    CHAN_FIELD(value_t, data);
    CHAN_FIELD(const task_t*, next_task);
};

struct msg_hash {
    CHAN_FIELD(hash_t, hash);
};

TASK(1,  task_init)
TASK(2,  task_hash)
TASK(3,  task_insert)
TASK(4,  task_fingerprint)
TASK(5,  task_index_1)
TASK(6,  task_index_2)

MULTICAST_CHANNEL(msg_key, ch_key, task_init, task_insert, task_fingerprint);
CHANNEL(task_fingerprint, task_index_1, msg_fingerprint);
CHANNEL(task_index_1, task_index_2, msg_index);

CALL_CHANNEL(ch_hash, msg_hash_args);
RET_CHANNEL(ch_hash, msg_hash);

hash_t djb_hash(uint8_t* data, unsigned len)
{
   uint32_t hash = 5381;
   unsigned int i;

   for(i = 0; i < len; data++, i++)
      hash = ((hash << 5) + hash) + (*data);

   return hash & 0xFFFF;
}

void task_hash()
{
    value_t data = *CHAN_IN1(data, CALL_CH(ch_hash));
    hash_t hash = djb_hash((uint8_t *)&data, sizeof(value_t));
    LOG("hash: data %04x hash %04x\r\n", data, hash);

    CHAN_OUT(hash, hash, RET_CH(ch_hash));

    const task_t *next_task = *CHAN_IN1(next_task, CALL_CH(ch_hash));
    transition_to(next_task);
}

void task_init()
{
    const value_t key = 0x4242;

    PRINTF("init: key: %x\r\n", key);

    CHAN_OUT(key, key, MC_OUT_CH(ch_key, task_init,
                                 task_insert, task_fingerprint));

    TRANSITION_TO(task_insert);
}

void task_insert()
{
    value_t key = *CHAN_IN1(key, MC_IN_CH(ch_key, task_init, task_insert));

    LOG("insert: key: %x\r\n", key);

    // Call: calc the fingerprint for the key by hashing the key
    //
    // NOTE: The fingerprint now is the same hash function the one for
    // calculating the index, but we don't re-use to keep the code modular,
    // because these hash functions may be different.

    CHAN_OUT(data, key, CALL_CH(ch_hash));

    CHAN_OUT(next_task, TASK_REF(task_fingerprint), CALL_CH(ch_hash));
    TRANSITION_TO(task_hash);
}

void task_fingerprint()
{
    hash_t hash = *CHAN_IN1(hash, RET_CH(ch_hash));
    LOG("fingerprint: hash %04x\r\n", hash);

    fingerprint_t fingerprint = hash; // could be more complex

    CHAN_OUT(fingerprint, fingerprint, CH(task_fingerprint, task_index_1));

    // TODO: send the fingerprint to somewhere

    // Call: calc the index 1 of the key by hashing the key

    value_t key = *CHAN_IN1(key, MC_IN_CH(ch_key, task_init, task_fingerprint));

    LOG("fingerprint: key %x\r\n", key);

    CHAN_OUT(data, key, CALL_CH(ch_hash));

    CHAN_OUT(next_task, TASK_REF(task_index_1), CALL_CH(ch_hash));
    TRANSITION_TO(task_hash);
}

void task_index_1()
{
    hash_t hash = *CHAN_IN1(hash, RET_CH(ch_hash));

    index_t index1 = hash & (NUM_BUCKETS - 1); // & (x-1) valid only for power of 2
    LOG("index1: key hash: %04x idx1 %04x\r\n", hash, index1);

    CHAN_OUT(index, index1, CH(task_index_1, task_index_2));

    // Call: hash the fingerprint

    fingerprint_t fingerprint = *CHAN_IN1(fingerprint,
                                CH(task_fingerprint, task_index_1));

    CHAN_OUT(data, fingerprint, CALL_CH(ch_hash));

    CHAN_OUT(next_task, TASK_REF(task_index_2), CALL_CH(ch_hash));
    TRANSITION_TO(task_hash);
}

void task_index_2()
{
    hash_t hash = *CHAN_IN1(hash, RET_CH(ch_hash));
    index_t index1 = *CHAN_IN1(index, CH(task_index_1, task_index_2));

    hash_t fp_hash = hash & (NUM_BUCKETS - 1); // & (x-1) valid only for power of 2
    index_t index2 = index1 ^ fp_hash;

    LOG("index2: fp hash: %04x idx1 %04x idx2 %04x\r\n",
        fp_hash, index1, index2);

    volatile uint32_t delay = 0xffff;
    while (delay--);

    TRANSITION_TO(task_init);
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
