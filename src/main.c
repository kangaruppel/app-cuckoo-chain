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

typedef uint16_t hash_t;

struct msg_hash_args {
    CHAN_FIELD(uint8_t, data); // TODO: array?
    CHAN_FIELD(unsigned, data_len);
    CHAN_FIELD(const task_t*, next_task);
};

struct msg_hash {
    CHAN_FIELD(hash_t, hash);
};

TASK(1,  task_init)
TASK(2,  task_hash)
TASK(3,  task_hashed)

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
    uint8_t *data = CHAN_IN1(data, CALL_CH(ch_hash));
    unsigned data_len = *CHAN_IN1(data_len, CALL_CH(ch_hash));

    hash_t hash = djb_hash(data, data_len);

    CHAN_OUT(hash, hash, RET_CH(ch_hash));

    const task_t *next_task = *CHAN_IN1(next_task, CALL_CH(ch_hash));
    transition_to(next_task);
}

void task_init()
{
    const uint8_t data = 'X';
    const unsigned data_len = 1;

    PRINTF("init\r\n");
    PRINTF("data: %x len %u\r\n", data, data_len);

    CHAN_OUT(data, data, CALL_CH(ch_hash));
    CHAN_OUT(data_len, data_len, CALL_CH(ch_hash));

    CHAN_OUT(next_task, TASK_REF(task_hashed), CALL_CH(ch_hash));
    TRANSITION_TO(task_hash);
}

void task_hashed()
{
    PRINTF("hashed\r\n");

    hash_t hash = *CHAN_IN1(hash, RET_CH(ch_hash));

    PRINTF("hash: %04x\r\n", hash);

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
