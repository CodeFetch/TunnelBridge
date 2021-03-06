/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2019 Vincent Wiemann <vincent.wiemann@ironai.com>
 * Copyright (C) 2015-2019 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.
 */

#ifndef ENCODING_H
#define ENCODING_H

#include <stdbool.h>
#include <stdint.h>
#include "containers.h"

#define TB_KEY_LEN_BASE64 ((((TB_KEY_LEN) + 2) / 3) * 4 + 1)
#define TB_KEY_LEN_HEX (TB_KEY_LEN * 2 + 1)

void key_to_base64(char base64[static TB_KEY_LEN_BASE64], const uint8_t key[static TB_KEY_LEN]);
bool key_from_base64(uint8_t key[static TB_KEY_LEN], const char *base64);

void key_to_hex(char hex[static TB_KEY_LEN_HEX], const uint8_t key[static TB_KEY_LEN]);
bool key_from_hex(uint8_t key[static TB_KEY_LEN], const char *hex);

bool key_is_zero(const uint8_t key[static TB_KEY_LEN]);

#endif
