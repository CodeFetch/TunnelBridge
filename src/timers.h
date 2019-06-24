/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2019 Vincent Wiemann <vincent.wiemann@ironai.com>
 * Copyright (C) 2015-2019 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.
 */

#ifndef _TB_TIMERS_H
#define _TB_TIMERS_H

#include <linux/ktime.h>

struct tb_peer;

void tb_timers_init(struct tb_peer *peer);
void tb_timers_stop(struct tb_peer *peer);
void tb_timers_data_sent(struct tb_peer *peer);
void tb_timers_data_received(struct tb_peer *peer);
void tb_timers_any_authenticated_packet_sent(struct tb_peer *peer);
void tb_timers_any_authenticated_packet_received(struct tb_peer *peer);
void tb_timers_handshake_initiated(struct tb_peer *peer);
void tb_timers_handshake_complete(struct tb_peer *peer);
void tb_timers_session_derived(struct tb_peer *peer);
void tb_timers_any_authenticated_packet_traversal(struct tb_peer *peer);

static inline bool tb_birthdate_has_expired(u64 birthday_nanoseconds,
					    u64 expiration_seconds)
{
	return (s64)(birthday_nanoseconds + expiration_seconds * NSEC_PER_SEC)
		<= (s64)ktime_get_coarse_boottime();
}

#endif /* _TB_TIMERS_H */
