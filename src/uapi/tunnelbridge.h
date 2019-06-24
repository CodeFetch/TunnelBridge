/* SPDX-License-Identifier: (GPL-2.0 WITH Linux-syscall-note) OR MIT */
/*
 * Copyright (C) 2019 Vincent Wiemann <vincent.wiemann@ironai.com>
 * Copyright (C) 2015-2019 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.
 *
 * Documentation
 * =============
 *
 * The below enums and macros are for interfacing with TunnelBridge, using generic
 * netlink, with family TB_GENL_NAME and version TB_GENL_VERSION. It defines two
 * methods: get and set. Note that while they share many common attributes,
 * these two functions actually accept a slightly different set of inputs and
 * outputs.
 *
 * TB_CMD_GET_DEVICE
 * -----------------
 *
 * May only be called via NLM_F_REQUEST | NLM_F_DUMP. The command should contain
 * one but not both of:
 *
 *    TBDEVICE_A_IFINDEX: NLA_U32
 *    TBDEVICE_A_IFNAME: NLA_NUL_STRING, maxlen IFNAMESIZ - 1
 *
 * The kernel will then return several messages (NLM_F_MULTI) containing the
 * following tree of nested items:
 *
 *    TBDEVICE_A_IFINDEX: NLA_U32
 *    TBDEVICE_A_IFNAME: NLA_NUL_STRING, maxlen IFNAMESIZ - 1
 *    TBDEVICE_A_PRIVATE_KEY: NLA_EXACT_LEN, len TB_KEY_LEN
 *    TBDEVICE_A_PUBLIC_KEY: NLA_EXACT_LEN, len TB_KEY_LEN
 *    TBDEVICE_A_LISTEN_PORT: NLA_U16
 *    TBDEVICE_A_FWMARK: NLA_U32
 *    TBDEVICE_A_PEERS: NLA_NESTED
 *        0: NLA_NESTED
 *            TBPEER_A_PUBLIC_KEY: NLA_EXACT_LEN, len TB_KEY_LEN
 *            TBPEER_A_PRESHARED_KEY: NLA_EXACT_LEN, len TB_KEY_LEN
 *            TBPEER_A_ENDPOINT: NLA_MIN_LEN(struct sockaddr), struct sockaddr_in or struct sockaddr_in6
 *            TBPEER_A_PERSISTENT_KEEPALIVE_INTERVAL: NLA_U16
 *            TBPEER_A_LAST_HANDSHAKE_TIME: NLA_EXACT_LEN, struct __kernel_timespec
 *            TBPEER_A_RX_BYTES: NLA_U64
 *            TBPEER_A_TX_BYTES: NLA_U64
 *            TBPEER_A_ALLOWEDIPS: NLA_NESTED
 *                0: NLA_NESTED
 *                    TBALLOWEDIP_A_FAMILY: NLA_U16
 *                    TBALLOWEDIP_A_IPADDR: NLA_MIN_LEN(struct in_addr), struct in_addr or struct in6_addr
 *                    TBALLOWEDIP_A_CIDR_MASK: NLA_U8
 *                0: NLA_NESTED
 *                    ...
 *                0: NLA_NESTED
 *                    ...
 *                ...
 *            TBPEER_A_PROTOCOL_VERSION: NLA_U32
 *        0: NLA_NESTED
 *            ...
 *        ...
 *
 * It is possible that all of the allowed IPs of a single peer will not
 * fit within a single netlink message. In that case, the same peer will
 * be written in the following message, except it will only contain
 * TBPEER_A_PUBLIC_KEY and TBPEER_A_ALLOWEDIPS. This may occur several
 * times in a row for the same peer. It is then up to the receiver to
 * coalesce adjacent peers. Likewise, it is possible that all peers will
 * not fit within a single message. So, subsequent peers will be sent
 * in following messages, except those will only contain TBDEVICE_A_IFNAME
 * and TBDEVICE_A_PEERS. It is then up to the receiver to coalesce these
 * messages to form the complete list of peers.
 *
 * Since this is an NLA_F_DUMP command, the final message will always be
 * NLMSG_DONE, even if an error occurs. However, this NLMSG_DONE message
 * contains an integer error code. It is either zero or a negative error
 * code corresponding to the errno.
 *
 * TB_CMD_SET_DEVICE
 * -----------------
 *
 * May only be called via NLM_F_REQUEST. The command should contain the
 * following tree of nested items, containing one but not both of
 * TBDEVICE_A_IFINDEX and TBDEVICE_A_IFNAME:
 *
 *    TBDEVICE_A_IFINDEX: NLA_U32
 *    TBDEVICE_A_IFNAME: NLA_NUL_STRING, maxlen IFNAMESIZ - 1
 *    TBDEVICE_A_FLAGS: NLA_U32, 0 or TBDEVICE_F_REPLACE_PEERS if all current
 *                      peers should be removed prior to adding the list below.
 *    TBDEVICE_A_PRIVATE_KEY: len TB_KEY_LEN, all zeros to remove
 *    TBDEVICE_A_LISTEN_PORT: NLA_U16, 0 to choose randomly
 *    TBDEVICE_A_FWMARK: NLA_U32, 0 to disable
 *    TBDEVICE_A_PEERS: NLA_NESTED
 *        0: NLA_NESTED
 *            TBPEER_A_PUBLIC_KEY: len TB_KEY_LEN
 *            TBPEER_A_FLAGS: NLA_U32, 0 and/or TBPEER_F_REMOVE_ME if the
 *                            specified peer should be removed rather than
 *                            added/updated and/or TBPEER_F_REPLACE_ALLOWEDIPS
 *                            if all current allowed IPs of this peer should be
 *                            removed prior to adding the list below.
 *            TBPEER_A_PRESHARED_KEY: len TB_KEY_LEN, all zeros to remove
 *            TBPEER_A_ENDPOINT: struct sockaddr_in or struct sockaddr_in6
 *            TBPEER_A_PERSISTENT_KEEPALIVE_INTERVAL: NLA_U16, 0 to disable
 *            TBPEER_A_ALLOWEDIPS: NLA_NESTED
 *                0: NLA_NESTED
 *                    TBALLOWEDIP_A_FAMILY: NLA_U16
 *                    TBALLOWEDIP_A_IPADDR: struct in_addr or struct in6_addr
 *                    TBALLOWEDIP_A_CIDR_MASK: NLA_U8
 *                0: NLA_NESTED
 *                    ...
 *                0: NLA_NESTED
 *                    ...
 *                ...
 *            TBPEER_A_PROTOCOL_VERSION: NLA_U32, should not be set or used at
 *                                       all by most users of this API, as the
 *                                       most recent protocol will be used when
 *                                       this is unset. Otherwise, must be set
 *                                       to 1.
 *        0: NLA_NESTED
 *            ...
 *        ...
 *
 * It is possible that the amount of configuration data exceeds that of
 * the maximum message length accepted by the kernel. In that case, several
 * messages should be sent one after another, with each successive one
 * filling in information not contained in the prior. Note that if
 * TBDEVICE_F_REPLACE_PEERS is specified in the first message, it probably
 * should not be specified in fragments that come after, so that the list
 * of peers is only cleared the first time but appened after. Likewise for
 * peers, if TBPEER_F_REPLACE_ALLOWEDIPS is specified in the first message
 * of a peer, it likely should not be specified in subsequent fragments.
 *
 * If an error occurs, NLMSG_ERROR will reply containing an errno.
 */

#ifndef _TB_UAPI_TUNNELBRIDGE_H
#define _TB_UAPI_TUNNELBRIDGE_H

#define TB_GENL_NAME "tunnelbridge"
#define TB_GENL_VERSION 1

#define TB_KEY_LEN 32

enum tb_cmd {
	TB_CMD_GET_DEVICE,
	TB_CMD_SET_DEVICE,
	__TB_CMD_MAX
};
#define TB_CMD_MAX (__TB_CMD_MAX - 1)

enum tbdevice_flag {
	TBDEVICE_F_REPLACE_PEERS = 1U << 0
};
enum tbdevice_attribute {
	TBDEVICE_A_UNSPEC,
	TBDEVICE_A_IFINDEX,
	TBDEVICE_A_IFNAME,
	TBDEVICE_A_PRIVATE_KEY,
	TBDEVICE_A_PUBLIC_KEY,
	TBDEVICE_A_FLAGS,
	TBDEVICE_A_LISTEN_PORT,
	TBDEVICE_A_FWMARK,
	TBDEVICE_A_PEERS,
	__TBDEVICE_A_LAST
};
#define TBDEVICE_A_MAX (__TBDEVICE_A_LAST - 1)

enum tbpeer_flag {
	TBPEER_F_REMOVE_ME = 1U << 0,
	TBPEER_F_REPLACE_ALLOWEDIPS = 1U << 1
};
enum tbpeer_attribute {
	TBPEER_A_UNSPEC,
	TBPEER_A_PUBLIC_KEY,
	TBPEER_A_PRESHARED_KEY,
	TBPEER_A_FLAGS,
	TBPEER_A_ENDPOINT,
	TBPEER_A_PERSISTENT_KEEPALIVE_INTERVAL,
	TBPEER_A_LAST_HANDSHAKE_TIME,
	TBPEER_A_RX_BYTES,
	TBPEER_A_TX_BYTES,
	TBPEER_A_ALLOWEDIPS,
	TBPEER_A_PROTOCOL_VERSION,
	__TBPEER_A_LAST
};
#define TBPEER_A_MAX (__TBPEER_A_LAST - 1)

enum tballowedip_attribute {
	TBALLOWEDIP_A_UNSPEC,
	TBALLOWEDIP_A_FAMILY,
	TBALLOWEDIP_A_IPADDR,
	TBALLOWEDIP_A_CIDR_MASK,
	__TBALLOWEDIP_A_LAST
};
#define TBALLOWEDIP_A_MAX (__TBALLOWEDIP_A_LAST - 1)

#endif /* _TB_UAPI_TUNNELBRIDGE_H */
