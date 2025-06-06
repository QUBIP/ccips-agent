/*
 * Copyright (c) 2018 Gabriel López <gabilm@um.es>, Rafael Marín <rafa@um.es>, Fernando Pereñiguez <fernando.pereniguez@cud.upct.es> 
 *
 * This file is part of cfgipsec2.
 *
 * cfgipsec2 is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * cfgipsec2 is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef __PFKEYV2_ENTRY
#define __PFKEYV2_ENTRY

#include "utils.h"
#include "log.h"
#include "spd_entry.h"
#include "sad_entry.h"
#include "host.h"
#include "pfkeyv2_utils.h"
#include "sysrepo_utils.h"
#include "sysrepo_entries.h"
#include <sysrepo.h>
#include <errno.h>
#include <sys/types.h>
#include <linux/xfrm.h>
#include <pthread.h>

#define PFKEY_EXTLEN(msg) \
    PFKEY_UNUNIT64(((const struct sadb_ext *)(const void *)(msg))->sadb_ext_len)
#define PFKEY_UNUNIT64(a)   ((a) << 3)


typedef struct{
    int parent_pid;
    int socket;
	sr_session_ctx_t *session;
} register_thread;

int pf_addsad(sad_entry_node *sad_node);
int pf_exec_register(sr_session_ctx_t *session,int satype);
int pf_delsad(sad_entry_node *sad_node);
int pf_addpolicy(spd_entry_node *spd_node);
int pf_delpolicy(spd_entry_node *spd_node);
// int pf_getsad(sad_entry_node *sad_node);




typedef struct pfkey_msg_t pfkey_msg_t;

struct pfkey_msg_t
{
	/**
	 * PF_KEY message base
	 */
	struct sadb_msg *msg;

	/**
	 * PF_KEY message extensions
	 */
	union {
		struct sadb_ext *ext[SADB_EXT_MAX + 1];
		struct {
			struct sadb_ext *reserved;				/* SADB_EXT_RESERVED */
			struct sadb_sa *sa;						/* SADB_EXT_SA */
			struct sadb_lifetime *lft_current;		/* SADB_EXT_LIFETIME_CURRENT */
			struct sadb_lifetime *lft_hard;			/* SADB_EXT_LIFETIME_HARD */
			struct sadb_lifetime *lft_soft;			/* SADB_EXT_LIFETIME_SOFT */
			struct sadb_address *src;				/* SADB_EXT_ADDRESS_SRC */
			struct sadb_address *dst;				/* SADB_EXT_ADDRESS_DST */
			struct sadb_address *proxy;				/* SADB_EXT_ADDRESS_PROXY */
			struct sadb_key *key_auth;				/* SADB_EXT_KEY_AUTH */
			struct sadb_key *key_encr;				/* SADB_EXT_KEY_ENCRYPT */
			struct sadb_ident *id_src;				/* SADB_EXT_IDENTITY_SRC */
			struct sadb_ident *id_dst;				/* SADB_EXT_IDENTITY_DST */
			struct sadb_sens *sensitivity;			/* SADB_EXT_SENSITIVITY */
			struct sadb_prop *proposal;				/* SADB_EXT_PROPOSAL */
			struct sadb_supported *supported_auth;	/* SADB_EXT_SUPPORTED_AUTH */
			struct sadb_supported *supported_encr;	/* SADB_EXT_SUPPORTED_ENCRYPT */
			struct sadb_spirange *spirange;			/* SADB_EXT_SPIRANGE */
			struct sadb_x_kmprivate *x_kmprivate;	/* SADB_X_EXT_KMPRIVATE */
			struct sadb_x_policy *x_policy;			/* SADB_X_EXT_POLICY */
			struct sadb_x_sa2 *x_sa2;				/* SADB_X_EXT_SA2 */
#if defined(__linux__) || defined (__FreeBSD__)
			struct sadb_x_nat_t_type *x_natt_type;	/* SADB_X_EXT_NAT_T_TYPE */
			struct sadb_x_nat_t_port *x_natt_sport;	/* SADB_X_EXT_NAT_T_SPORT */
			struct sadb_x_nat_t_port *x_natt_dport;	/* SADB_X_EXT_NAT_T_DPORT */
#ifdef __linux__
			struct sadb_address *x_natt_oa;			/* SADB_X_EXT_NAT_T_OA */
			struct sadb_x_sec_ctx *x_sec_ctx;		/* SADB_X_EXT_SEC_CTX */
			struct sadb_x_kmaddress *x_kmaddress;	/* SADB_X_EXT_KMADDRESS */
#else
			struct sadb_address *x_natt_oai;		/* SADB_X_EXT_NAT_T_OAI */
			struct sadb_address *x_natt_oar;		/* SADB_X_EXT_NAT_T_OAR */
#ifdef SADB_X_EXT_NAT_T_FRAG
			struct sadb_x_nat_t_frag *x_natt_frag;	/* SADB_X_EXT_NAT_T_FRAG */
#ifdef SADB_X_EXT_SA_REPLAY
			struct sadb_x_sa_replay *x_replay;		/* SADB_X_EXT_SA_REPLAY */
			struct sadb_address *x_new_addr_src;	/* SADB_X_EXT_NEW_ADDRESS_SRC */
			struct sadb_address *x_new_addr_dst;	/* SADB_X_EXT_NEW_ADDRESS_DST */
#endif
#endif
#endif /* __linux__ */
#endif /* __linux__ || __FreeBSD__ */
		} __attribute__((__packed__));
	};
};


#endif


