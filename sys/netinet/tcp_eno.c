/*-
 * Copyright (c) 2017 Robert Koehler <robert.koehler@ee39.de>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */


#include <sys/cdefs.h> /* XXX ENO what for */
__FBSDID("$FreeBSD: ... $");

#include "opt_inet.h" /* other <.h> need to know about TCP_ENO */

#include <sys/types.h> /* sbuf_*, u_char ... */
#include <sys/systm.h> /* printf */
#include <sys/sbuf.h> /* sbuf_ */
#include <sys/sysctl.h>
#include <sys/_bitset.h>
#include <sys/bitset.h>

/************ XXX ENO blurry block of dependencies for tcp_var */
#include <sys/param.h>
#include <sys/kernel.h>
#include <sys/limits.h>
#include <sys/lock.h>

#include <sys/rmlock.h>
#include <sys/socket.h>
#include <sys/socketvar.h>
#include <sys/sysctl.h>
/********************/


#include <netinet/in.h> /* IPPORT_MAX */
#include <netinet/tcp_var.h>

// XXX ENO does this bug? #include <netinet/in_pcb.h> /* (struct inpcb).inp_fport */
#include <netinet/tcp_eno.h>



static MALLOC_DEFINE(M_CONTROL, "eno_control", "TCP ENO control");
static MALLOC_DEFINE(M_SESSID, "eno_sessid", "TCP ENO protocol session ID");
static MALLOC_DEFINE(M_OPTION, "eno_option", "TCP ENO transcript");
static MALLOC_DEFINE(M_PROTO_DATA, "eno_proto_data", "data for TEP");





#define _PROTOS_SIZE		8
/* ENO_PROTO_NONE = 0 in .h */
#define _PROTO_TCPCRYPT		1
#define _PROTO_USE_TLS		2
#define _PROTO_XOR		3
#define _PROTO_NONCE		4
#define _PROTO_SQRT		5
#define _PROTO_FIRST_FREE	6



/*
 * ### sysctl
 */

/* ENO XXX when to use static SYSCTL_NODE and static VNET_DEFINE? */

SYSCTL_NODE(_net_inet_tcp, OID_AUTO, eno, CTLFLAG_RW, 0, "TCP ENO");

VNET_DEFINE(uint8_t, tcp_eno_specs[TCP_ENO_SPEC_SIZE]) = {
	_TEP_XOR,
	_TEP_NONCE,
	_TEP_USE_TLS,
	_TEP_SQRT_A,
	_TEP_SQRT_B,
	/* XXX ENO collision with _TEP_SQRT_:
	_TEP_TCPCRYPT_ECDHE_P256,
	_TEP_TCPCRYPT_ECDHE_P521,
	_TEP_TCPCRYPT_ECDHE_CURVE25519,
	_TEP_TCPCRYPT_ECDHE_CURVE448, */
	0
};

/* easy access to SYSCTL_HANDLER_ARGS */
#define str ((char *) arg1)
#define size arg2

static int
tcp_eno_handle_optional_hexstring(SYSCTL_HANDLER_ARGS) {
	int error;
	size_t len;

	error = sysctl_handle_string(oidp, arg1, arg2, req);
	if(error)
		return (error);
	len = strnlen(str, size);
	if(len < 2 || strncmp(str, "0x", 2))
		return (0);
	if(len % 2)
		return (EINVAL);

	/* can just write it into the string itself, there is enough space luckily */
	for(uint8_t i = 0; i * 2 + 3 < len; i ++)
		sscanf(str + i * 2 + 2, "%2hhx", &str[i]);
	str[len / 2 - 1] = '\0';

	return (0);
}

static int
tcp_eno_handle_specs(SYSCTL_HANDLER_ARGS) {
	int error;
	error = tcp_eno_handle_optional_hexstring(oidp, arg1, arg2, req);
	if(error)
		return (error);

	for(uint8_t i = 0; i < size && str[i] != '\0'; i ++)
		if((str[i] & 0x7f) < 0x20)
			return (EINVAL);
	return (0);
}
#undef str
#undef size

#define	V_tcp_eno_specs			VNET(tcp_eno_specs)
SYSCTL_PROC(_net_inet_tcp_eno, OID_AUTO, specs, CTLFLAG_VNET | CTLTYPE_STRING |
    CTLFLAG_WR, &V_tcp_eno_specs, sizeof(V_tcp_eno_specs), tcp_eno_handle_optional_hexstring, "A",
    "Default encryption specs in order of descending priority, format \"0xBEEF\" allowed");

/* SYSCTL_BOOL seems to be new & undocumented in man 9 sysctl */
VNET_DEFINE(bool, tcp_eno_enable_connect) = 1;
#define	V_tcp_eno_enable_connect	VNET(tcp_eno_enable_connect)
SYSCTL_BOOL(_net_inet_tcp_eno, OID_AUTO, enable_connect, CTLFLAG_VNET | CTLFLAG_RW,
    &VNET_NAME(tcp_eno_enable_connect), 0,
    "Enable ENO for active opener");

VNET_DEFINE(bool, tcp_eno_enable_listen) = 1;
#define	V_tcp_eno_enable_listen	VNET(tcp_eno_enable_listen)
SYSCTL_BOOL(_net_inet_tcp_eno, OID_AUTO, enable_listen, CTLFLAG_VNET | CTLFLAG_RW,
    &VNET_NAME(tcp_eno_enable_listen), 0,
    "Enable ENO for passive opener");




VNET_DEFINE(tcp_eno_ports_t, tcp_eno_bad_connect_ports) = ENO_PORT_INIT();
#define	V_tcp_eno_bad_connect_ports	VNET(tcp_eno_bad_connect_ports)
VNET_DEFINE(tcp_eno_ports_t, tcp_eno_bad_listen_ports) = ENO_PORT_INIT();
#define	V_tcp_eno_bad_listen_ports	VNET(tcp_eno_bad_listen_ports)


/* XXX ENO think about locking ... */
static int
tcp_eno_handle_portlist(SYSCTL_HANDLER_ARGS) {
	tcp_eno_ports_t *portlist = (tcp_eno_ports_t *) arg1;
	char inbuf[req->newlen + 1];
	struct sbuf sb;
	int error;
	int port;
	char *portstr, *end;

	/* create output */
	sbuf_new_for_sysctl(&sb, NULL, 128, req);

	for(uint32_t i = 0, comma = 0; i <= IPPORT_MAX; i ++) /* XXX ENO check type size ... we are using the whole uint16_t space + 1? */
		if(ENO_PORT_ISSET(portlist, i))
			sbuf_printf(&sb, comma ++ ? ",%d" : "%d", i);

	error = sbuf_finish(&sb); /* implicit SYSCTL_OUT() */
	sbuf_delete(&sb);

	/* read input */
	if (error == 0 && req->newptr != NULL) {
		error = SYSCTL_IN(req, &inbuf, req->newlen);
		if (error)
			return (error);
		ENO_PORT_ZERO(portlist);

		if(req->newlen == 0)
			return (0); /* deleted ports, done */

		inbuf[req->newlen] = '\0';
		portstr = inbuf;

		do {
			port = strtol(portstr, &end, 10);
			if(portstr == end || (*end != ',' && *end != '\0'))
				return (EINVAL);
			if(port < 0 || port > IPPORT_MAX)
				return (EINVAL);
			ENO_PORT_SET(portlist, port);
			portstr = end + 1;
		} while(*end == ',');
	}

	return (error);
}


SYSCTL_PROC(_net_inet_tcp_eno, OID_AUTO, bad_connect_ports, CTLFLAG_VNET | CTLTYPE_STRING |
    CTLFLAG_RW, (void *) &V_tcp_eno_bad_connect_ports, 0, tcp_eno_handle_portlist, "A",
    "Disable ENO on specified ports for active openers");

SYSCTL_PROC(_net_inet_tcp_eno, OID_AUTO, bad_listen_ports, CTLFLAG_VNET | CTLTYPE_STRING |
    CTLFLAG_RW, (void *) &V_tcp_eno_bad_listen_ports, 0, tcp_eno_handle_portlist, "A",
    "Disable ENO on specified ports for passive openers");



/*
 * ### TEP register
 */



uint8_t _xor_subopt_create_syn(struct tcpcb *tp, uint8_t tep, uint8_t *buf_end, uint8_t avail);
uint8_t _xor_subopt_reply(struct tcp_eno_control *ec, uint8_t *buf, uint8_t len);
void _xor_subopt_parse_syn_ack(struct tcpcb *tp, uint8_t *buf, uint8_t len);

uint8_t _nonce_subopt_create_syn(struct tcpcb *tp, uint8_t tep, uint8_t *buf_end, uint8_t avail);
uint8_t _nonce_subopt_reply(struct tcp_eno_control *ec, uint8_t *buf, uint8_t len);

uint8_t _sqrt_subopt_create_syn(struct tcpcb *tp, uint8_t tep, uint8_t *buf_end, uint8_t avail);
uint8_t _sqrt_subopt_reply(struct tcp_eno_control *ec, uint8_t *buf, uint8_t len);


/* XXX ENO this must become visible via header */
/* just like in_proto.c */
struct tcp_eno_proto _protos[_PROTOS_SIZE] = {
	[ENO_PROTO_NONE] = {}, /* XXX ENO undefined teps will point and stop here. Later we can have memory usage optimization. */
	[_PROTO_TCPCRYPT] = {
	},
	[_PROTO_USE_TLS] = {
	},
	[_PROTO_XOR] = {
		.ep_subopt_create_syn = _xor_subopt_create_syn,
		.ep_subopt_reply = _xor_subopt_reply,
		.ep_subopt_parse_syn_ack = _xor_subopt_parse_syn_ack
	},
	[_PROTO_NONCE] = {
		.ep_subopt_create_syn = _nonce_subopt_create_syn,
		.ep_subopt_reply = _nonce_subopt_reply,
	},
	[_PROTO_SQRT] = {
		.ep_subopt_create_syn = _sqrt_subopt_create_syn,
		.ep_subopt_reply = _sqrt_subopt_reply,
	},
	[_PROTO_FIRST_FREE ... _PROTOS_SIZE - 1] = { /* add addtl. slots for dynamic loading */
		.ep_spacer = 1
	},
};





/* multiple protocol identifiers ("TEPs") can be assigned to one proto, store them in a map for fast lookup */
#define _TEP_MAP_SIZE				(128 - 32)
#define _TEP_MAP_KEY(tep)			((tep & 0x7f) - 32)
#define _TEP_MAP(tep)				_tep_map[_TEP_MAP_KEY(tep)]
#define _TEP_MAP_ISSET(tep)			(_TEP_MAP(tep) != ENO_PROTO_NONE)
/* gives you a ptr to the proto. for undefined TEP this will give you an empty disabled proto. FOR NOW. better use _ISSET before */
#define _TEP_MAP_PROTO(tep)			(((struct tcp_eno_proto*) &_protos) + _TEP_MAP(tep))
/* evaluates to 1 on error */
#define _TEP_MAP_REGISTER(tep, proto_no)	(_TEP_MAP_ISSET(tep) ? 1 : (_TEP_MAP(tep) = proto_no) & 0) 	/* XXX ENO untested */
#define _TEP_MAP_UNREGISTER(tep)		(_TEP_MAP(tep) = ENO_PROTO_NONE)  					/* XXX ENO untested */

uint8_t _tep_map[_TEP_MAP_SIZE] = {
	/* XXX ENO collision with _TEP_SQRT
	[_TEP_MAP_KEY(_TEP_TCPCRYPT_ECDHE_P256)] = _PROTO_TCPCRYPT,
	[_TEP_MAP_KEY(_TEP_TCPCRYPT_ECDHE_P521)] = _PROTO_TCPCRYPT,
	[_TEP_MAP_KEY(_TEP_TCPCRYPT_ECDHE_CURVE25519)] = _PROTO_TCPCRYPT,
	[_TEP_MAP_KEY(_TEP_TCPCRYPT_ECDHE_CURVE448)] = _PROTO_TCPCRYPT, */
	[_TEP_MAP_KEY(_TEP_SQRT_A)] = _PROTO_SQRT,
	[_TEP_MAP_KEY(_TEP_SQRT_B)] = _PROTO_SQRT,
	[_TEP_MAP_KEY(_TEP_USE_TLS)] = _PROTO_USE_TLS,
	[_TEP_MAP_KEY(_TEP_XOR)] = _PROTO_XOR,
	[_TEP_MAP_KEY(_TEP_NONCE)] = _PROTO_NONCE
};


/*
 * ### internal definitions
 */




/*
 * ### option handling
 */




void tcp_eno_init() {
	/* XXX ENO which default VNET is determined here? */
}


/* USAGE:
 *
 * uint8_t proto_no = tcp_eno_proto_register((struct tcp_eno_proto) {
 *         .ep_subopt_reply =
 *         .ep_subopt_parse_syn_ack =
 *         .ep_subopt_create_syn =
 *         ... =
 * });
 *
 * _TEP_MAP_REGISTER(0x21, proto_no)
 * _TEP_MAP_REGISTER(0x22, proto_no)
 *
 * XXX ENO this func is not thread-safe!
 *
 * XXX ENO lock proto before doing that
 * - do not read while copying, it could be incomplete --> list would be better
 */
int8_t tcp_eno_proto_register(struct tcp_eno_proto prot) {

	for(int8_t i = 1; i < _PROTOS_SIZE; i ++)
		if(_protos[i].ep_spacer) {
			bcopy((char *) &_protos[i], (char *) &prot, sizeof(struct tcp_eno_proto));
			return i;
		}

	return -1; /* no space */
}

/*
 * This complicated and low-prio.
 *
 * Unguarded unregister would cause any hook to be unavailable even if there is an active connection,
 * leading to inconsistent state, possibly sending cipher data to application.
 *
 * XXX ENO implement tcp_eno_proto_unregister()
 */
void tcp_eno_proto_unregister(uint8_t proto_no) {
	/*
	 * possible mechanism:
	 * - if ep_active_connections == 0, unload right away. exit. (else:)
	 * - set proto.ep_unregistering = 1
	 * - do not offer ep_unregistering proto for new connections
	 * - in _control_free(), decrease own proto's ep_active_connections
	 * - check if own proto's ep_active_connections == 0, then unload
	 *
	 * - increase ep_active_connections when proto is ...
	 *      - chosen in _reply() by sending (passive opener)
	 *      - confirmed by sending an _ack() (active opener)
	 *      !!! still this would make some active handshakes fail
	 *      !!! alternative: count earlier, be safe and create even more load?
	 *
	 * - unloading is
	 *     - cleaning any references to proto in _TEP_MAP using _TEP_MAP_UNREGISTER(tep)
	 *     - setting ep_spacer = 1 signalling free slot
	 *
	 * down sides:
	 * - will do a lot if locking counting active connections for unregister action that will probably never happen
	 */
}


/* XXX ENO remove ... */
#define TCP_ENO_CONTROL_AUTOALLOC(tp)	\
	(tp->t_eno != NULL || (tp->t_eno = tcp_eno_control_alloc()) != NULL)
/* usage:
 * if(!TCP_ENO_CONTROL_AUTOALLOC(tp))
 * 	break;
 * ...
 * tp->t_eno->foo ... use it
 */

/* XXX ENO !!! make sure all callees fail i.e. do not acces tp->t_eno if return is non-zero */
struct tcp_eno_control *tcp_eno_control_alloc() {
	struct tcp_eno_control *ec;

	ec = malloc(sizeof(struct tcp_eno_control), M_CONTROL, M_ZERO | M_NOWAIT);
	/* M_WAITOK will cause trouble to tcpcb_create: nonsleepable locks rw tcpinp and rw tcp are held*/
	if(ec == NULL)
		return NULL; /* no good */

	printf("tcp_eno_control_alloc() ec=%x\n", (uint32_t) ec);
	ec->ec_state = ENOS_OFF;
	ec->ec_enabled = ENO_ENABLED_SYSCTL;
	ec->ec_self_gopt = 0;
	ec->ec_peer_gopt = 0;
	ec->ec_aa_mandatory = 0;
	ec->ec_tep_mandatory = 0;
	ec->ec_negspec = 0;

	/* XXX ENO just set a pointer to NULL to look up from here ... or malloc own */
	bcopy(V_tcp_eno_specs, &ec->ec_specs, sizeof(ec->ec_specs));
	/* t_eno_xor_key will be initialized on use */

	return ec;
}

void tcp_eno_control_free(struct tcp_eno_control *ec) {
	if(ec == NULL) {
		printf("tcp_eno_control_free() ec=NULL\n");
		return;
	}

	printf("tcp_eno_control_free() ec=%x nspec=%d sessid=%d s_trans=%d p_trans=%d proto=%d\n",
	       (uint32_t) ec, ec->ec_negspec, ec->ec_sessid != NULL,
	       ec->ec_self_transcript != NULL, ec->ec_peer_transcript != NULL, ec->ec_proto != NULL);
	free(ec->ec_sessid, M_SESSID);
	free(ec->ec_self_transcript, M_OPTION);
	free(ec->ec_peer_transcript, M_OPTION);
	free(ec->ec_proto, M_PROTO_DATA);
	free(ec, M_CONTROL);
}


/* alloc space for eno option. structure is always <tcpopt> <len> <data>. len must be >= 2 */
uint8_t *tcp_eno_option_alloc(uint8_t *data) {
	if(TCP_ENO_OPT_LEN(data) < 2) {
		printf("tcp_eno_option_alloc() malformed option received. rejecting\n");
		return NULL;
		// kassert
	}
	uint8_t *o = malloc(TCP_ENO_OPT_LEN(data), M_OPTION, M_NOWAIT);
	if(o == NULL)
		return NULL;

	bcopy(data, o, TCP_ENO_OPT_LEN(data));
	return o;
}

/* must be at least 33 bytes long */
uint8_t *tcp_eno_sessid_alloc(uint8_t *data, uint8_t len) {
	if(len < 33) {
		printf("tcp_eno_sessid_alloc() nonstd allocation request\n");
		/* return NULL; */
	}
	uint8_t *sessid = malloc(len, M_SESSID, M_NOWAIT);
	if(sessid == NULL)
		return NULL;

	bcopy(data, sessid, len);
	return sessid;
}



#define SUBOPT_IS_GOPT(b)	(!(b & 0xe0))		/* 0 0 0 x x x x x */
#define SUBOPT_IS_LEN(b)	((b & 0xe0) == 0x80)	/* 1 0 0 n n n n n */

/*
 * soptr must be initialized to null. first value of solen does not matter.
 * soptr will contain a ptr to current option, always the tep or global opt, length will always be skipped.
 * return will be len of the option in soptr or 0 if end reached or <0 if error.
 * feed back return as next solen
 */
int8_t subopt(uint8_t *tcpopt, uint8_t **soptr, int8_t solen);
int8_t subopt(uint8_t *tcpopt, uint8_t **soptr, int8_t solen) {
	uint8_t len = tcpopt[1];
	uint8_t opt;

	if(*soptr == NULL)
		*soptr = tcpopt + (tcpopt[0] == TCPOPT_EXPERIMENTAL ? 4 : 2);
	else
		*soptr += solen;

	if(*soptr >= tcpopt + len)
		return 0; /* done */

	opt = **soptr;

	if(SUBOPT_IS_LEN(opt)) {
		solen = (opt & 0x1f) + 2; /* data len is (n+1), add one for the tep */
		(*soptr) ++;

		if(*soptr + solen > tcpopt + len) {
			printf("[suboption data len] > available cnt!?\n"); /* XXX RFC: ignore complete ENO option now!! */
			return -1;
		}

		opt = **soptr;
		if(~opt & 0x80 || (opt & 0x7f) < 0x20) {
			printf("invalid data after [suboption data len] ... need a v=1 TEP here\n");  /* XXX RFC: ignore complete ENO option now!! */
			return -2;
		}
		return solen;
	}

	if(SUBOPT_IS_GOPT(opt) || (opt & 0x80) == 0)
		return 1;

	/* it's the end of option TEP, give out all the rest */
	return len - (*soptr - tcpopt);
}



#define _SOPTBUF_MAXLEN 24 /* max tcp sopt len */
#define _SOPTBUF_MAXLEN_REPLY (_SOPTBUF_MAXLEN - 2) /* -gopt, -len byte */


/* XXX ENO function could rearrange options to save a byte sometimes, but priority is defined by user */
void tcp_eno_option_create_syn(struct tcpcb *tp, struct tcpopt *to) {
#define _OPTION_MAXLEN 30
	uint8_t buf[_OPTION_MAXLEN];
	uint8_t *end = buf + _OPTION_MAXLEN;
	uint8_t *ptr = end;
	uint8_t used = 0;
	uint8_t len;

	KASSERT(tp->t_eno != NULL, ("%s: t_eno is NULL", __func__));

	if(!(tp->t_eno->ec_enabled == ENO_ENABLED_SYSCTL ? V_tcp_eno_enable_connect : tp->t_eno->ec_enabled)) {
		tp->t_eno->ec_state = ENOS_OFF | ENOS_SYN | ENOS_DISABLED;
		return;
	}

	/*
	 * XXX ENO continue here
	 * XXX ENO where get I the XXX_PORT from?
	 * - (struct tcphdr).th_dport
	 * - better use trusted value from connection, start navigation to it from tp
	 * - follow how connect() configures the tp for a new connection
	 * - first attempts failed :(
	if(ENO_PORT_ISSET(V_tcp_eno_bad_connect_ports, XXX_PORT)) {
		printf("tcp_eno_option_create_syn(): port %d in bad connect ports\n", XXX_PORT);
		tp->t_eno->ec_state = OFF|SYN|BAD_PORT
		return;
	}
	 */

	tp->t_eno->ec_state = ENOS_NEGOTIATE;

	for(uint8_t tep, i = 0; i < sizeof(tp->t_eno->ec_specs) && (tep = tp->t_eno->ec_specs[i]) != 0; i ++) {
		if(!_TEP_MAP_ISSET(tep)) {
			printf("tcp_eno_option_create_syn() tep 0x%02x has no proto. This should never happen.\n", tep);
			continue;
		}
		struct tcp_eno_proto *proto = _TEP_MAP_PROTO(tep);

		if(proto->ep_subopt_create_syn == NULL) {
			printf("tcp_eno_option_create_syn() no ep_subopt_create_syn for tep 0x%02x, proto[%d]\n", tep, _TEP_MAP(tep));
			continue;
		}

		printf("tcp_eno_option_create_syn() processing tep 0x%02x ptr=%lx\n", tep, (long) ptr);
		len = proto->ep_subopt_create_syn(tp, tep, ptr, _OPTION_MAXLEN - used - 2 - 4); /* addtl. len byte and gopt, 4 byte tcp option, may not be used */

		printf("tcp_eno_option_create_syn() len=%d\n", len);
		/* the last option (ptr == end) does not require a len byte */
		if(len > 1 && ptr != end) {
			len ++;
			*(ptr - len) = 0x80 | (len - 3) /* & 0x1f ... no serious implementation will exceed this */;
		}

		ptr -= len;
		used += len;

		if(used == _OPTION_MAXLEN - 1) /* XXX ENO what is going on here? */
			break;
	}

	if(used == 0) {
		printf("did not add any teps, disable eno\n");
		return;
	}

	if(tp->t_eno->ec_self_gopt != 0)
		*(-- ptr) = tp->t_eno->ec_self_gopt & 0x1f;

	ptr -= TCP_ENO_OPTHEADER_LEN;
	bcopy((char []) TCP_ENO_OPTHEADER(used + TCP_ENO_OPTHEADER_LEN), ptr, TCP_ENO_OPTHEADER_LEN);

	/* XXX ENO if no eno control, control_alloc() */
	tp->t_eno->ec_self_transcript = tcp_eno_option_alloc(ptr);
	if(tp->t_eno->ec_self_transcript == NULL) {
		printf("tcp_eno_option_create() could not alloc mem for tcp eno ctrl\n");
		TCP_ENO_FAIL(tp->t_eno, ENOS_SYN | ENOS_NOMEM);
		return;
	}

	to->to_flags |= TOF_ENO;
	to->to_eno = tp->t_eno->ec_self_transcript; /* will be freed on tcpcb disposal only, we can pass a pointer */
}

/* to is output */
void tcp_eno_option_reply(uint8_t *peer_transcript, struct tcp_eno_control *ec, struct tcpopt *to) {
	uint8_t	*soptr = NULL;
	int8_t	solen = 0;

	bool gopt_set = 0;
	uint8_t *best_tep = NULL;
	uint8_t	best_tep_len;
	uint8_t best_tep_prio = 255;

	if(peer_transcript == NULL) {
		printf("tcp_eno_option_reply() no transcript, skipping\r\n");
		ec->ec_state = ENOS_ERROR | ENOS_SYNACK | ENOS_OPTMISSING;
		return;
	}

	ec->ec_peer_transcript = peer_transcript;

	printf("tcp_eno_option_reply() dump transcript = ");
	for(uint8_t i = 0; i < peer_transcript[1]; i ++)
		printf("%02x ", peer_transcript[i]);
	printf("\n");

	while((solen = subopt(peer_transcript, &soptr, solen)) > 0) {
		if(SUBOPT_IS_GOPT(*soptr)) {
			printf("tcp_eno_option_reply(): global suboption %02x\n", *soptr);
			if(!gopt_set) { /* first occurence only */
				ec->ec_peer_gopt = *soptr;
				gopt_set = 1;

				/* handle gopt right here, save some cpu cycles */
				if(ec->ec_aa_mandatory && ~ec->ec_peer_gopt & ENO_GOPT_APP_AWARE) {
					/* APP_AWARE set is required by application but was not set -> fail */
					TCP_ENO_FAIL(ec, ENOS_SYNACK | ENOS_AAMISMATCH);
					return;
				}
			}
			continue;
		}

		if(!_TEP_MAP_ISSET(*soptr))
			continue; /* unkown tep, don't even search in ec_specs */

		/* find the tep that matches our ec_specs best ... */
		/* this is O(m, n) = m * n; but m <= 8, n <= 16 so sticking to that for now. */
		/* XXX ENO locking of ec_spec? --> maybe copy it out */
		for(uint8_t prio = 0; ec->ec_specs[prio] != 0 && prio < sizeof(ec->ec_specs); prio ++) {
			if(((*soptr) & 0x7f) != ec->ec_specs[prio])
				continue;

			if(prio < best_tep_prio) {
				best_tep_prio = prio;
				best_tep = soptr;
				best_tep_len = solen;
			}
			break;
		}

	}

	if(solen < 0) {
		printf("tcp_eno_option_reply(): ENO TCP option data invalid\n");
		TCP_ENO_FAIL(ec, ENOS_SYNACK | ENOS_PARSEFAIL);
		return;
	}

	if(best_tep == NULL) {
		printf("tcp_eno_option_reply() could not elect a matching TEP\n");
		TCP_ENO_FAIL(ec, ENOS_SYNACK | ENOS_NOMATCH);
		return;
	}

	ec->ec_negspec = best_tep[0];
	printf("tcp_eno_option_reply() TEP %02x elected\n", best_tep[0]);
	struct tcp_eno_proto *prot = _TEP_MAP_PROTO(best_tep[0]);

	if(prot->ep_subopt_reply == NULL) {
		printf("_reply() no such function in _proto\n"); /* XXX ENO do not allow this tep to be selected ...  earlier ...*/
		return;
	}

	/* XXX ENO array boundary check for buf */
	uint8_t buf[_SOPTBUF_MAXLEN];
	uint8_t *ptr = buf + TCP_ENO_OPTHEADER_LEN;

	ec->ec_self_gopt = ENO_GOPT_PASSIVE_ROLE;
	/* if(ec->ec_self_gopt != 0) */
	*(ptr ++) = ec->ec_self_gopt & 0x1f;
	uint8_t outlen = 1;
	/* XXX ENO check max array bounds */

	bcopy(best_tep, ptr, best_tep_len);
	outlen += prot->ep_subopt_reply(ec, ptr, best_tep_len);
	if(ENOS_STATE(ec->ec_state) == ENOS_ERROR)
		/* central tep response failed, stop it */
		/* XXX ENO develop recovery strategy */
		return;

	if(outlen == 1) {
		printf("_reply(): no output from _proto subfn\n");
		TCP_ENO_FAIL(ec, ENOS_SYNACK | ENOS_TEPFAIL);
		return;
	}

	outlen += TCP_ENO_OPTHEADER_LEN;
	bcopy((char []) TCP_ENO_OPTHEADER(outlen), &buf, TCP_ENO_OPTHEADER_LEN);
/*
	printf("tcp_eno_option_reply() dump transcript_out = ");
	for(uint8_t i = 0; i < outlen; i ++)
		printf("%02x ", buf[i]);
	printf("\n");
*/
	uint8_t *eo = tcp_eno_option_alloc(buf); /* XXX ENO late alloc */
	ec->ec_self_transcript = eo;

	to->to_flags |= TOF_ENO;
	to->to_eno = eo; /* will be freed on tcpcb disposal only, can pass a pointer */
}

/* to is input */
void tcp_eno_option_parse_syn_ack(struct tcpcb *tp, struct tcpopt *to) {
	uint8_t	*soptr = NULL;
	int8_t	solen = 0;

	bool gopt_set = 0;
	uint8_t *best_tep = NULL;
	uint8_t	best_tep_len;

	if(ENOS_STATE(tp->t_eno->ec_state) != ENOS_NEGOTIATE) {
		printf("tcp_eno_option_parse_syn_ack() ec_state is not negotiate: state=" ENOS_FMT, ENOS_VAL(tp->t_eno->ec_state));
		return;
	}

	if(!(to->to_flags & TOF_ENO)) {
		printf("tcp_eno_option_parse_syn_ack() no ENO flag in SYN|ACK, skipping\r\n");
		tp->t_eno->ec_state = ENOS_ERROR | ENOS_SYNACK | ENOS_OPTMISSING;
		return;
	}

	printf("tcp_eno_option_parse_syn_ack() dump to->to_eno = ");
	for(uint8_t i = 0; i < to->to_eno[1]; i ++)
		printf("%02x ", to->to_eno[i]);
	printf("\n");

	tp->t_eno->ec_peer_transcript = tcp_eno_option_alloc(to->to_eno);
	if(tp->t_eno->ec_peer_transcript == NULL) {
		TCP_ENO_FAIL(tp->t_eno, ENOS_SYNACK | ENOS_NOMEM);
		return;
	}

	while((solen = subopt(to->to_eno, &soptr, solen)) > 0) {
		if(SUBOPT_IS_GOPT(*soptr)) {
			printf("tcp_eno_option_parse_syn_ack(): global suboption %02x\n", *soptr);
			if(!gopt_set) { /* first occurence only */
				tp->t_eno->ec_peer_gopt = *soptr;
				gopt_set = 1;

				/* handle gopt right here, save some cpu cycles */
				if(tp->t_eno->ec_aa_mandatory && ~tp->t_eno->ec_peer_gopt & ENO_GOPT_APP_AWARE) {
					/* APP_AWARE set is required by application but was not set -> fail */
					TCP_ENO_FAIL(tp->t_eno, ENOS_SYNACK | ENOS_AAMISMATCH);
					return;
				}
			}
			continue;
		}

		if(!_TEP_MAP_ISSET(*soptr))
			continue; /* unkown tep, don't bother with it */

		/* XXX ENO locking of ec_spec? */
		/* rightmost tep is selected by b role host ... so always take the more-right one IF in SPEC */
		for(uint8_t i = 0; tp->t_eno->ec_specs[i] != 0 && i < sizeof(tp->t_eno->ec_specs); i ++)
			if(((*soptr) & 0x7f) == tp->t_eno->ec_specs[i]) {
				best_tep = soptr;
				best_tep_len = solen;
				break;
			}
	}

	if(solen < 0) {
		printf("tcp_eno_option_parse_syn_ack(): ENO TCP option data invalid\n");
		TCP_ENO_FAIL(tp->t_eno, ENOS_SYNACK | ENOS_PARSEFAIL);
		return;
	}

	if(best_tep == NULL) {
		TCP_ENO_FAIL(tp->t_eno, ENOS_SYNACK | ENOS_NOMATCH);
		printf("tcp_eno_option_parse_syn_ack() could not find a matching TEP\n");
		return;
	}

	tp->t_eno->ec_negspec = best_tep[0];
	printf("tcp_eno_option_parse_syn_ack() TEP %02x elected\n", best_tep[0]);
	struct tcp_eno_proto *prot = _TEP_MAP_PROTO(best_tep[0]); /* XXX ENO late declaration */

	if(prot->ep_subopt_parse_syn_ack != NULL)
		prot->ep_subopt_parse_syn_ack(tp, best_tep, best_tep_len);
}



/*
 * ### XOR_TEP
 */


/* no input here, backwards filling */
uint8_t _xor_subopt_create_syn(struct tcpcb *tp, uint8_t tep, uint8_t *buf_end, uint8_t avail) {
	/* do not need to check for 1 byte. if there is no byte left, this wouldn't get called */
	*(-- buf_end) = _TEP_XOR;
	printf("_xor_subopt_create_syn() SYN buf=%lx c=%02x\n", (unsigned long) buf_end, *buf_end);
	return 1;
}

/* an proto may consume a reasonable amount of bytes, but at most _SOPTBUF_MAXLEN_REPLY  */
uint8_t _xor_subopt_reply(struct tcp_eno_control *ec, uint8_t *buf, uint8_t len) {
	/* the fact that the reply option gets called tells us this is the chosen tep. we could answer to the syn eno data. */

	if(_SOPTBUF_MAXLEN_REPLY <= 5) {
		TCP_ENO_FAIL(ec, ENOS_SYNACK | ENOS_HDRFULL);
		return 0;
	}

	ec->ec_proto = malloc(ENO_XOR_KEY_LEN, M_PROTO_DATA, M_ZERO | M_NOWAIT);
	if(ec->ec_proto == NULL) {
		TCP_ENO_FAIL(ec, ENOS_SYNACK | ENOS_NOMEM);
		return 0;
	}

	/* XXX ENO create 2 TEPS: XOR_ONES, XOR_RAND ... */
	bcopy((char []) {0x01, 0x01, 0x01, 0x01}, ec->ec_proto, ENO_XOR_KEY_LEN);
	bcopy(ec->ec_proto, buf + 1, ENO_XOR_KEY_LEN);

	printf("_xor_subopt_reply() SYN|ACK buf=%lx start\n", (unsigned long) buf);
	buf[0] = _TEP_XOR | 0x80;
	return 5;
}



/* no subopt output, so no return */
void _xor_subopt_parse_syn_ack(struct tcpcb *tp, uint8_t *buf, uint8_t len) {
	printf("_xor_subopt_parse_syn_ack()\r\n");
	if(len != 5) {
		printf("_xor_subopt_parse_syn_ack() len is not 5\r\n");
		TCP_ENO_FAIL(tp->t_eno, ENOS_SYNACK | ENOS_TEPFAIL); /* XXX ENO subcode collision? */
		return;
	}

	tp->t_eno->ec_proto = malloc(ENO_XOR_KEY_LEN, M_PROTO_DATA, M_ZERO | M_NOWAIT);
	if(tp->t_eno->ec_proto == NULL) {
		printf("_xor_subopt_parse_syn_ack() could not alloc\r\n");
		TCP_ENO_FAIL(tp->t_eno, ENOS_SYNACK | ENOS_NOMEM);
		return;
	}

	bcopy(buf + 1, tp->t_eno->ec_proto, ENO_XOR_KEY_LEN);
}



/* handler for m_apply */
int
tcp_eno_xor_apply(void *arg, void *data, u_int len) {
	printf("tcp_eno_xor_apply(): len=%d", len);

	struct eno_xor_ctx *ctx = (struct eno_xor_ctx *) arg;
	/* yes this is slow, but not of productive use anyway */
	for(u_int i = 0; i < len; i ++, ctx->kpos = (ctx->kpos + 1) % ENO_XOR_KEY_LEN)
		((u_char *) data)[i] ^= ctx->key[ctx->kpos];

	for(u_int i = 0; i < len; i ++) {
		if(i % 8 == 0)
			printf(" ");
		printf("%02x", ((u_char*) data)[i]);
	}
	printf("\n");

	return 0; /* success */
}


/*
 * ### NONCE_TEP
 */

#define _NONCE_LEN 8
#define _NONCE_ECHO_LEN 4 /* of _NONCE_LEN, how many bytes should be echoed? */

uint8_t _nonce_subopt_create_syn(struct tcpcb *tp, uint8_t tep, uint8_t *buf_end, uint8_t avail) {
	KASSERT(tp != NULL, ("%s: tp is NULL", __func__));
	KASSERT(tp->t_eno != NULL, ("%s: t_eno is NULL", __func__));

	if(avail < _NONCE_LEN + 1)
		return 0;

	buf_end -= _NONCE_LEN;
	arc4rand(buf_end, _NONCE_LEN, 0);

	tp->t_eno->ec_sessid = tcp_eno_sessid_alloc(buf_end, _NONCE_LEN); /* alloc sessid on active opener */
	tp->t_eno->ec_sessid_len = _NONCE_LEN;

	*(-- buf_end) = _TEP_NONCE | 0x80;
	printf("_nonce_subopt_create_syn() SYN\n");
	return _NONCE_LEN + 1;
}

/* an proto may consume a reasonable amount of bytes, but at most _SOPTBUF_MAXLEN_REPLY  */
uint8_t _nonce_subopt_reply(struct tcp_eno_control *ec, uint8_t *buf, uint8_t len) {
	if(_SOPTBUF_MAXLEN_REPLY <= _NONCE_LEN + 1) {
		TCP_ENO_FAIL(ec, ENOS_SYNACK | ENOS_HDRFULL);
		return 0;
	}

	if(len != 9) {
		printf("_nonce_subopt_reply() the read nonce was not 9 bytes long\n");
		TCP_ENO_FAIL(ec, ENOS_SYNACK | ENOS_TEPFAIL); /* XXX ENO duplicate use?? */
		return 0;
	}

	/* in buf, there is received NONCE already ... */
	buf[0] = _TEP_NONCE | 0x80; /* should be in there already */
	/* no just keep a simple nonce, no fancy stuff
	arc4rand(buf + 1 + _NONCE_ECHO_LEN, _NONCE_LEN - _NONCE_ECHO_LEN, 0); */
	printf("_nonce_subopt_reply() SYN|ACK\n");

	ec->ec_sessid = tcp_eno_sessid_alloc(buf + 1, _NONCE_LEN); /* alloc sessid on passive opener */
	ec->ec_sessid_len = _NONCE_LEN;
	return _NONCE_LEN + 1;
}






/*
 * ### SQRT_TEP
 * for compatibility with https://github.com/squarooticus/tcpinc-linux
 */

uint8_t _sqrt_subopt_create_syn(struct tcpcb *tp, uint8_t tep, uint8_t *buf_end, uint8_t avail) {
	printf("_sqrt_subopt_create_syn() SYN\n");
	*(-- buf_end) = tep; /* create the suboption for whatever TEP was requested. */
	return 1;
}

/* an proto may consume a reasonable amount of bytes, but at most _SOPTBUF_MAXLEN_REPLY  */
uint8_t _sqrt_subopt_reply(struct tcp_eno_control *ec, uint8_t *buf, uint8_t len) {
	printf("_sqrt_subopt_reply() reply SYN|ACK\n");
	if(len != 1) {
		printf("_sqrt_subopt_reply() the SYN suboption was not 1 bytes long\n");
		TCP_ENO_FAIL(ec, ENOS_SYNACK | ENOS_TEPFAIL); /* XXX ENO duplicate use?? */
		return 0;
	}
	
	printf("_sqrt_subopt_reply() got option %02x\n", buf[0]);

	buf[0] &= 0x7f; /* probably unnecessary */
	return 1;
}

