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

#ifndef _NETINET_TCP_ENO_H_
#define _NETINET_TCP_ENO_H_


#define TCP_ENO_EXPERIMENTAL_OPTION /* define if RFC6994 experimental option space should be used instead of TCP option no. 69 (IANA pending) */

#ifdef TCP_ENO_EXPERIMENTAL_OPTION
#define TCP_ENO_OPTHEADER_LEN 4
#define TCP_ENO_OPTHEADER(optlen)		{TCPOPT_EXPERIMENTAL, optlen, TCPOPT_EXPERIMENTAL_ENO_1, TCPOPT_EXPERIMENTAL_ENO_2}
#else
#define TCP_ENO_OPTHEADER_LEN 2
#define TCP_ENO_OPTHEADER(optlen)		{TCPOPT_ENO, optlen}
#endif


#define TCP_ENO_SPEC_SIZE	16


/*
 * ## sysctl
 */

/* XXX ENO make them static (local only), remove them from header if possible */

VNET_DECLARE(uint8_t, tcp_eno_specs[TCP_ENO_SPEC_SIZE]);
#define	V_tcp_eno_specs			VNET(tcp_eno_specs)

VNET_DECLARE(bool, tcp_eno_enable_connect);
#define	V_tcp_eno_enable_connect	VNET(tcp_eno_enable_connect)

VNET_DECLARE(bool, tcp_eno_enable_listen);
#define	V_tcp_eno_enable_listen VNET(tcp_eno_enable_listen)



#define _PORTS_SIZE (IPPORT_MAX + 1) /* it is 0 .. MAX, so MAX + 1 elements */

BITSET_DEFINE(_enoports, _PORTS_SIZE);
typedef struct _enoports tcp_eno_ports_t;


/* XXX ENO name clash? */
#define ENO_PORT_ZERO(set)		BIT_ZERO(_PORTS_SIZE, set)
#define ENO_PORT_SET(set, bit)		BIT_SET(_PORTS_SIZE, bit, set)
#define ENO_PORT_CLR(set, bit)		BIT_ZERO(_PORTS_SIZE, bit, set)
#define ENO_PORT_ISSET(set, bit)	BIT_ISSET(_PORTS_SIZE, bit, set)
#define ENO_PORT_INIT()			BITSET_T_INITIALIZER(0) /* cannot init e. g. 1 << 433, it's to large */

VNET_DECLARE(tcp_eno_ports_t, tcp_eno_bad_connect_ports);
#define	V_tcp_eno_bad_connect_ports	VNET(tcp_eno_bad_connect_ports)
VNET_DECLARE(tcp_eno_ports_t, tcp_eno_bad_listen_ports);
#define	V_tcp_eno_bad_listen_ports	VNET(tcp_eno_bad_listen_ports)



#define ENO_ENABLED_SYSCTL	-1



/* ss pp uuuu = uint8
 * ss = state
 * 00 = off
 * 01 = negotiate
 * 10 = success
 * 11 = error
 *    pp = position, when did this happen?
 *    10 = syn
 *    01 = ack
 *    11 = syn|ack
 *       uuuu = sUbstate 0..15
 *
 * state is used internally
 * pos and code is for informational purposes
 *
 * this could easy be put into a 32 bit int
 */
#define ENOS_OFF		0x00
#define ENOS_NEGOTIATE		0x40
#define ENOS_SUCCESS		0x80
#define ENOS_ERROR		0xc0
#define ENOS_STATE(s)		(s & 0xc0)

#define ENOS_CONTINUE(s)	(ENOS_STATE(s) & ENOS_NEGOTIATE)
					/* can negotiation continue? */

/* XXX ENO this does not work out ... need to address the place in code not the packet working on (it's sending and receiving) */
#define ENOS_SYN		0x20
#define ENOS_ACK		0x10
#define ENOS_SYNACK		0x30
#define ENOS_POS(s)		(s & 0x30)

#define ENOS_EMPTYCONF		1	/* SPECS not filled */
#define ENOS_OPTMISSING		2	/* no ENO received */
#define ENOS_PARSEFAIL		3	/* could not parse received ENO */
#define ENOS_NOMATCH		4	/* received eno contained no acceptable TEP */
#define ENOS_SENT		5	/* sent ENO */
#define ENOS_RECVD		6	/* received ENO */
#define ENOS_NOMEM		7	/* failed mem alloc */
#define ENOS_AAMISMATCH		8	/*  */
#define ENOS_ROLEMISMATCH	9	/*  */
#define ENOS_TEPFAIL		10	/* TEP handler failed by not creating an answer */
#define ENOS_HDRFULL		11	/* TCP option space is full */
#define ENOS_DISABLED		12	/*  */
#define ENOS_BADPORT		13	/*  */
#define ENOS_SUBSTATE(s)	(s & 0x0f)

/* nothing to see here. inefficient and simple. usage:
 * printf("hello %s! state=" ENOS_FMT "\n", name, ENOS_VAL(ec_state)); */
#define ENOS_FMT	"%s%s%s%s|%s%s%s|%s%s%s%s%s%s%s%s%s%s%s%s%s"
#define ENOS_VAL(s)	\
	ENOS_STATE(s) == ENOS_OFF ? "OFF" : "", \
	ENOS_STATE(s) == ENOS_NEGOTIATE ? "NEGOTIATE" : "", \
	ENOS_STATE(s) == ENOS_SUCCESS ? "SUCCESS" : "", \
	ENOS_STATE(s) == ENOS_ERROR ? "ERROR" : "", \
	ENOS_POS(s) == ENOS_SYN ? "SYN" : "", \
	ENOS_POS(s) == ENOS_ACK ? "ACK" : "", \
	ENOS_POS(s) == ENOS_SYNACK ? "SYNACK" : "", \
	ENOS_SUBSTATE(s) == ENOS_EMPTYCONF ? "EMPTYCONF" : "", \
	ENOS_SUBSTATE(s) == ENOS_OPTMISSING ? "OPTMISSING" : "", \
	ENOS_SUBSTATE(s) == ENOS_PARSEFAIL ? "PARSEFAIL" : "", \
	ENOS_SUBSTATE(s) == ENOS_NOMATCH ? "NOMATCH" : "", \
	ENOS_SUBSTATE(s) == ENOS_SENT ? "SENT" : "", \
	ENOS_SUBSTATE(s) == ENOS_RECVD ? "RECVD" : "", \
	ENOS_SUBSTATE(s) == ENOS_NOMEM ? "NOMEM" : "", \
	ENOS_SUBSTATE(s) == ENOS_AAMISMATCH ? "AAMISMATCH" : "", \
	ENOS_SUBSTATE(s) == ENOS_ROLEMISMATCH ? "ROLEMISMATCH" : "", \
	ENOS_SUBSTATE(s) == ENOS_TEPFAIL ? "TEPFAIL" : "", \
	ENOS_SUBSTATE(s) == ENOS_HDRFULL ? "HDRFULL" : "", \
	ENOS_SUBSTATE(s) == ENOS_BADPORT ? "BADPORT" : "", \
	ENOS_SUBSTATE(s) == ENOS_DISABLED ? "DISABLED" : ""


/* XXX ENO VNET for ...
 * tcp_eno_bad_connect_ports,
 * tcp_eno_bad_listen_ports */


/*
 * ### struct
 */


#define ENO_GET_TEP_ID(so)		(so & 0x7f)


#define ENO_PROTO_NONE			0


#define _TEP_EXPERIMENTAL_USE		0x20
#define _TEP_TCPCRYPT_ECDHE_P256	0x21
#define _TEP_TCPCRYPT_ECDHE_P521	0x22
#define _TEP_TCPCRYPT_ECDHE_CURVE25519	0x23
#define _TEP_TCPCRYPT_ECDHE_CURVE448	0x24
#define _TEP_USE_TLS			0x30
#define _TEP_XOR			0x40 /* not even in ENO draft */
#define _TEP_NONCE			0x41 /* not even in ENO draft */

#define _TEP_SQRT_A			0x21 /* for testing against squarooticus/tcpinc-linux */
#define _TEP_SQRT_B			0x23 
					     /* XXX ENO NOTE this is a duplicate of TCPCRYPT */


/* this type is at least 2 bytes long, containing len in 2nd byte */
#define TCP_ENO_OPT_LEN(opt)	(opt == NULL ? 0 : opt[1])


/* XXX ENO check if negspec needs to be reset. other addtl. values to be reset? */
/* XXX ENO can we try another spec at this time??? */
#define TCP_ENO_FAIL(ec, reason)				\
	do {						\
		ec->ec_negspec = ENO_PROTO_NONE;	\
		ec->ec_state = ENOS_ERROR | reason;	\
	} while(0)


/* processes suboptions returns how much bytes were added */
/* XXX ENO refactor names */
typedef uint8_t	subopt_create_syn_t(struct tcpcb *tp, uint8_t tep, uint8_t *buf_end, uint8_t avail);
typedef uint8_t	subopt_reply_t(struct tcp_eno_control *ec, uint8_t *buf, uint8_t len);
typedef void	subopt_parse_syn_ack_t(struct tcpcb *tp, uint8_t *buf, uint8_t len);

struct tcp_eno_proto {
	bool			ep_spacer;
	subopt_create_syn_t	*ep_subopt_create_syn;
	subopt_reply_t		*ep_subopt_reply;
	subopt_parse_syn_ack_t	*ep_subopt_parse_syn_ack;

	/* Need some more hooks
	 * ep_init() -- not required, ec is already allocated, _reply() and _parse_syn_ack() can initialize.
	 * ep_input()
	 * ep_output()
	 * ep_close()
	 * ep_sockopt() -- not required, any proto could hook itself up into tfb_tcp_ctloutput to register its values.
	 */
};


/* locked together with TCB */
struct tcp_eno_control {
	uint8_t	ec_state;		/* see ENOS_* */

					/* XXX ENO late optimization: see what opts can be put into combined flag var */
	int8_t	ec_enabled; 		/* XXX ENO could be put back in tcpcb to save space if turned off? configured by get/setsockopt */
	uint8_t	*ec_sessid;		/* The session ID MUST be at least 33 bytes (including the one-byte suboption), though TEPs MAY choose longer session IDs. Maybe this field can go away and TEPs specify an in/out function --> set/getsock wrapper */
	uint8_t	ec_sessid_len;
	bool	ec_aa_mandatory; 	/* XXX ENO candidate for flag */
	bool	ec_tep_mandatory; 	/* XXX ENO candidate for flag */
	uint8_t	ec_specs[TCP_ENO_SPEC_SIZE];	/* 0 is invalid spec, errr TEP, so 0 is the EOL */
					/* XXX ENO there might be just a good place in tcp_output to replace this ... */
	uint8_t	ec_self_gopt;
	uint8_t	ec_peer_gopt;
					/* doc specifies to keep first two SYN elements only. */
					/* if not NULL, a transcript is always at least 2 bytes long and index 1 carries length, see tcp option format */
	uint8_t *ec_self_transcript;
	uint8_t *ec_peer_transcript;
	uint8_t	ec_negspec; 		/* XXX ENO should be _negproto but get/setsockopt doc defines this as negspec */
	void 	*ec_proto; 		/* to be used by TEP, it can put own data structure in here */
};



/*
 * ## option handling
 */


/* most FreeBSD header files skip the parameter names ... */
void 	tcp_eno_init(void);
int8_t	tcp_eno_proto_register(struct tcp_eno_proto prot);
void	tcp_eno_proto_unregister(uint8_t proto_no);

struct tcp_eno_control *tcp_eno_control_alloc(void);
void	tcp_eno_control_free(struct tcp_eno_control *ec);
uint8_t *tcp_eno_sessid_alloc(uint8_t *data, uint8_t len);
uint8_t *tcp_eno_option_alloc(uint8_t *data);

void	tcp_eno_option_create_syn(struct tcpcb *tp, struct tcpopt *to);
void	tcp_eno_option_reply(uint8_t *peer_transcript, struct tcp_eno_control *ec, struct tcpopt *to);
void	tcp_eno_option_parse_syn_ack(struct tcpcb *tp, struct tcpopt *to);

/*
 * ## TEPs
 */

#define ENO_GOPT_PASSIVE_ROLE	0x01
#define ENO_GOPT_APP_AWARE	0x02


/*
 * ### XOR_TEP
 */

#define ENO_XOR_KEY_LEN 4
struct eno_xor_ctx {
    u_char key[ENO_XOR_KEY_LEN]; /* could be a pointer aswell */
    u_int8_t kpos;
};

int tcp_eno_xor_apply(void *, void *, u_int);



#endif /* _NETINET_TCP_ENO_H_ */
