/* source: xio-socks5.c */
/* Copyright Gerhard Rieger and contributors (see file CHANGES) */
/* Published under the GNU General Public License V.2, see file COPYING */

/* this file contains the source for opening addresses of socks5 type */

/*
* At the moment UDP ASSOCIATE is not supported, but CONNECT and BIND are.
* At the moment no authentication methods are supported (i.e only NO AUTH),
* which is technically not compliant with RFC1928.
*/

#include "xiosysincludes.h"

#if WITH_SOCKS5

#include "xioopen.h"
#include "xio-ascii.h"
#include "xio-socket.h"
#include "xio-ip.h"
#include "xio-ipapp.h"

#include "xio-socks5.h"

#include <strings.h>

#define SOCKS5_MODE_CONNECT	"socks5"
#define SOCKS5_MODE_BIND	"socks5-bind"

#define SOCKS5_MAX_REPLY_SIZE	6 + 256

const uint8_t SOCKS5_AUTH_NONE		= 0;
const uint8_t SOCKS5_AUTH_FAIL		= 0xff;

const uint8_t SOCKS5_COMMAND_CONNECT		= 1;
const uint8_t SOCKS5_COMMAND_BIND		= 2;
const uint8_t SOCKS5_COMMAND_UDP_ASSOCIATE	= 3;

const uint8_t SOCKS5_ATYPE_IPv4		= 1;
const uint8_t SOCKS5_ATYPE_DOMAINNAME	= 3;
const uint8_t SOCKS5_ATYPE_IPv6		= 4;

const uint8_t SOCKS5_VERSION = 5;

const uint8_t SOCKS5_STATUS_SUCCESS			= 0;
const uint8_t SOCKS5_STATUS_GENERAL_FAILURE		= 1;
const uint8_t SOCKS5_STATUS_CONNECTION_NOT_ALLOWED	= 2;
const uint8_t SOCKS5_STATUS_NETWORK_UNREACHABLE		= 3;
const uint8_t SOCKS5_STATUS_HOST_UNREACHABLE		= 4;
const uint8_t SOCKS5_STATUS_CONNECTION_REFUSED		= 5;
const uint8_t SOCKS5_STATUS_TTL_EXPIRED			= 6;
const uint8_t SOCKS5_STATUS_COMMAND_NOT_SUPPORTED	= 7;
const uint8_t SOCKS5_STATUS_ADDRESS_TYPE_NOT_SUPPORTED	= 8;

static int xioopen_socks5(int argc, const char *argv[], struct opt *opts,
					int xioflags, xiofile_t *xxfd,
					unsigned groups, int dummy1, int dummy2,
					int dummy3);

const struct addrdesc addr_socks5_connect = { SOCKS5_MODE_CONNECT, 3, xioopen_socks5, GROUP_FD|GROUP_SOCKET|GROUP_SOCK_IP4|GROUP_SOCK_IP6|GROUP_IP_TCP|GROUP_CHILD|GROUP_RETRY, 0, 0, 0 HELP(":<socks-server>:<socks-port>:<target-host>:<target-port>") };

const struct addrdesc addr_socks5_bind = { SOCKS5_MODE_BIND, 3, xioopen_socks5, GROUP_FD|GROUP_SOCKET|GROUP_SOCK_IP4|GROUP_SOCK_IP6|GROUP_IP_TCP|GROUP_CHILD|GROUP_RETRY|GROUP_LISTEN, 0, 0, 0 HELP(":<socks-server>:<socks-port>:<listen-host>:<listen-port>") };

static char * _xioopen_socks5_strerror(uint8_t r) {
	switch(r) {
		case SOCKS5_STATUS_SUCCESS:
			return "succeeded";
		case SOCKS5_STATUS_GENERAL_FAILURE:
			return "general SOCKS server failure";
		case SOCKS5_STATUS_CONNECTION_NOT_ALLOWED:
			return "connection not allowed by ruleset";
		case SOCKS5_STATUS_NETWORK_UNREACHABLE:
			return "network unreachable";
		case SOCKS5_STATUS_HOST_UNREACHABLE:
			return "host unreachable";
		case SOCKS5_STATUS_CONNECTION_REFUSED:
			return "connection refused";
		case SOCKS5_STATUS_TTL_EXPIRED:
			return "TTL expired";
		case SOCKS5_STATUS_COMMAND_NOT_SUPPORTED:
			return "command not supported";
		case SOCKS5_STATUS_ADDRESS_TYPE_NOT_SUPPORTED:
			return "address type not supported";
		default:
			return "unknown error";
	}
}

/*
* performs the SOCKS5 handshake, i.e sends client hello and receives server hello back.
* if successful the connection is now ready for sending a SOCKS5 request.
*
* the code is unnecessarily complex right now, for what is essentially send(0x050100)
* followed by "return read() == 0x0500", but will be easier to extend for other
* auth mode support.
*/
static int _xioopen_socks5_handshake(struct single *xfd, int level) {
	int result;
	ssize_t bytes;
	struct socks5_server_hello server_hello;

	int nmethods = 1;	/* support only 1 auth method - no auth */
	int client_hello_size = sizeof(struct socks5_client_hello) + (sizeof(uint8_t) * nmethods);

	struct socks5_client_hello *client_hello = Malloc(client_hello_size);
	if (client_hello == NULL) {
		Msg2(level, "malloc(%d): %s",
			client_hello_size, strerror(errno));
		if (Close(xfd->fd) < 0) {
			Info2("close(%d): %s", xfd->fd, strerror(errno));
		}

		/* malloc failed - could succeed later, so retry then */
		return STAT_RETRYLATER;
	}

	unsigned char *server_hello_ptr = (unsigned char *)&server_hello;

	/* SOCKS5 Hello with 1 authentication mechanism - 0x00 NO AUTHENTICATION */
	client_hello->version	= SOCKS5_VERSION;
	client_hello->nmethods	= 1;
	client_hello->methods[0]= SOCKS5_AUTH_NONE;

	/* send SOCKS5 Client Hello */
#if WITH_MSGLEVEL <= E_INFO
	Info2("sending socks5 client hello version=%d nmethods=%d",
		client_hello->version,
		client_hello->nmethods);
#endif
#if WITH_MSGLEVEL <= E_DEBUG
	{
		char *msgbuf;
		if ((msgbuf = Malloc(3 * client_hello_size)) != NULL) {
			xiohexdump((unsigned char *)client_hello, client_hello_size, msgbuf);
			Debug1("sending socks5 client hello %s", msgbuf);
			free(msgbuf);
		}
	}
#endif

	if (writefull(xfd->fd, client_hello, client_hello_size) < 0) {
		Msg4(level, "write(%d, %p, "F_Zu"): %s",
			xfd->fd, client_hello, client_hello_size, strerror(errno));
		if (Close(xfd->fd) < 0) {
			Info2("close(%d): %s", xfd->fd, strerror(errno));
		}
		free(client_hello);

		/* writefull() failed, but might succeed later, so RETRYLATER */
		return STAT_RETRYLATER;
	}
	free(client_hello);

	bytes = 0;
	Info("waiting for socks5 reply");
	while (bytes >= 0) {
		do {
			result = Read(xfd->fd, server_hello_ptr + bytes, sizeof(struct socks5_server_hello)-bytes);
		} while (result < 0 && errno == EINTR);
		if (result < 0) {
			Msg4(level, "read(%d, %p, "F_Zu"): %s",
				xfd->fd, server_hello_ptr + bytes,
				sizeof(struct socks5_server_hello)-bytes, strerror(errno));
			if (Close(xfd->fd) < 0) {
				Info2("close(%d): %s", xfd->fd, strerror(errno));
			}
		}
		if (result == 0) {
			Msg(level, "read(): EOF during read of SOCKS5 server hello, peer might not be a SOCKS5 server");
			if(Close(xfd->fd) < 0) {
				Info2("close(%d): %s", xfd->fd, strerror(errno));
			}

			return STAT_RETRYLATER;
		}

		bytes += result;
		if (bytes == sizeof(struct socks5_server_hello)) {
			Debug1("received all "F_Zd" bytes", bytes);
			break;
		}
		Debug2("received %d bytes, waiting for "F_Zu" more bytes",
			result, sizeof(struct socks5_server_hello)-bytes);
	}
	if (result <= 0) {
		return STAT_RETRYLATER;
	}

	Info2("received SOCKS5 server hello version=%d method=%d",
		server_hello.version,
		server_hello.method);

	if (server_hello.version != SOCKS5_VERSION) {
		Msg2(level, "SOCKS5 Server Hello version was %d, not the expected %d, peer might not be a SOCKS5 server",
			server_hello.version,
			SOCKS5_VERSION);
		if (Close(xfd->fd) < 0) {
			Info2("close(%d): %s", xfd->fd, strerror(errno));
		}
		return STAT_RETRYLATER;
	}

	if (server_hello.method == SOCKS5_AUTH_FAIL) {
		Msg(level, "SOCKS5 authentication negotiation failed - client & server have no common supported methods");
		if (Close(xfd->fd) < 0) {
			Info2("close(%d): %s", xfd->fd, strerror(errno));
		}
		return STAT_RETRYLATER;
	}

	if (server_hello.method != SOCKS5_AUTH_NONE) {
		Msg1(level, "SOCKS5 server requested unsupported auth method (%d)", server_hello.method);
		if (Close(xfd->fd) < 0) {
			Info2("close(%d): %s", xfd->fd, strerror(errno));
		}
		return STAT_RETRYLATER;
	}

	/* Server accepted using no auth */
	return STAT_OK;
}

/*
* generates the SOCKS5 request for a given command, host and port
*/
static struct socks5_request *_xioopen_socks5_prepare_request(int *bytes, const char *target_name, const char *target_port, uint8_t socks_command, int level) {

	struct socks5_request *req;

	char ipaddr[16];

	uint16_t *dstport;
	*bytes = 0;

	if (inet_pton(AF_INET, target_name, ipaddr)){ // if(valid_ipv4)
		*bytes = sizeof(struct socks5_request) + 4 + sizeof(uint16_t);
		req = (struct socks5_request *)Malloc(*bytes);
		if (req == NULL){
			Info2("Malloc(%d): %s", *bytes, strerror(errno));
			return NULL;
		}

		req->address_type = SOCKS5_ATYPE_IPv4;
		memcpy(req->dstdata, ipaddr, 4);

		dstport = (uint16_t *) &req->dstdata[4];
		*dstport = parseport(target_port, IPPROTO_TCP);
	} else if (inet_pton(AF_INET6, target_name, ipaddr)) { // else if(valid_ipv6)
		*bytes = sizeof(struct socks5_request) + 16 + sizeof(uint16_t);
		req = (struct socks5_request *)Malloc(*bytes);
		if (req == NULL){
			Info2("Malloc(%d): %s", *bytes, strerror(errno));
			return NULL;
		}

		req->address_type = SOCKS5_ATYPE_IPv6;
		memcpy(req->dstdata, ipaddr, 16);

		dstport = (uint16_t *) &req->dstdata[16];
		*dstport = parseport(target_port, IPPROTO_TCP);
	} else { // invalid IP, assume hostname
		int hlen = strlen(target_name);
		if (hlen > 255) {
			Msg(level, "Target hostname too long (>255 bytes), aborting");
			return NULL;
		}

		*bytes = sizeof(struct socks5_request) + 1 + hlen + sizeof(uint16_t);
		req = (struct socks5_request *)Malloc(*bytes);
		if (req == NULL ){
			Info2("Malloc(%d): %s", *bytes, strerror(errno));
			return NULL;
		}

		req->address_type = SOCKS5_ATYPE_DOMAINNAME;
		req->dstdata[0] = (unsigned char) hlen;
		memcpy(&req->dstdata[1], target_name, hlen);

		dstport = (uint16_t *) &req->dstdata[hlen + 1];
		*dstport = parseport(target_port, IPPROTO_TCP);
	}


	if (*dstport == 0){
		free(req);
		return NULL;
	}

	req->version = SOCKS5_VERSION;
	req->command = socks_command;
	req->reserved = 0;

	return req;
}

/*
* reads a server reply after a request has been sent
*/
static int _xioopen_socks5_read_reply(struct single *xfd, struct socks5_reply *reply, int level){
	int result = 0;
	int bytes_read = 0;

	int bytes_to_read = 5;
	bool typechecked = false;

	while (bytes_to_read >= 0) {
		Info("reading SOCKS5 reply");
		do {
			result = Read(xfd->fd, ((unsigned char *)reply) + bytes_read, bytes_to_read-bytes_read);
		} while (result < 0 && errno == EINTR);
		if (result < 0) {
			Msg4(level, "read(%d, %p, "F_Zu"): %s",
				xfd->fd, ((unsigned char *)reply) + bytes_read, bytes_to_read-bytes_read, strerror(errno));
			if (Close(xfd->fd) < 0) {
				Info2("close(%d): %s", xfd->fd, strerror(errno));
			}
			return STAT_RETRYLATER;

		}
		if (result == 0) {
			Msg(level, "read(): EOF during read of SOCKS5 reply");
			if (Close(xfd->fd) < 0) {
				Info2("close(%d): %s", xfd->fd, strerror(errno));
			}
			return STAT_RETRYLATER;
		}
		bytes_read += result;

		/* once we've read 5 bytes, figure out total message length and
		*  update bytes_to_read accordingly. */
		if (!typechecked && bytes_read <= 5) {
			switch(reply->address_type) {
				case SOCKS5_ATYPE_IPv4:
					// 6 fixed bytes, and 4 bytes for v4 address
					bytes_to_read = 10;
					break;
				case SOCKS5_ATYPE_IPv6:
					// 6 fixed bytes, and 16 bytes for v6 address
					bytes_to_read = 22;
					break;
				case SOCKS5_ATYPE_DOMAINNAME:
					// 6 fixed bytes, 1 byte for strlen, and 0-255 bytes for domain name
					bytes_to_read = 7 + reply->dstdata[0];
					break;
				default:
					Msg1(level, "invalid SOCKS5 reply address type (%d)", reply->address_type);
					if (Close(xfd->fd) < 0) {
						Info2("close(%d): %s", xfd->fd, strerror(errno));
					}
					return STAT_RETRYLATER;
			}
			typechecked = true;
			continue;
		}

		if (bytes_to_read == bytes_read) {
			Debug1("received all "F_Zd" bytes", bytes_read);
			break;
		}

		Debug2("received %d of %d bytes, waiting", bytes_read, bytes_to_read);
	}

	if (result <= 0) {
		return STAT_RETRYLATER;
	}

	return STAT_OK;
}


/*
* sends a request and receives the reply.
* if command is BIND we receive two replies.
*/
static int _xioopen_socks5_request(struct single *xfd, const char *target_name, const char *target_port, uint8_t socks_command, int level) {
	struct socks5_request *req;

	int bytes, result = 0;

	req = _xioopen_socks5_prepare_request(&bytes, target_name, target_port, socks_command, level);
	if (req == NULL) {
		if (Close(xfd->fd) < 0) {
			Info2("close(%d): %s", xfd->fd, strerror(errno));
		}

		/* prepare_request could fail due to malloc, but most likely
		the destination is invalid, e.g too long hostname, so NORETRY */
		return STAT_NORETRY;
	}

	Info4("sending socks5 request version=%d command=%d reserved=%d address_type=%d",
		req->version,
		req->command,
		req->reserved,
		req->address_type);

#if WITH_MSGLEVEL <= E_DEBUG
	{
		char *msgbuf;
		if ((msgbuf = Malloc(3 * bytes)) != NULL) {
			xiohexdump((const unsigned char *)req, bytes, msgbuf);
			Debug1("sending socks5 request %s", msgbuf);
			free(msgbuf);
		}
	}
#endif

	if (writefull(xfd->fd, req, bytes) < 0) {
		Msg4(level, "write(%d, %p, "F_Zu"): %s",
			xfd->fd, req, bytes, strerror(errno));
		if (Close(xfd->fd) < 0) {
			Info2("close(%d): %s", xfd->fd, strerror(errno));
		}
		free(req);
		return STAT_RETRYLATER;
	}
	free(req);
	req = NULL;

	struct socks5_reply *reply = Malloc(SOCKS5_MAX_REPLY_SIZE);
	if (reply == NULL) {
		if (Close(xfd->fd) < 0) {
			Info2("close(%d): %s", xfd->fd, strerror(errno));
		}

		return STAT_RETRYLATER;
	}

	result = _xioopen_socks5_read_reply(xfd, reply, level);
	if (result != STAT_OK) {
		free(reply);
		return result;
	}

	// TODO: maybe output nicer debug, like including address
	Info3("received SOCKS5 reply version=%d reply=%d address_type=%d",
		reply->version,
		reply->reply,
		reply->address_type);

	if (reply->version != SOCKS5_VERSION) {
		Msg2(level, "SOCKS5 reply version was %d, not the expected %d, peer might not be a SOCKS5 server",
			reply->version,
			SOCKS5_VERSION);
		if (Close(xfd->fd) < 0) {
			Info2("close(%d): %s", xfd->fd, strerror(errno));
		}
		free(reply);
		return STAT_RETRYLATER;
	}

	if (reply->reply == SOCKS5_STATUS_SUCCESS && socks_command == SOCKS5_COMMAND_BIND) {
		Notice("listening on remote host, waiting for connection"); // TODO: nicer debug output
		/* for BIND, we read two replies */
		result = _xioopen_socks5_read_reply(xfd, reply, level);
		if (result != STAT_OK) {
			free(reply);
			return result;
		}
		Notice("received connection on remote host"); // TODO: nicer debug output
		// TODO: maybe output nicer debug, like including address
		Info3("received second SOCKS5 reply version=%d reply=%d address_type=%d",
			reply->version,
			reply->reply,
			reply->address_type);
	}

	switch (reply->reply) {
		case SOCKS5_STATUS_SUCCESS:
			break;
		case SOCKS5_STATUS_GENERAL_FAILURE:
		case SOCKS5_STATUS_CONNECTION_NOT_ALLOWED:
		case SOCKS5_STATUS_NETWORK_UNREACHABLE:
		case SOCKS5_STATUS_HOST_UNREACHABLE:
		case SOCKS5_STATUS_CONNECTION_REFUSED:
		case SOCKS5_STATUS_TTL_EXPIRED:
		case SOCKS5_STATUS_COMMAND_NOT_SUPPORTED:
		case SOCKS5_STATUS_ADDRESS_TYPE_NOT_SUPPORTED:
		default:
			Msg2(level, "SOCKS5 server error %d: %s",
				reply->reply,
				_xioopen_socks5_strerror(reply->reply));
			if (Close(xfd->fd) < 0) {
				Info2("close(%d): %s", xfd->fd, strerror(errno));
			}
			free(reply);
			return STAT_RETRYLATER;
	}

	free(reply);
	return STAT_OK;
}

/* same function for all socks5-modes, determined by argv[0] */
static int xioopen_socks5(int argc, const char *argv[], struct opt *opts,
					int xioflags, xiofile_t *xxfd,
					unsigned groups, int dummy1, int dummy2,
					int dummy3){

	bool dofork = false;
	int socktype = SOCK_STREAM;
	int pf = PF_UNSPEC;
	int ipproto = IPPROTO_TCP;
	int level, result;

	struct opt *opts0 = NULL;

	struct single *xfd = &xxfd->stream;
	const char *socks_server, *target_name, *target_port, *socks_port;

	union sockaddr_union us_sa, *us = &us_sa;
	union sockaddr_union them_sa, *them = &them_sa;
	socklen_t themlen = sizeof(them_sa);
	socklen_t uslen = sizeof(us_sa);

	bool needbind = false;
	bool lowport = false;
	uint8_t socks_command;

	if (argc != 5) {
		Error1("%s: 4 parameters required", argv[0]);
		return STAT_NORETRY;
	}

	if (!strcasecmp(argv[0], SOCKS5_MODE_CONNECT)) {
		socks_command = SOCKS5_COMMAND_CONNECT;
	} else if (!strcasecmp(argv[0], SOCKS5_MODE_BIND)) {
		socks_command = SOCKS5_COMMAND_BIND;
	} else {
		Error1("Unrecognized argv[0]: %s", argv[0]);
		return STAT_NORETRY;
	}

	socks_server = argv[1];
	socks_port = argv[2];
	target_name = argv[3];
	target_port = argv[4];

	xfd->howtoend = END_SHUTDOWN;
	if (applyopts_single(xfd, opts, PH_INIT) < 0)	return -1;
	applyopts(-1, opts, PH_INIT);

	retropt_int(opts, OPT_SO_TYPE, &socktype);
	retropt_bool(opts, OPT_FORK, &dofork);


	result = _xioopen_ipapp_prepare(opts, &opts0, socks_server, socks_port, &pf, ipproto,
					xfd->para.socket.ip.res_opts[1],
					xfd->para.socket.ip.res_opts[0],
					them, &themlen,
					us, &uslen,
					&needbind, &lowport, socktype);

	Notice2("connecting to socks5 server %s:%s",
		socks_server, socks_port);
	
	do {
#if WITH_RETRY
		if (xfd->forever || xfd->retry) {
			level = E_INFO;
		} else {
			level = E_ERROR;
		}
#endif
		result = _xioopen_connect(xfd, needbind?us:NULL, sizeof(*us),
					 (struct sockaddr *)them, themlen,
					 opts, pf, socktype, IPPROTO_TCP, lowport, level);
		switch(result){
			case STAT_OK:
				break;
#if WITH_RETRY
			case STAT_RETRYLATER:
			case STAT_RETRYNOW:
				if (xfd->forever || xfd->retry-- ) {
					if (result == STAT_RETRYLATER)	Nanosleep(&xfd->intervall, NULL);
					continue;
				}
			default:
				return result;
#endif
		}

		applyopts(xfd->fd, opts, PH_ALL);
		if ((result = _xio_openlate(xfd, opts)) < 0)
			return result;

		if ((result = _xioopen_socks5_handshake(xfd, level)) != STAT_OK) {
			return result;
		}

		result = _xioopen_socks5_request(xfd, target_name, target_port, socks_command, level);
		switch (result) {
			case STAT_OK:
				break;
#if WITH_RETRY
			case STAT_RETRYLATER:
			case STAT_RETRYNOW:
				if ( xfd->forever || xfd->retry-- ) {
					if (result == STAT_RETRYLATER)	Nanosleep(&xfd->intervall, NULL);
					continue;
				}
#endif
			default:
				return result;
		}

		if (dofork) {
			xiosetchilddied();
		}

#if WITH_RETRY
		if (dofork) {
			pid_t pid;
			int level = E_ERROR;
			if (xfd->forever || xfd->retry) {
				level = E_WARN;
			}
			while ((pid = xio_fork(false, level)) < 0) {
				if (xfd->forever || --xfd->retry) {
					Nanosleep(&xfd->intervall, NULL);
					continue;
				}
				return STAT_RETRYLATER;
			}
			if ( pid == 0 ) {
				xfd->forever = false;
				xfd->retry = 0;
				break;
			}

			Close(xfd->fd);
			Nanosleep(&xfd->intervall, NULL);
			dropopts(opts, PH_ALL);
			opts = copyopts(opts0, GROUP_ALL);
			continue;
		} else
#endif
		{
			break;
		}
	} while (true);
	return 0;
}

#endif

