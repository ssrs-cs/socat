#ifndef __xio_socks5_h_included
#define __xio_socks5_h_included 1

#if WITH_SOCKS5

struct socks5_client_hello {
	uint8_t version;
	uint8_t nmethods;
	uint8_t methods[];
};

struct socks5_server_hello {
	uint8_t version;
	uint8_t method;
};

struct socks5_request {
	uint8_t version;
	uint8_t command;
	uint8_t reserved;
	uint8_t	address_type;
	char	dstdata[];
};

struct socks5_reply {
	uint8_t version;
	uint8_t reply;
	uint8_t reserved;
	uint8_t address_type;
	char	dstdata[];
};

extern const struct addrdesc addr_socks5_connect, addr_socks5_bind;

#endif
#endif
