#ifndef __LOADBALANCER_H__
#define __LOADBALANCER_H__

#include <stdint.h>

#define NAT 1
#define DNAT 2
#define DR 3

#define CONFIG_PORT 4000

typedef struct {
	uint32_t	addr;
	uint16_t	port;
} Endpoint;

typedef struct {
	Endpoint	source;
	uint16_t	port;
	Endpoint	destination;
	uint64_t	fin;
} Session;

#endif /* __LOADBALANCER_H__ */
