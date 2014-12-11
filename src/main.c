#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <malloc.h>
#include <thread.h>
#include <net/ni.h>
#include <net/ether.h>
#include <net/arp.h>
#include <net/ip.h>
#include <net/icmp.h>
#include <net/checksum.h>
#include <net/udp.h>
#include <net/tcp.h>
#include <util/list.h>
#include <util/map.h>
#include <util/event.h>
#include <util/cmd.h>
#include "loadbalancer.h"

static Map* sessions;
static Map* ports;
static int mode;

static void rip_add(uint32_t addr, uint16_t port) {
	Endpoint* endpoint = malloc(sizeof(Endpoint));
	endpoint->addr = addr;
	endpoint->port = port;
	
	NetworkInterface* ni_intra = ni_get(1);
	List* rips = ni_config_get(ni_intra, "pn.lb.rips");
	list_add(rips, endpoint);
}

static Endpoint* rip_alloc(NetworkInterface* ni) {
	static int robin;
	
	List* rips = ni_config_get(ni, "pn.lb.rips");
	int idx = (robin++) % list_size(rips);
	
	return list_get(rips, idx);
}

static uint32_t str_to_adr(char* argv) {
	char* str = argv;
	uint32_t address = (strtol(str, &str, 0) & 0xff) << 24; str++;
	address |= (strtol(str, &str, 0) & 0xff) << 16; str++;
	address |= (strtol(str, &str, 0) & 0xff) << 8; str++;
	address |= strtol(str, NULL, 0) & 0xff;

	return address;
}

static int cmd_exit(int argc, char** argv) {
	//stop monitoring

	return 0;
}

static int cmd_niconfig(int argc, char** argv) {

	if(argc == 1) {
		int pos = 0;
		NetworkInterface* ni_inter = ni_get(0);
		uint32_t inter_ip = (uint32_t)(uint64_t)ni_config_get(ni_inter, "ip");
		uint32_t inter_gateway = (uint32_t)(uint64_t)ni_config_get(ni_inter, "gw");
		uint32_t inter_netmask = (uint32_t)(uint64_t)ni_config_get(ni_inter, "mask");
		uint16_t inter_port = (uint16_t)(uint64_t)ni_config_get(ni_inter, "pn.lb.port");
		
		NetworkInterface* ni_intra = ni_get(1);
		uint32_t intra_ip = (uint32_t)(uint64_t)ni_config_get(ni_intra, "ip");
		uint32_t intra_gateway = (uint32_t)(uint64_t)ni_config_get(ni_intra, "gw");
		uint32_t intra_netmask = (uint32_t)(uint64_t)ni_config_get(ni_intra, "mask");
		uint16_t intra_port = (uint16_t)(uint64_t)ni_config_get(ni_intra, "pn.lb.config.port");
		pos += sprintf(cmd_result, "inter IP:%d.%d.%d.%d Gateway:%d.%d.%d.%d Mask:%d.%d.%d.%d Port:%d\n", (inter_ip >> 24) & 0xff, (inter_ip >> 16) & 0xff, (inter_ip >> 8) & 0xff, inter_ip & 0xff,
		(inter_gateway >> 24) & 0xff, (inter_gateway >> 16) & 0xff, (inter_gateway >> 8) & 0xff, inter_gateway & 0xff, 
		(inter_netmask >> 24) & 0xff, (inter_netmask >> 16) & 0xff, (inter_netmask >> 8) & 0xff, inter_netmask & 0xff, 
		inter_port);
		pos += sprintf(cmd_result + pos, "intra IP:%d.%d.%d.%d Gateway:%d.%d.%d.%d Mask:%d.%d.%d.%d ConfigPort:%d\n", (intra_ip >> 24) & 0xff, (intra_ip >> 16) & 0xff, (intra_ip >> 8) & 0xff, intra_ip & 0xff, 
		(intra_gateway >> 24) & 0xff, (intra_gateway >> 16) & 0xff, (intra_gateway >> 8) & 0xff, intra_gateway & 0xff, 
		(intra_netmask >> 24) & 0xff, (intra_netmask >> 16) & 0xff, (intra_netmask >> 8) & 0xff, intra_netmask & 0xff, 
		intra_port);
		return 0;

	} else if(argc > 3) {
		if(!strcmp(argv[1], "-set")) {
			NetworkInterface* ni;
			if(!strcmp(argv[2], "inter"))
				ni = ni_get(0);
			else if(!strcmp(argv[2], "intra"))
				ni = ni_get(1);
			else {
				sprintf(cmd_result, "Check NetworkInterface number");
				return 1;
			}
			uint32_t ip;
			bool ip_change = false;
			uint32_t gw;
			bool gw_change = false;
			uint32_t mask;
			bool mask_change = false;
			uint16_t port;
			bool port_change = false;
			for(int i = 3; (i + 1) < argc; i++) {
				if(!strcmp(argv[i], "ip")) {
					ip = str_to_adr(argv[++i]);
					ip_change = true;
				} else if(!strcmp(argv[i], "gw")) {
					gw = str_to_adr(argv[++i]);
					gw_change = true;
				} else if(!strcmp(argv[i], "mask")) {
					mask = str_to_adr(argv[++i]);
					mask_change = true;
				} else if(!strcmp(argv[i], "port")) {
					char* str;
					port = strtol(argv[++i], &str, 0);
					port_change = true;
				} else {
					sprintf(cmd_result, "Check options\nhelp gives usage information");
					return 1;
				}
			}
			if(ip_change)
				ni_config_put(ni, "ip", (void*)(uint64_t)ip);
			if(gw_change)
				ni_config_put(ni, "gw", (void*)(uint64_t)gw);
			if(mask_change)
				ni_config_put(ni, "mask", (void*)(uint64_t)mask);
			if(port_change) {
				if(!strcmp(argv[2], "inter"))
					ni_config_put(ni, "pn.lb.port", (void*)(uint64_t)port);
				else
					ni_config_put(ni, "pn.lb.config.port", (void*)(uint64_t)port);
			}
			cmd_niconfig(1, NULL);
			return 0;
		} else {
			sprintf(cmd_result, "Check options\nhelp gives usage information");
			return 1;
		}
	} else {
		sprintf(cmd_result, "Check options\nhelp gives usage information");
		return 1;
	}
}

int cmd_modeconfig(int argc, char** argv) {
	if(argc != 1 && argc != 3) {
		sprintf(cmd_result, "Check options\nhelp gives usage information");
		return 1;
	}

	if(argc == 1) {
		sprintf(cmd_result, "mode : %s", mode == 1 ? "NAT" : (mode == 2 ? "DNAT" : "DR"));
		return 0;
	} else if(argc == 3) {
		if(!strcmp(argv[1], "-set")) {
			if(!strcmp(argv[2], "NAT")) {
				mode = NAT;
				sprintf(cmd_result, "NAT");
				return 0;
			} else if(!strcmp(argv[2], "DNAT")) {
				mode = DNAT;
				sprintf(cmd_result, "DNAT");
				return 0;
			} else if(!strcmp(argv[2], "DR")) {
				mode = DR;
				sprintf(cmd_result, "DR");
				return 0;
			} else {
				sprintf(cmd_result, "Check serviceable mode : NAT, DNAT, DR");
				return 1;
			}
		} else {
			sprintf(cmd_result, "Check options\nhelp gives usage information");
			return 1;
		}
	}

	return 0;
}

static int cmd_ripconfig(int argc, char** argv) {
	if(argc != 1 && argc!= 6) {
		sprintf(cmd_result, "Check options\nhelp gives usage information");
		return 1;
	}
	
	if(argc == 1) {
		NetworkInterface* ni_intra = ni_get(1);
		List* rips = ni_config_get(ni_intra, "pn.lb.rips");
		int rips_size = list_size(rips);

		if(rips_size == 0) {
			sprintf(cmd_result, "rips is empty");
			return 1;
		}
		int pos = 0;
		for(int i = 0; i < rips_size; i++) {
			Endpoint* rip = list_get(rips, i);
			pos += sprintf(cmd_result + pos, "rip %d IP:%d.%d.%d.%d Port:%d\n", i, (rip->addr >> 24) & 0xff, (rip->addr >> 16) & 0xff, (rip->addr >> 8) & 0xff, rip->addr & 0xff, rip->port);
		}
		return 0;
	}
	
	if(!strcmp(argv[1], "-add")) {
		NetworkInterface* ni_intra = ni_get(1);
		List* rips = ni_config_get(ni_intra, "pn.lb.rips");

		uint32_t ip;
		uint16_t port;
		if((!strcmp(argv[2], "ip")) && (!strcmp(argv[4], "port"))) {
			char* str;
			ip = str_to_adr(argv[3]);
			port = strtol(argv[5], &str, 0);
		} else if((!strcmp(argv[2], "port")) && (!strcmp(argv[4], "ip"))) {
			char* str;
			ip = str_to_adr(argv[5]);
			port = strtol(argv[3], &str, 0);
		} else {
			sprintf(cmd_result, "Check options\nhelp gives usage information");	
			return 1;
		}

		for(int i = 0; i < list_size(rips); i++) {
			Endpoint* rip = list_get(rips, i);

			if((ip == (uint32_t)(uint64_t)rip->addr) && (port == (uint16_t)(uint64_t)rip->port)) {
				sprintf(cmd_result, "IP:%d.%d.%d.%d Port:%d is already exist", (ip >> 24) & 0xff, (ip >> 16) & 0xff, (ip >> 8) & 0xff, ip & 0xff, port);
				return 1;
			}
		}

		rip_add(ip, port);
		sprintf(cmd_result, "rip is added IP:%d.%d.%d.%d Port:%d", (ip >> 24) & 0xff, (ip >> 16) & 0xff, (ip >> 8) & 0xff, ip & 0xff, port);
		return 0;

	} else if(!strcmp(argv[1], "-del")) {
		NetworkInterface* ni_intra = ni_get(1);
		List* rips = ni_config_get(ni_intra, "pn.lb.rips");

		int32_t ip;
		uint16_t port;
		if((!strcmp(argv[2], "ip")) && (!strcmp(argv[4], "port"))) {
			char* str;
			ip = str_to_adr(argv[3]);
			port = strtol(argv[5], &str, 0);
		} else if((!strcmp(argv[2], "port")) && (!strcmp(argv[4], "ip"))) {
			char* str;
			ip = str_to_adr(argv[5]);
			port = strtol(argv[3], &str, 0);
		} else {
			sprintf(cmd_result, "Check options\nhelp gives usage information");
			return 1;
		}

		for(int i = 0; i < list_size(rips); i++) {
			Endpoint* rip = list_get(rips, i);
			if((ip == (uint32_t)(uint64_t)rip->addr) && (port == (uint16_t)(uint64_t)rip->port)) {
				list_remove(rips, i);
				sprintf(cmd_result, "rip is deleted IP:%d.%d.%d.%d Port:%d", (ip >> 24) & 0xff, (ip >> 16) & 0xff, (ip >> 8) & 0xff, ip & 0xff, port);
			return 0;
			}
		}

		sprintf(cmd_result, "Not found");
		return 1;

	} else {
		sprintf(cmd_result, "Check options\nhelp gives usage information");
		return 1;
	}
}

static int cmd_algorithm(int argc, char** argv) {
	//Not yet
	return 0;
}

static int cmd_monitor(int argc, char** argv) {
	//Not yet
	return 0;
}

static int cmd_help_(int argc, char** argv) {
	int command_len = 0;
	int pos = 0;
	for(int i = 0; commands[i].name != NULL; i++) {
		int len = strlen(commands[i].name);
		command_len = len > command_len ? len : command_len;
	}

	for(int i = 0; commands[i].name != NULL; i++) {
		pos += sprintf(cmd_result + pos, "%s", commands[i].name);
		int len = strlen(commands[i].name);
		len = command_len - len + 2;
		for(int j = 0; j < len; j++)
			pos += sprintf(cmd_result + pos, " ");
		if(commands[i].args != NULL)
			pos += sprintf(cmd_result + pos, "%s  %s\n", commands[i].desc, commands[i].args);
		else
			pos += sprintf(cmd_result + pos, "%s\n", commands[i].desc);
	}

	return 0;
}

Command commands[] = {
	{
		.name = "exit",
		.desc = "Exit the configure",
		.func = cmd_exit
	},
	{
		.name = "help",
		.desc = "Show this message",
		.func = cmd_help_ //can not use function name cmd_help
	},
	{
		.name = "niconfig",
		.desc = "Set network interface",
		.args = "-set [ni name] ip [new ip] gw [new gateway] mask [new netmask] port [new port]",
		.func = cmd_niconfig
	},
	{
		.name = "ripconfig",
		.desc = "Set real sever's ip, port",
		.args = "-add ip [rip ip] port [rip port]\n-del ip [rip ip] port [rip port]",
		.func = cmd_ripconfig
	},
	{
		.name = "modeconfig",
		.desc = "Set loadbalance mode",
		.args = "-set [mode]    :NAT, DNAT, DR",
		.func = cmd_modeconfig
	},
	{
		.name = "algorithm",
		.desc = "Not yet",
		.args = "Not yet",
		.func = cmd_algorithm
	},
	{
		.name = "monitor",
		.desc = "Not yet",
		.args = "Not yet",
		.func = cmd_monitor
	},
	{
		.name = NULL
	},
};

int ginit(int argc, char** argv) {
	uint32_t count = ni_count();
	mode = NAT;

	if(count != 2)
		return 1;
	
	NetworkInterface* ni_inter = ni_get(0);
	ni_config_put(ni_inter, "ip", (void*)(uint64_t)0xc0a8640a);	// 192.168.100.10
	ni_config_put(ni_inter, "pn.lb.port", (void*)(uint64_t)80);
	arp_announce(ni_inter, 0);
	
	NetworkInterface* ni_intra = ni_get(1);
	ni_config_put(ni_intra, "ip", (void*)(uint64_t)0xc0a86414);	// 192.168.100.20
	arp_announce(ni_intra, 0);
	
	List* rips = list_create(NULL);
	ni_config_put(ni_intra, "pn.lb.rips", rips);
	ni_config_put(ni_intra, "pn.lb.config.port", (void*)(uint64_t)CONFIG_PORT);
	//rip_add(0xc0a864c8, 8080);	//192.168.100.200
	//rip_add(0xc0a864c8, 8081);
	//rip_add(0xc0a864c8, 8082);
	//rip_add(0xc0a864c8, 8083);
	//rip_add(0xc0a864c8, 8084);
	
	sessions = map_create(4096, NULL, NULL, NULL);
	ports = map_create(4096, NULL, NULL, NULL);
	return 0;
}

void init(int argc, char** argv) {
	sessions = map_create(4096, NULL, NULL, NULL);
}

static NetworkInterface* ni_inter;
static NetworkInterface* ni_intra;

static void process_config(Packet** packet) {
	Ether* ether = (Ether*)((*packet)->buffer + (*packet)->start);
	IP* ip = (IP*)ether->payload;
	UDP* udp = (UDP*)ip->body;

	if(strlen((char*)udp->body) == 0) {
		return;
	}

	if(cmd_exec((char*)udp->body) == CMD_STATUS_NOT_FOUND) {
		strcpy(cmd_result, "command not found");
	}
	
	int cmd_len = strlen(cmd_result) + 1;

	uint16_t size = (*packet)->size + cmd_len - strlen((char*)udp->body) + 1;
	uint16_t end = (*packet)->end + cmd_len - strlen((char*)udp->body) + 1;
	Packet* packet_ = ni_alloc((*packet)->ni, size);
	memcpy(packet_, *packet, (*packet)->size);
	ni_free(*packet);
	*packet = packet_;

	ether = (Ether*)((*packet)->buffer + (*packet)->start);
	ip = (IP*)ether->payload;
	udp = (UDP*)ip->body;

	//swap source <-> destination
	uint16_t t = udp->destination;
	udp->destination = udp->source;
	udp->source = t;
	udp->checksum = 0;
	
	uint32_t t2 = ip->destination;
	ip->destination = ip->source;
	ip->source = t2;
	ip->ttl = 0x40;
	ip->checksum = endian16(checksum(ip, ip->ihl * 4));

	uint64_t t3 = ether->dmac;
	ether->dmac = ether->smac;
	ether->smac = t3;
	//
	memcpy(udp->body, cmd_result, cmd_len);
	(*packet)->size = size;
	(*packet)->end = end;

	udp_pack((*packet), cmd_len);
	ni_output(ni_intra, (*packet));
	*packet = NULL;
}

static Session* session_alloc(uint32_t saddr, uint16_t sport) {
	uint64_t key = (uint64_t)saddr << 32 | (uint64_t)sport;
	
	Session* session = malloc(sizeof(Session));
	session->source.addr = saddr;
	session->source.port = sport;
	session->port = tcp_port_alloc(ni_intra);
	Endpoint* rip = rip_alloc(ni_intra);
	session->destination.addr = rip->addr;
	session->destination.port = rip->port;
	session->fin = 0;
	
	map_put(sessions, (void*)key, session);
	map_put(ports, (void*)(uint64_t)session->port, session);
	
	printf("Alloc session %x:%d -> %d -> %x:%d\n", saddr, sport, session->port, rip->addr, rip->port);
	
	return session;
}

static void session_free(Session* session) {
	printf("Session freeing: %d.%d.%d.%d:%d %d %d.%d.%d.%d:%d\n", 
		(session->source.addr) >> 24 & 0xff,
		(session->source.addr) >> 16 & 0xff,
		(session->source.addr) >> 8 & 0xff,
		(session->source.addr) >> 0 & 0xff,
		session->source.port,
		session->port,
		(session->destination.addr) >> 24 & 0xff,
		(session->destination.addr) >> 16 & 0xff,
		(session->destination.addr) >> 8 & 0xff,
		(session->destination.addr) >> 0 & 0xff,
		session->destination.port);
	
	uint64_t key = (uint64_t)session->source.addr << 32 | (uint64_t)session->source.port;
	map_remove(sessions, (void*)key);
	map_remove(ports, (void*)(uint64_t)session->port);
	tcp_port_free(ni_intra, session->port);
	free(session);
}

void process_inter() {
	NetworkInterface* ni = ni_inter;
	
	Packet* packet = ni_input(ni);
	if(!packet)
		return;
	
	if(arp_process(packet))
		return;
	
	if(icmp_process(packet))
		return;
	
	uint32_t addr = (uint32_t)(uint64_t)ni_config_get(ni, "ip");
	uint16_t port = (uint16_t)(uint64_t)ni_config_get(ni, "pn.lb.port");
	
	Ether* ether = (Ether*)(packet->buffer + packet->start);
	if(endian16(ether->type) == ETHER_TYPE_IPv4) {
		IP* ip = (IP*)ether->payload;
		
		if(ip->protocol == IP_PROTOCOL_TCP) {
			TCP* tcp = (TCP*)ip->body;
			
			if(endian32(ip->destination) == addr && endian16(tcp->destination) == port) {
				uint32_t saddr = endian32(ip->source);
				uint16_t sport = endian16(tcp->source);
				uint32_t raddr = (uint32_t)(uint64_t)ni_config_get(ni_intra, "ip");
				uint64_t key = (uint64_t)saddr << 32 | (uint64_t)sport;
				
				Session* session = map_get(sessions, (void*)key);
				if(!session) {
					session = session_alloc(saddr, sport);
				}
				
				switch(mode) {
					case NAT:
					ip->source = endian32(raddr);
					tcp->source = endian16(session->port);
				
					ip->destination = endian32(session->destination.addr);
					tcp->destination = endian16(session->destination.port);
					ether->smac = endian48(ni_intra->mac);
					ether->dmac = endian48(arp_get_mac(ni_intra, session->destination.addr));
					break;

					case DNAT:
					ip->destination = endian32(session->destination.addr);
					tcp->destination = endian16(session->destination.port);
					ether->smac = endian48(ni_intra->mac);
					ether->dmac = endian48(arp_get_mac(ni_intra, session->destination.addr));
					break;

					case DR:
					ether->smac = endian48(ni_intra->mac);
					ether->dmac = endian48(arp_get_mac(ni_intra, session->destination.addr));
					break;
				}
				tcp_pack(packet, endian16(ip->length) - ip->ihl * 4 - TCP_LEN);
				
				printf("Incoming: %lx %lx %d.%d.%d.%d:%d %d %d.%d.%d.%d:%d\n", 
					endian48(ether->dmac), 
					endian48(ether->smac),
					(endian32(ip->source)) >> 24 & 0xff,
					(endian32(ip->source)) >> 16 & 0xff,
					(endian32(ip->source)) >> 8 & 0xff,
					(endian32(ip->source)) >> 0 & 0xff,
					endian16(tcp->source),
					session->port,
					(endian32(ip->destination)) >> 24 & 0xff,
					(endian32(ip->destination)) >> 16 & 0xff,
					(endian32(ip->destination)) >> 8 & 0xff,
					(endian32(ip->destination)) >> 0 & 0xff,
					endian16(tcp->destination));
				
				if(session->fin && tcp->ack) {
					printf("Ack fin\n");
					event_timer_remove(session->fin);
					session_free(session);
				}
				
				ni_output(ni_intra, packet);
				
				packet = NULL;
			}
		}
	}
	
	if(packet)
		ni_free(packet);
}

void process_intra() {
	NetworkInterface* ni = ni_intra;
	
	Packet* packet = ni_input(ni);
	if(!packet)
		return;
	
	if(arp_process(packet))
		return;
	
	if(icmp_process(packet))
		return;
	
	Ether* ether = (Ether*)(packet->buffer + packet->start);
	
	if(endian16(ether->type) == ETHER_TYPE_IPv4) {
		IP* ip = (IP*)ether->payload;
		
		if(ip->protocol == IP_PROTOCOL_TCP) {
			TCP* tcp = (TCP*)ip->body;
			
			Session* session;
			uint32_t saddr;
			uint16_t sport;
			uint64_t key;

			switch(mode) {
				case NAT:
				session = map_get(ports, (void*)(uint64_t)endian16(tcp->destination));
				break;

				case DNAT:
				saddr = endian32(ip->destination);
				sport = endian16(tcp->destination);
				key = (uint64_t)saddr << 32 | (uint64_t)sport;

				session = map_get(sessions, (void*)key);
				break;

				case DR:
				//Can't reacheable
				break;
			}
			if(session) {
				uint32_t addr = (uint32_t)(uint64_t)ni_config_get(ni_inter, "ip");
				uint16_t port = (uint16_t)(uint64_t)ni_config_get(ni_inter, "pn.lb.port");
				
				switch(mode) {
					case NAT:
					tcp->source = endian16(port);
					ip->source = endian32(addr);
					tcp->destination = endian16(session->source.port);
					ip->destination = endian32(session->source.addr);
					ether->smac = endian48(ni_inter->mac);
					ether->dmac = endian48(arp_get_mac(ni_inter, endian32(ip->destination)));
					break;

					case DNAT:
					tcp->source = endian16(port);
					ip->source = endian32(addr);
					ether->smac = endian48(ni_inter->mac);
					ether->dmac = endian48(arp_get_mac(ni_inter, endian32(ip->destination)));
					break;

					case DR:
					//Do nothing
					break;
				}
				tcp_pack(packet, endian16(ip->length) - ip->ihl * 4 - TCP_LEN);
				
				printf("Outgoing: %lx %lx %d.%d.%d.%d:%d %d %d.%d.%d.%d:%d\n", 
					endian48(ether->dmac), 
					endian48(ether->smac),
					(endian32(ip->source)) >> 24 & 0xff,
					(endian32(ip->source)) >> 16 & 0xff,
					(endian32(ip->source)) >> 8 & 0xff,
					(endian32(ip->source)) >> 0 & 0xff,
					endian16(tcp->source),
					session->port,
					(endian32(ip->destination)) >> 24 & 0xff,
					(endian32(ip->destination)) >> 16 & 0xff,
					(endian32(ip->destination)) >> 8 & 0xff,
					(endian32(ip->destination)) >> 0 & 0xff,
					endian16(tcp->destination));
				
				if(tcp->fin) {
					bool gc(void* context) {
						Session* session = context;
						
						printf("Timeout fin\n");
						session_free(session);
						
						return false;
					}
					
					printf("Fin timer\n");
					session->fin = event_timer_add(gc, session, 3000, 3000);
				}
				
				ni_output(ni_inter, packet);
				
				packet = NULL;
			}
		} else if(ip->protocol == IP_PROTOCOL_UDP) {
			UDP* udp = (UDP*)ip->body;
			if(endian16(udp->destination) == (uint16_t)(uint64_t)ni_config_get(ni_intra, "pn.lb.config.port")) {
				process_config(&packet);
			}
		}
	}
	
	if(packet)
		ni_free(packet);
}

void destroy() {
}

void gdestroy() {
}

int main(int argc, char** argv) {
	printf("Thread %d bootting\n", thread_id());
	if(thread_id() == 0) {
		int err = ginit(argc, argv);
		if(err != 0)
			return err;
	}
	
	thread_barrior();
	
	init(argc, argv);
	
	thread_barrior();
	
	cmd_init();

	ni_inter = ni_get(0);
	ni_intra = ni_get(1);
	event_init();
	
	while(1) {
		if(ni_has_input(ni_inter)) {
			process_inter();
		}
		
		if(ni_has_input(ni_intra)) {
			process_intra();
		}
		
		event_loop();
	}
	
	thread_barrior();
	
	destroy();
	
	thread_barrior();
	
	if(thread_id() == 0) {
		gdestroy(argc, argv);
	}
	
	return 0;
}
