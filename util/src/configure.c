#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/socket.h>
#include <util/cmd.h>
#include <util/types.h>
#include <util/list.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define DEFAULT_ADDR "192.168.100.20" //intra address
#define DEFAULT_PORT 4000

#define MAX_LINE_SIZE 4096

static int sock;
struct sockaddr_in lb_addr;
static int is_continue = true;

static int cmd_exit(int argc, char** argv) {
	//stop moniotorting
	is_continue = false;
	return 0;
}

static int cmd_help_(int argc, char** argv) {
	//do nothing
	return 0;
}

static int cmd_niconfig(int argc, char** argv) {
	if(argc <= 3) {
		return 0;
	} 
	
	if(!strcmp(argv[1], "-set")) {
		if(!strcmp(argv[2], "intra")) {
			uint32_t ip;
			bool ip_change = false;
			uint16_t port;
			bool port_change = false;

			for(int i = 3; (i + 1) < argc; i++) {
				if(!strcmp(argv[i], "ip")) {
					ip = inet_addr(argv[++i]);
					ip_change = true;
				} else if(!strcmp(argv[i], "gw")) {
					//do nothing
				} else if(!strcmp(argv[i], "mask")) {
					//do nothing
				} else if(!strcmp(argv[i], "port")) {
					char* str;
					port = strtol(argv[++i], &str, 0);
					port_change = true;
				} else {
					return 1;
				}
			}
			
			if(!ip_change)
				ip = ntohl(lb_addr.sin_addr.s_addr);	
			if(!port_change)
				port = ntohs(lb_addr.sin_port);
	
			memset(&lb_addr, 0, sizeof(struct sockaddr_in));
			lb_addr.sin_family = AF_INET;
			lb_addr.sin_port = htons(port);
			lb_addr.sin_addr.s_addr = htonl(ip);
		}
	}
	return 0;
}

static int cmd_ripconfig(int argc, char** argv) {
	//do nothing
	return 0;
}

static int cmd_modeconfig(int argc, char** argv) {
	//do nothing
	return 0;
}

static int cmd_algorithm(int argc, char** argv) {
	//do nothing
	return 0;
}

static int cmd_monitor(int argc, char** argv) {
	//do nothing
	return 0;
}

Command commands[] = {
	{
		.name = "exit",
		.func = cmd_exit
	},
	{
		.name = "help",
		.func = cmd_help_
	},
	{
		.name = "niconfig",
		.func = cmd_niconfig
	},
	{
		.name = "ripconfig",
		.func = cmd_ripconfig
	},
	{
		.name = "modeconfig",
		.func = cmd_modeconfig
	},
	{
		.name = "algorithm",
		.func = cmd_algorithm
	},
	{
		.name = "monitor",
		.func = cmd_monitor
	},
	{
		.name = NULL
	},
};

static void init_config(void) {
	sock = socket(PF_INET, SOCK_DGRAM, 0);
	if(sock == -1) {
		printf("error : can not create socket");
		exit(1);
	}

	memset(&lb_addr, 0, sizeof(struct sockaddr_in));
	lb_addr.sin_family = AF_INET;
	lb_addr.sin_port = htons(DEFAULT_PORT);
	lb_addr.sin_addr.s_addr = inet_addr(DEFAULT_ADDR);
	
	cmd_init();
}

int main(int argc, char** argv) {
	init_config();

	int execute_cmd(char* line, bool is_dump) {
		//if is_dump == true then file cmd
		//   is_dump == false then stdin cmd
		if(is_dump == true)
			printf("%s\n", line);
		
		sendto(sock, line, strlen(line) + 1, 0,(struct sockaddr*)&lb_addr, sizeof(lb_addr));
		cmd_exec(line);

		printf("> ");
		fflush(stdout);

		return 0;
	}
	
	List* fd_list = list_create(NULL);
	
	for(int i = 1; i < argc; i++) {
		int fd = open(argv[i], O_RDONLY);
		if(fd != -1) {
			list_add(fd_list, (void*)(int64_t)fd);
		}
	}
	list_add(fd_list, STDIN_FILENO); //fd of stdin

	void get_cmd_line(int fd) {
		static char line[MAX_LINE_SIZE] = {0, };
		char* head;
		int seek = 0;
		static int eod = 0; //end of data

		while((eod += read(fd, &line[eod], MAX_LINE_SIZE - eod))) {
			head = line;
			for(; seek < eod; seek++) {
				if(line[seek] == '\n') {
					line[seek] = '\0';
					int ret = execute_cmd(head, fd != STDIN_FILENO);

					if(fd != STDIN_FILENO && ret != 0 && ret != CMD_STATUS_ASYNC_CALL) {//parsing file and return error code
						printf("stop parsing file\n");
						eod = 0;
						return;
					}
					head = &line[seek] + 1;
				}
			}
			if(head == line && eod == MAX_LINE_SIZE){ //not found '\n' and head == 0
				printf("Command line is too long %d > %d\n", eod, MAX_LINE_SIZE);
				eod = 0; 
				return;
			} else { //not found '\n' and seek != 0
				memmove(line, head, eod - (head - line));
				eod -= head - line;
				seek = eod;
				if(fd == STDIN_FILENO) {
					return;
				} else
					continue;
			}
		}
		if(eod != 0) {
			line[eod] = '\0';
			execute_cmd(&line[0], fd != STDIN_FILENO);
		}
		eod = 0;
		return;
	}
	
	int fd = (int)(int64_t)list_remove_first(fd_list);
	int retval;
	char buf[CMD_RESULT_SIZE] = {0, };
	
	fd_set in_put;
	fd_set temp_in;

	FD_ZERO(&in_put);
	FD_SET(sock, &in_put);
	FD_SET(fd, &in_put);

	printf(">");
	fflush(stdout);
	
	while(is_continue) {
		temp_in = in_put;

		retval = select(fd > sock ? (fd + 1) : (sock + 1), &temp_in, 0, 0, NULL);

		if(retval == -1) {
			printf("selector error\n");
			return -1;
		} else if(retval == 0) {
			printf("selector timeout\n");
			continue;
		} else {
			if(FD_ISSET(sock, &temp_in) != 0) {
				struct sockaddr_in recv_addr;
				socklen_t recv_addr_size;
				recvfrom(sock, buf, CMD_RESULT_SIZE - 1, 0, (struct sockaddr*)&recv_addr, &recv_addr_size);
				printf("%s\n",buf);
				fflush(stdout);
			}
			if(FD_ISSET(fd, &temp_in) != 0) {
				get_cmd_line(fd);
				if(fd != STDIN_FILENO) {
					FD_CLR(fd, &in_put);
					close(fd);
					fd = (int)(int64_t)list_remove_first(fd_list);
					FD_SET(fd, &in_put);
				}
			}
		}

	}
}
