/*
 * Copyright 2014, Vietor Liu <vietor.liu at gmail.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or any later version. For full terms that can be
 * found in the LICENSE file.
 */

#include "dnsproxy.h"
#include "settings.h"

#define CONFIG_NAME "proxy.cfg"
#define PACKAGE_SIZE 8192
#define CACHE_CLEAN_TIME (MIN_TTL / 2 + 1)

typedef struct {
	SOCKET sock;
	char buffer[PACKAGE_SIZE + sizeof(unsigned short)];
} LOCAL_DNS;

typedef struct {
	int tcp;
	SOCKET sock;
	struct sockaddr_in addr;
	unsigned int head;
	unsigned int rear;
	unsigned int capacity;
	char buffer[PACKAGE_SIZE * 3];
} REMOTE_DNS;

typedef struct {
	LOCAL_DNS local;
	REMOTE_DNS remote;
} PROXY_ENGINE;
#pragma (push, 1)
struct fake_rrs {
            uint16_t type : 0x01;
            uint16_t classes : 0x01;
            uint32_t ttl;
            uint16_t rd_length : 0x04;
            in_addr_t address;
        } fake;
#pragma (pop)
static const int enable = 1;
static PRX_SETS *cfg;

static void process_query(PROXY_ENGINE *engine)
{
	LOCAL_DNS *ldns;
	REMOTE_DNS *rdns;
	DNS_HDR *hdr, *rhdr;
	DNS_QDS *qds;
	TRANSPORT_CACHE *tcache;
	socklen_t addrlen;
	struct sockaddr_in source;
	char *pos, *head, *rear;
	char *buffer, domain[PACKAGE_SIZE], rbuffer[PACKAGE_SIZE];
	int size, dlen;
	unsigned char qlen;
        unsigned short q_len;
      
	ldns = &engine->local;
	rdns = &engine->remote;
	buffer = ldns->buffer + sizeof(unsigned short);

	addrlen = sizeof(struct sockaddr_in);
	size = recvfrom(ldns->sock, buffer, PACKAGE_SIZE, 0, (struct sockaddr*)&source, &addrlen);
	if(size <= (int)sizeof(DNS_HDR))
		return;

	hdr = (DNS_HDR*)buffer;
	rhdr = (DNS_HDR*)rbuffer;
	memset(rbuffer, 0, sizeof(DNS_HDR));

	rhdr->id = hdr->id;
	rhdr->qr = 1;
	q_len = 0;
	qds = NULL;
	head = buffer + sizeof(DNS_HDR);
	rear = buffer + size;
	if(hdr->qr != 0 || hdr->tc != 0 || ntohs(hdr->qd_count) != 1)
		rhdr->rcode = 1;
	else {
		dlen = 0;
		pos = head;
		while(pos < rear) {
			qlen = (unsigned char)*pos++;
			if(qlen > 63 || (pos + qlen) > (rear - sizeof(DNS_QDS))) {
				rhdr->rcode = 1;
				break;
			}
			if(qlen > 0) {
				if(dlen > 0)
					domain[dlen++] = '.';
				while(qlen-- > 0)
					domain[dlen++] = (char)tolower(*pos++);
			}
			else {
				qds = (DNS_QDS*) pos;
				if(ntohs(qds->classes) != 0x01)
					rhdr->rcode = 4;
				else {
					pos += sizeof(DNS_QDS);
					q_len = pos - head;
				}
				break;
			}
		}
		domain[dlen] = '\0';
//                fprintf(stdout, "Requested domain: %s\n", domain);
	}

	if(rhdr->rcode == 0) {
		tcache = transport_cache_insert(ntohs(hdr->id), &source, ldns);
		if(tcache == NULL)
			rhdr->rcode = 2;
		else {
			hdr->id = htons(tcache->new_id);
			if(!rdns->tcp) {
				if(sendto(rdns->sock, buffer, size, 0, (struct sockaddr*)&rdns->addr, sizeof(struct sockaddr_in)) != size)
					rhdr->rcode = 2;
			}
			else {
				if(rdns->sock == INVALID_SOCKET) {
					rdns->head = 0;
					rdns->rear = 0;
					rdns->sock = socket(AF_INET, SOCK_STREAM, 0);
					if(rdns->sock != INVALID_SOCKET) {
						setsockopt(rdns->sock, IPPROTO_TCP, TCP_NODELAY, (void*)&enable, sizeof(enable));
						if(connect(rdns->sock, (struct sockaddr*)&rdns->addr, sizeof(struct sockaddr_in)) != 0) {
							closesocket(rdns->sock);
							rdns->sock = INVALID_SOCKET;
						}
					}
				}
				if(rdns->sock == INVALID_SOCKET)
					rhdr->rcode = 2;
				else{
					pos = ldns->buffer;
					*(unsigned short*)pos = htons((unsigned short)size);
					size += sizeof(unsigned short);
					if(send(rdns->sock, ldns->buffer, size, 0) != size) {
						rdns->head = 0;
						rdns->rear = 0;
						closesocket(rdns->sock);
						rdns->sock = INVALID_SOCKET;
						rhdr->rcode = 2;
					}
				}
			}
			if(rhdr->rcode != 0)
				transport_cache_delete(tcache);
		}
	}

 	if(rhdr->rcode != 0)
		sendto(ldns->sock, rbuffer, sizeof(DNS_HDR), 0, (struct sockaddr*)&source, sizeof(struct sockaddr_in));
}

static void process_response(char* buffer, int size)
{
	DNS_HDR *hdr;
	DNS_QDS *qds;
	DNS_RRS *rrs;
	LOCAL_DNS *ldns;
	TRANSPORT_CACHE *cache;
	char domain[PACKAGE_SIZE];
	char *pos, *rear, *answer;
	int badfmt, dlen, length;
        uint32_t *p;
        uint32_t fake_ip;
	unsigned char qlen;
	unsigned int ttl, ttl_tmp, blacklisted, i;
	unsigned short index, an_count;

 


	length = size;
	hdr = (DNS_HDR*)buffer;
 	an_count = ntohs(hdr->an_count);
	if(hdr->qr == 1 && hdr->tc == 0 && ntohs(hdr->qd_count) == 1 && an_count > 0) {
		dlen = 0;
		qds = NULL;
		pos = buffer + sizeof(DNS_HDR);
		rear = buffer + size;
		while(pos < rear) {
			qlen = (unsigned char)*pos++;
			if(qlen > 63 || (pos + qlen) > (rear - sizeof(DNS_QDS)))
				break;
			if(qlen > 0) {
				if(dlen > 0)
					domain[dlen++] = '.';
				while(qlen-- > 0)
					domain[dlen++] = (char)tolower(*pos++);
			}
			else {
				qds = (DNS_QDS*) pos;
				if(ntohs(qds->classes) != 0x01)
					qds = NULL;
				else
					pos += sizeof(DNS_QDS);
				break;
			}
		}
		domain[dlen] = '\0';
//                fprintf(stdout, "Got domain: %s\n", domain);
                blacklisted = 0;
                for (i = 0; i < cfg->bl_size; ++i) {
                    if(!strcmp((char *)cfg->blacklist[i], domain)){
                        blacklisted = 1;
                        break;
                    }
                }
//                printf("blacklisted: %u\n", blacklisted);

		if(qds && ntohs(qds->type) == 0x01) {
			ttl = MAX_TTL;
			index = 0;
			badfmt = 0;
			answer = pos;
			while(badfmt == 0 && pos < rear && index++ < an_count) {
				rrs = NULL;
				if((unsigned char)*pos == 0xc0) {
					pos += 2;
					rrs = (DNS_RRS*) pos;
				}
				else {
					while(pos < rear) {
						qlen = (unsigned char)*pos++;
						if(qlen > 63 || (pos + qlen) > (rear - sizeof(DNS_RRS)))
							break;
						if(qlen > 0)
							pos += qlen;
						else {
							rrs = (DNS_RRS*) pos;
							break;
						}
					}
				}
				if(rrs == NULL || ntohs(rrs->classes) != 0x01)
					badfmt = 1;
				else {
					ttl_tmp = ntohl(rrs->ttl);
					if(ttl_tmp < ttl)
						ttl = ttl_tmp;
                                        if(blacklisted){
                puts("RRS:");
        for (i = 0; i < sizeof(DNS_RRS); i++){
            printf("%X", rrs[i]);
        };
        printf("\n");
//                                            struct fake_rrs *p = &fake;
//                                            fake.ttl = 300;
//                                            fake.address = inet_addr(cfg->dns_response);
//                                            printf("type: %d\nclass: %d\nttl: %d\nlength: %d\nrd_data:\n",
//                                                    ntohs(rrs->type),
//                                                    ntohs(rrs->classes),
//                                                    ntohl(rrs->ttl),
//                                                    ntohs(rrs->rd_length)
//                                                    );
                                            p = &rrs->rd_data;
                                            printf("%X\n", *p);
                                            fake_ip = inet_addr(cfg->dns_response);
                                            p = &fake_ip;                                            
                                            printf("%X\n", ntohl(*p));
                                            memcpy(&rrs->rd_data, p, sizeof(uint32_t));
                                            puts("NEW RESPONSE RRS:");
                                            for (i = 0; i < sizeof(DNS_RRS); i++){
                                                printf("%X", rrs[i]);
                                            };
                                            printf("\n");
                                            
//                                            printf("TTL: %d\n", ntohl(rrs->ttl));
//                                            printf("FAKE ADDRESS: %X\n", p->address);
//                                            memcpy(&rrs->type, &fake, sizeof(struct fake_rrs));
//                                            puts("NEW RESPONSE DNS RRS:");
//                                            struct in_addr addr;
//                                            p = &addr;
//                                            memcpy(&addr, &rrs->rd_data, 4);
//            printf("%X", addr);
                                        }
					pos += sizeof(DNS_RRS) + ntohs(rrs->rd_length);
				}
			}
			if(badfmt == 0) {
				hdr->nr_count = 0;
				hdr->ns_count = 0;
				length = pos - buffer;
			}
		}
	}

	cache = transport_cache_search(ntohs(hdr->id));
	if(cache) {
		ldns = (LOCAL_DNS*)cache->context;
		hdr->id = htons(cache->old_id);
		sendto(ldns->sock, buffer, length, 0, (struct sockaddr*)&cache->source, sizeof(struct sockaddr_in));
		transport_cache_delete(cache);
	}
}

static void process_response_udp(REMOTE_DNS *rdns)
{
	int size;
	socklen_t addrlen;
	struct sockaddr_in source;
//        puts("process_response started");

	addrlen = sizeof(struct sockaddr_in);
	size = recvfrom(rdns->sock, rdns->buffer, PACKAGE_SIZE, 0, (struct sockaddr*)&source, &addrlen);
	if(size < (int)sizeof(DNS_HDR))
		return;

	if(source.sin_addr.s_addr != rdns->addr.sin_addr.s_addr)
		return;

	process_response(rdns->buffer, size);
}


static PROXY_ENGINE g_engine;

static int dnsproxy(int remote_tcp)
{
	int maxfd, fds;
	fd_set readfds;
	struct timeval timeout;
	struct sockaddr_in addr;
	time_t current, last_clean;

	PROXY_ENGINE *engine = &g_engine;
	LOCAL_DNS *ldns = &engine->local;
	REMOTE_DNS *rdns = &engine->remote;

//        puts("dnsproxy started");
	ldns->sock = socket(AF_INET, SOCK_DGRAM, 0);
	if(ldns->sock == INVALID_SOCKET) {
		perror("create socket");
		return -1;
	}
//        puts("local socket created");
        
	setsockopt(ldns->sock, SOL_SOCKET, SO_REUSEADDR, (char*)&enable, sizeof(enable));
	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = INADDR_ANY;
	addr.sin_port = htons(cfg->proxy_port);
	if(bind(ldns->sock, (struct sockaddr*)&addr, sizeof(addr)) != 0) {
		perror("bind service port");
		return -1;
	}
//        puts("local socket binded");

	rdns->tcp = remote_tcp;
	rdns->sock = INVALID_SOCKET;
	rdns->addr.sin_family = AF_INET;
	rdns->addr.sin_addr.s_addr = inet_addr(cfg->dns_ip);
	rdns->addr.sin_port = htons(cfg->dns_port);
	rdns->head = 0;
	rdns->rear = 0;
	rdns->capacity = sizeof(rdns->buffer);
	rdns->sock = socket(AF_INET, SOCK_DGRAM, 0);
	if(rdns->sock == INVALID_SOCKET) {
            perror("create socket");
            return -1;
	}
//        puts("remote socket created");

	last_clean = time(&current);
	while(1) {
		FD_ZERO(&readfds);
		FD_SET(ldns->sock, &readfds);
		maxfd = (int)ldns->sock;
		if(rdns->sock != INVALID_SOCKET) {
			FD_SET(rdns->sock, &readfds);
			if(maxfd < (int)rdns->sock)
				maxfd = (int)rdns->sock;
		}
		timeout.tv_sec = CACHE_CLEAN_TIME;
		timeout.tv_usec = 0;
		fds = select(maxfd + 1, &readfds, NULL, NULL, &timeout);
		if(fds > 0) {
			if(rdns->sock != INVALID_SOCKET
				&& FD_ISSET(rdns->sock, &readfds)) {
				process_response_udp(rdns);
//                                puts("responded");
			}
			if(FD_ISSET(ldns->sock, &readfds)){
				process_query(engine);
//                                puts("query processed");
                        }                                
		}

		if(time(&current) - last_clean > CACHE_CLEAN_TIME || fds == 0) {
			last_clean = current;
			transport_cache_clean(current);
//                        puts("transport cache cleaned");

		}
	}
//        puts("dnsproxy exited\n");

	return 0;
}

int main()
{
	int remote_tcp = 0;
	int transport_timeout = 5;

        cfg = readconfig(CONFIG_NAME);
        if(cfg == NULL)
            return 1;
        
	signal(SIGPIPE, SIG_IGN);


	printf( " * running at %d\n"
		" * transport to %s:%d,%s\n"
                " * response address: %s\n"
		, cfg->proxy_port
		, cfg->dns_ip
		, cfg->dns_port
                , remote_tcp? "tcp": "udp"
                , cfg->dns_response);
       
	srand((unsigned int)time(NULL));
//	domain_cache_init(hosts_file);
	transport_cache_init(transport_timeout);
	return dnsproxy(remote_tcp);
}
