/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

/* 
 * File:   settings.h
 * Author: nevmnd
 *
 * Created on 11 ноября 2018 г., 19:26
 */

/*structure to store configuration*/
typedef struct {
    const char *dns_ip;
    uint16_t dns_port;
    const char *dns_response;
    uint16_t proxy_port;
    uint32_t bl_size;
    const char **blacklist;
} PRX_SETS;

/*function to read configuration*/
PRX_SETS* readconfig(char *filename);
