/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

#include <arpa/inet.h>
#include <stdlib.h>
#include <string.h>
#include <libconfig.h>
#include "settings.h"

PRX_SETS* readconfig(char *filename)
{
    
    PRX_SETS *config;
    static uint32_t length, i;
    static const char *string_p;
    puts("readconfig started");
    /* используются типы из libconfig */
    config_t cfg; 
    config_setting_t *setting_p;

    config_init(&cfg);

    /* Читаем файл. Если ошибка, то завершаем работу */
    if(! config_read_file(&cfg, filename))
    {
        fprintf(stderr, "%s:%d - %s\n", config_error_file(&cfg),
            config_error_line(&cfg), config_error_text(&cfg));
        config_destroy(&cfg);
        return(NULL);
    }
    puts("file read");
 
    /* Записываем параметры в структуру Config */
    config = (PRX_SETS *)malloc(sizeof(PRX_SETS));
    setting_p = config_lookup (&cfg, "DNS.Port");
    if (setting_p != NULL) {
    puts("setting_p if");
        config->dns_port = config_setting_get_int (setting_p);
    }
  else {
        fprintf (stderr, "%s - %s\n", config_error_file(&cfg), 
                "wrong DNS port specified");
        return(NULL);
    }
    puts("dns port read");
  
    setting_p = config_lookup (&cfg, "DNS.IP");
    if (setting_p != NULL) {
        string_p = config_setting_get_string (setting_p);
        length = strlen((char *) string_p);
        config->dns_ip = (char *)malloc(length * sizeof(char));
        strcpy ((char *)config->dns_ip, string_p);
    }
    else {
        fprintf (stderr, "%s - %s\n", config_error_file(&cfg), "wrong DNS address specified");
        return(NULL);
    }

    setting_p = config_lookup (&cfg, "DNS.Response");
    if (setting_p != NULL) {
        string_p = config_setting_get_string (setting_p);
        length = strlen((char *) string_p);
        config->dns_response = (char *)malloc(length * sizeof(char));
        strcpy ((char *)config->dns_response, string_p);
    }
    else {
        config->dns_response = NULL;
    }

    setting_p = config_lookup (&cfg, "Blacklist");
    if (setting_p != NULL) {
        config->bl_size = config_setting_length (setting_p);
        config->blacklist = (const char **)malloc(config->bl_size * sizeof(const char *));
        for (i = 0; i < config->bl_size; ++i) {
            string_p = config_setting_get_string_elem (setting_p, i);
            if (string_p != 0 || NULL){
                length = strlen((char *) string_p);
                config->blacklist[i] = (char *)malloc(length * sizeof(char));
                strcpy ((char *)config->blacklist[i], string_p);
            }
        }
    }
    else {
        fprintf (stderr, "%s - %s\n", config_error_file(&cfg), 
                "blacklist not found");
        return(NULL);
    }
    setting_p = config_lookup (&cfg, "Proxy.Port");
    if (setting_p != NULL) {
        config->proxy_port = config_setting_get_int (setting_p);
    }
    else {
      fprintf (stderr, "%s - %s\n", config_error_file(&cfg), 
              "wrong proxy port specified");
      return(NULL);
    }
  
    /* Удаляем структуру libconfig */
    
    config_destroy(&cfg);
    return(config); 
}