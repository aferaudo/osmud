#include "interface_conf_parser.h"

// gcc $(pkg-config --cflags glib-2.0) test_parser.c $(pkg-config --libs glib-2.0) -o out
// gcc $(pkg-config --cflags glib-2.0) parser_conf.c test_parser.c $(pkg-config --libs glib-2.0) -o out

void
buildInterfaces(Interfaces *interfaces)
{
    interfaces->lan=NULL;
    interfaces->wan=NULL;

}

Interfaces *get_interfaces(char *file_name){

    Interfaces *interfaces = (Interfaces *) malloc(sizeof(Interfaces)); // change to safe_malloc

    buildInterfaces(interfaces);

    // Loading a key file and reading a value
    g_autoptr(GError) error = NULL;
    g_autoptr(GKeyFile) key_file = g_key_file_new();

    if(!g_key_file_load_from_file(key_file, file_name, G_KEY_FILE_NONE, &error)){
        
        if(!g_error_matches(error, G_FILE_ERROR, G_FILE_ERROR_NOENT))
            g_warning ("Error loading key file:%s", error->message);
    }

    interfaces->lan = g_key_file_get_string(key_file, "INTERFACE", "LAN", &error);
    

    if(interfaces->lan == NULL && 
        !g_error_matches(error, G_KEY_FILE_ERROR, G_KEY_FILE_ERROR_KEY_NOT_FOUND)){

            g_warning("Error finding key in key file: %s", error->message);

    }else if(interfaces->lan == NULL){

        // Fall back to a default value.
        interfaces->lan = g_strdup("eth0");

    }
    
    interfaces->wan = g_key_file_get_string(key_file, "INTERFACE", "WAN", &error);
    if(interfaces->wan == NULL && 
        !g_error_matches(error, G_KEY_FILE_ERROR, G_KEY_FILE_ERROR_KEY_NOT_FOUND)){

            g_warning("Error finding key in key file: %s", error->message);

    }else if(interfaces->wan == NULL){

        // Fall back to a default value.
        interfaces->wan = g_strdup("eth1");

    }

    return interfaces;
}