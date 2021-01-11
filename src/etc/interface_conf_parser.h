#include <stdio.h>
#include <stdlib.h>
#include <glib.h>

typedef struct{
    char *lan;
    char *wan;
}Interfaces;

Interfaces *get_interfaces(char *file_name);