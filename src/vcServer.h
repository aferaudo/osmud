// x509_server.h
#ifndef VCDID_H
#define VCDID_H

/**
 * Avvia un server HTTP sulla porta 8888 che accetta certificati X.509
 * tramite POST a /register_mud_cert, estrae MUD URL e IP e invoca
 * executeOpenMudDhcpAction().
 */
void start_vc_server_async();
void process_verified_vc_for_ip(const char *ip);
void block_device_traffic_except_osmud(const char *ip);
void save_event_to_file(const DhcpEvent *event);

#endif // VCDID_H