// x509_server.h
#ifndef X509_SERVER_H
#define X509_SERVER_H

/**
 * Avvia un server HTTP sulla porta 8888 che accetta certificati X.509
 * tramite POST a /register_mud_cert, estrae MUD URL e IP e invoca
 * executeOpenMudDhcpAction().
 */
void start_x509_server_async();
void process_certificate_for_ip(DhcpEvent *event);
void block_device_traffic_except_osmud(const char *ip);
void save_event_to_file(const DhcpEvent *event);

#endif // X509_SERVER_H
