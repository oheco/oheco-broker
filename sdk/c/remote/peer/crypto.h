#ifndef OB_PEER_CRYPTO_H
#define OB_PEER_CRYPTO_H
#include "internal.h"
void ob_hex(const unsigned char *bytes, size_t size, char *out);
int ob_unhex(const char *text, unsigned char *out, size_t size);
int ob_signal_mac(const unsigned char key[32], uint64_t seq, const char *type,
                  const char *payload, unsigned char out[32]);
int ob_derive_keys(ob_remote_peer *p, const unsigned char *client_msg,
                   const unsigned char *server_msg);
int ob_channel_mac(const unsigned char *shared, size_t shared_len,
                    const unsigned char fingerprint[32], const unsigned char exporter[32],
                    int sender_server, unsigned char out[32]);
/* RFC 9000 sections 16 and 18: inspect the complete peer TP TLV sequence.
 * xquic 1.9.7's private no_crypto parameter is 0x1000; absent/zero only. */
int ob_transport_params_encrypted(const unsigned char *params, size_t len);
int ob_connection_encrypted(xqc_connection_t *conn);
void ob_peer_handshake(xqc_connection_t *conn, void *data, void *proto);
int ob_certificate_matches(ob_remote_peer *p, const unsigned char *der, size_t len);
int ob_make_certificate(ob_remote_peer *p);
void ob_certificate_cleanup(ob_remote_peer *p);
#endif
