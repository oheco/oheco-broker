#include "internal.h"
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/hkdf.h>
#include <openssl/sha.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/ec.h>
#include <openssl/rand.h>
#include <openssl/mem.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include "crypto.h"

void ob_hex(const unsigned char *bytes, size_t size, char *out)
{
    static const char digits[] = "0123456789abcdef";
    for (size_t i = 0; i < size; ++i) {
        out[2*i] = digits[bytes[i] >> 4]; out[2*i+1] = digits[bytes[i] & 15];
    }
    out[2*size] = 0;
}
int ob_unhex(const char *text, unsigned char *out, size_t size)
{
    if (!text || strlen(text) != size * 2) return -1;
    for (size_t i = 0; i < size * 2; ++i) {
        unsigned char c = (unsigned char)text[i];
        int n = c >= '0' && c <= '9' ? c-'0' : c >= 'a' && c <= 'f' ? c-'a'+10 : -1;
        if (n < 0) return -1;
        if (!(i & 1)) out[i/2] = (unsigned char)(n << 4);
        else out[i/2] |= (unsigned char)n;
    }
    return 0;
}
int ob_signal_mac(const unsigned char key[32], uint64_t seq, const char *type,
                  const char *payload, unsigned char out[32])
{
    unsigned char be[8]; unsigned int n = 0;
    for (int i = 7; i >= 0; --i) { be[i] = (unsigned char)seq; seq >>= 8; }
    HMAC_CTX ctx; HMAC_CTX_init(&ctx);
    int ok = HMAC_Init_ex(&ctx, key, 32, EVP_sha256(), NULL)
        && HMAC_Update(&ctx, be, 8)
        && HMAC_Update(&ctx, (const unsigned char *)type, strlen(type)+1)
        && HMAC_Update(&ctx, (const unsigned char *)payload, strlen(payload))
        && HMAC_Final(&ctx, out, &n);
    HMAC_CTX_cleanup(&ctx);
    return ok && n == 32 ? 0 : -1;
}
int ob_derive_keys(ob_remote_peer *p, const unsigned char *client_msg,
                   const unsigned char *server_msg)
{
    SHA256_CTX ctx; unsigned char salt[32], keys[64];
    SHA256_Init(&ctx);
    const char suite[] = "OBP1/BoringSSL-SPAKE2-draft02/Ed25519/SHA512/HKDF-SHA256";
    SHA256_Update(&ctx, suite, sizeof(suite));
    SHA256_Update(&ctx, p->broker_id, strlen(p->broker_id)+1);
    SHA256_Update(&ctx, p->session_id, strlen(p->session_id)+1);
    SHA256_Update(&ctx, client_msg, SPAKE2_MAX_MSG_SIZE);
    SHA256_Update(&ctx, server_msg, SPAKE2_MAX_MSG_SIZE);
    SHA256_Final(salt, &ctx);
    const unsigned char info[] = "ob-peer-v1 directional signalling";
    if (!HKDF(keys, sizeof(keys), EVP_sha256(), p->shared, p->shared_len,
              salt, sizeof(salt), info, sizeof(info)-1)) return -1;
    memcpy(p->tx_key, keys + (p->is_server ? 32 : 0), 32);
    memcpy(p->rx_key, keys + (p->is_server ? 0 : 32), 32);
    OPENSSL_cleanse(keys, sizeof(keys));
    return 0;
}
int ob_channel_mac(const unsigned char *shared, size_t shared_len,
                    const unsigned char fingerprint[32], const unsigned char exporter[32],
                    int sender_server, unsigned char out[32])
{
    if (!shared || shared_len != SPAKE2_MAX_KEY_SIZE || !fingerprint || !exporter
        || !out || (sender_server != 0 && sender_server != 1)) return -1;
    static const char label[] = "EXPORTER-ob-peer-v1";
    unsigned int n = 0;
    HMAC_CTX ctx; HMAC_CTX_init(&ctx);
    unsigned char role = (unsigned char)sender_server;
    int ok = HMAC_Init_ex(&ctx, shared, (int)shared_len, EVP_sha256(), NULL)
        && HMAC_Update(&ctx, (const unsigned char *)label, sizeof(label))
        && HMAC_Update(&ctx, &role, 1)
        && HMAC_Update(&ctx, fingerprint, 32)
        && HMAC_Update(&ctx, exporter, 32)
        && HMAC_Final(&ctx, out, &n);
    HMAC_CTX_cleanup(&ctx); return ok && n == 32 ? 0 : -1;
}
static int quic_varint(const unsigned char *bytes, size_t len, size_t *used,
                       uint64_t *value)
{
    if (!len) return -1;
    size_t n = (size_t)1 << (bytes[0] >> 6);
    if (n > len) return -1;
    uint64_t v = bytes[0] & 63;
    for (size_t i = 1; i < n; ++i) v = (v << 8) | bytes[i];
    *used = n; *value = v; return 0;
}
int ob_transport_params_encrypted(const unsigned char *params, size_t len)
{
    if (!params || !len) return 0;
    int seen_no_crypto = 0;
    while (len) {
        uint64_t id, size; size_t used;
        if (quic_varint(params, len, &used, &id)) return 0;
        params += used; len -= used;
        if (quic_varint(params, len, &used, &size)) return 0;
        params += used; len -= used;
        if (size > len) return 0;
        /* This is xquic's private extension, NOT the negotiated TLS cipher.
         * TLS still reports a cipher when xquic installs null protection. */
        if (id == UINT64_C(0x1000)) {
            uint64_t no_crypto;
            if (seen_no_crypto++ || quic_varint(params, (size_t)size, &used, &no_crypto)
                || used != size || no_crypto != 0) return 0;
        }
        params += (size_t)size; len -= (size_t)size;
    }
    return 1;
}
int ob_connection_encrypted(xqc_connection_t *conn)
{
    SSL *ssl = conn ? xqc_conn_get_ssl(conn) : NULL;
    const uint8_t *params = NULL; size_t len = 0;
    if (!ssl) return 0;
    SSL_get_peer_quic_transport_params(ssl, &params, &len);
    return ob_transport_params_encrypted(params, len);
}
int ob_connection_proof(ob_remote_peer *p, int sender_server, unsigned char out[32])
{
    if (!p->tls_ready || !p->conn || !ob_connection_encrypted(p->conn)) return -1;
    unsigned char exporter[32];
    static const char label[] = "EXPORTER-ob-peer-v1";
    SSL *ssl = xqc_conn_get_ssl(p->conn);
    if (!ssl || !SSL_export_keying_material(ssl, exporter, sizeof(exporter),
            label, sizeof(label)-1, (const unsigned char *)p->session_id,
            strlen(p->session_id), 1)) return -1;
    int rc = ob_channel_mac(p->shared, p->shared_len, p->fingerprint, exporter,
                            sender_server, out);
    OPENSSL_cleanse(exporter, sizeof(exporter)); return rc;
}
int ob_certificate_matches(ob_remote_peer *p, const unsigned char *der, size_t len)
{
    unsigned char hash[32];
    if (!p || !der || !len) return 0;
    SHA256(der, len, hash);
    return !CRYPTO_memcmp(hash, p->fingerprint, sizeof(hash));
}
static int write_pem(const char *path, EVP_PKEY *key, X509 *cert)
{
    int fd = open(path, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
    if (fd < 0) return -1;
    BIO *bio = BIO_new_fd(fd, BIO_CLOSE);
    if (!bio) { close(fd); return -1; }
    int ok = key ? PEM_write_bio_PrivateKey(bio, key, NULL, NULL, 0, NULL, NULL)
                 : PEM_write_bio_X509(bio, cert);
    BIO_free(bio); return ok ? 0 : -1;
}
int ob_make_certificate(ob_remote_peer *p)
{
    const char *tmp = getenv("TMPDIR");
    if (!tmp || !*tmp || strlen(tmp) > 900) return -1;
    snprintf(p->cert_dir, sizeof(p->cert_dir), "%s/ob-peer.XXXXXX", tmp);
    if (!mkdtemp(p->cert_dir)) { p->cert_dir[0] = 0; return -1; }
    struct stat st;
    if (stat(p->cert_dir, &st) || (st.st_mode & 077) != 0) return -1;
    snprintf(p->cert_path, sizeof(p->cert_path), "%s/cert.pem", p->cert_dir);
    snprintf(p->key_path, sizeof(p->key_path), "%s/key.pem", p->cert_dir);
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
    EVP_PKEY *key = NULL; X509 *cert = X509_new(); int rc = -1;
    if (!ctx || !cert || !EVP_PKEY_keygen_init(ctx)
        || !EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx, NID_X9_62_prime256v1)
        || !EVP_PKEY_keygen(ctx, &key)) goto end;
    unsigned char serial[16];
    if (!RAND_bytes(serial, sizeof(serial))) goto end;
    serial[0] &= 0x7f;
    BIGNUM *bn = BN_bin2bn(serial, sizeof(serial), NULL);
    ASN1_INTEGER *asn = bn ? BN_to_ASN1_INTEGER(bn, NULL) : NULL;
    BN_free(bn);
    if (!asn) goto end;
    int serial_ok = X509_set_serialNumber(cert, asn); ASN1_INTEGER_free(asn);
    if (!serial_ok || !X509_set_version(cert, 2)
        || !X509_gmtime_adj(X509_get_notBefore(cert), -60)
        || !X509_gmtime_adj(X509_get_notAfter(cert), 86400)
        || !X509_set_pubkey(cert, key)) goto end;
    X509_NAME *name = X509_get_subject_name(cert);
    if (!X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
            (const unsigned char *)"ob-peer-ephemeral", -1, -1, 0)
        || !X509_set_issuer_name(cert, name) || !X509_sign(cert, key, EVP_sha256())) goto end;
    unsigned int len;
    if (!X509_digest(cert, EVP_sha256(), p->fingerprint, &len) || len != 32
        || write_pem(p->key_path, key, NULL) || write_pem(p->cert_path, NULL, cert)) goto end;
    rc = 0;
end:
    EVP_PKEY_free(key); EVP_PKEY_CTX_free(ctx); X509_free(cert);
    return rc;
}
int ob_resume_key_derive(ob_remote_peer *p)
{
    if (!p->control_managed || !ob_valid_id(p->connection_id)) return 0;
    static const unsigned char info[] = "ob-peer-v2 logical recovery context";
    if (!HKDF(p->fresh_resume_key, sizeof(p->fresh_resume_key), EVP_sha256(),
              p->shared, p->shared_len, (const unsigned char *)p->connection_id,
              strlen(p->connection_id), info, sizeof(info) - 1)) return -1;
    if (!p->resume_key_set) {
        memcpy(p->resume_key, p->fresh_resume_key, sizeof(p->resume_key));
        p->resume_key_set = 1;
    }
    return 0;
}
int ob_resume_proof(ob_remote_peer *p, int sender_server, unsigned char out[32])
{
    if (!p->resume_key_set || !p->session_id || !out ||
        (sender_server != 0 && sender_server != 1)) return -1;
    static const unsigned char label[] = "ob-peer-v2 authenticated reattachment";
    unsigned char generation[8], fresh[32], role = (unsigned char)sender_server;
    uint64_t n = p->control_generation;
    for (int i = 7; i >= 0; --i) { generation[i] = (unsigned char)n; n >>= 8; }
    SHA256(p->shared, p->shared_len, fresh);
    HMAC_CTX ctx; HMAC_CTX_init(&ctx); unsigned int length = 0;
    int ok = HMAC_Init_ex(&ctx, p->resume_key, sizeof(p->resume_key), EVP_sha256(), NULL)
        && HMAC_Update(&ctx, label, sizeof(label))
        && HMAC_Update(&ctx, &role, 1)
        && HMAC_Update(&ctx, (const unsigned char *)p->broker_id, strlen(p->broker_id) + 1)
        && HMAC_Update(&ctx, (const unsigned char *)p->connection_id, strlen(p->connection_id) + 1)
        && HMAC_Update(&ctx, (const unsigned char *)p->session_id, strlen(p->session_id) + 1)
        && HMAC_Update(&ctx, generation, sizeof(generation))
        && HMAC_Update(&ctx, fresh, sizeof(fresh))
        && HMAC_Final(&ctx, out, &length);
    HMAC_CTX_cleanup(&ctx); OPENSSL_cleanse(fresh, sizeof(fresh));
    return ok && length == 32 ? 0 : -1;
}
void ob_certificate_cleanup(ob_remote_peer *p)
{
    if (p->key_path[0]) unlink(p->key_path);
    if (p->cert_path[0]) unlink(p->cert_path);
    if (p->cert_dir[0]) rmdir(p->cert_dir);
}
