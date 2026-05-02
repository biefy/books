# Day 25 — kTLS: in-kernel transport encryption

> **Today's mission:** see how Linux puts AES-GCM into the kernel data path. Total time: ~60 minutes.

![kTLS](diagrams/day25_ktls.png)

## What kTLS does

After the TLS handshake (still in userspace), the application hands the negotiated session keys to the kernel via `setsockopt(TLS_TX/TLS_RX, ...)`. The kernel then handles encryption/decryption inline with the TCP send and receive paths.

Two big wins:

1. **`sendfile()` over TLS**: zero-copy from a file descriptor into a TLS-encrypted stream. Without kTLS, you'd have to read into a userspace buffer, encrypt, then write — defeating sendfile.
2. **Hardware offload**: NICs that support TLS inline (Mellanox, Chelsio) can do AES-GCM right at DMA. CPU sees only plaintext.

## Setup

```c
struct tls12_crypto_info_aes_gcm_128 crypto = {
    .info.version = TLS_1_2_VERSION,
    .info.cipher_type = TLS_CIPHER_AES_GCM_128,
    /* fill in iv, key, salt, rec_seq from your TLS handshake */
};

setsockopt(fd, SOL_TCP, TCP_ULP, "tls", 4);
setsockopt(fd, SOL_TLS, TLS_TX, &crypto, sizeof(crypto));
setsockopt(fd, SOL_TLS, TLS_RX, &crypto, sizeof(crypto));

// now write/read are kTLS-encrypted
```

The `TCP_ULP` ("Upper Layer Protocol") sockopt activates the TLS module on the socket. After that, `TLS_TX/RX` install the keys.

## What to read in the kernel

- **`net/tls/tls_main.c`** — kTLS init, sockopt handlers.
- **`net/tls/tls_sw.c`** — software path (CPU does crypto).
- **`net/tls/tls_device.c`** — hardware offload path.
- **`Documentation/networking/tls.rst`** — official.

## Bullet Points

- kTLS = TLS records produced by the kernel after handshake done in userspace.
- Activated via `TCP_ULP` + `TLS_TX/RX` sockopts.
- Enables zero-copy `sendfile()` for HTTPS.
- Hardware offload via `NETIF_F_HW_TLS_TX/RX`.
- Used by nginx, Netflix's stream servers, and others.

## Check question

Why doesn't Linux just do the TLS handshake in the kernel too?

<details>
<summary>Click to reveal answer</summary>

**Answer:** TLS handshakes involve certificate validation, complex state machines, and (for newer protocols) constantly-evolving key exchange protocols. Putting that in-kernel would balloon the attack surface and require kernel updates with every TLS protocol change. The handshake stays in userspace OpenSSL/etc., where it's well-tested and easy to update; only the steady-state record encryption — which is just AES-GCM streaming — moves into the kernel where the throughput wins.

</details>

## Tomorrow

Day 26: MPTCP.
