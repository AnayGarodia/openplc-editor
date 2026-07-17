/*
license_blob.h - On-device license blob binary layout (OLS-01, OLS-03)
Copyright (C) 2022 OpenPLC - Thiago Alves

Materialization of lic_payload_t / lic_blob_t (see hardware-licensing design).
Shared by every storage backend (AVR EEPROM, ESP32 NVS) and by the Modbus
license handlers. Layout is PACKED and LITTLE-ENDIAN for every multi-byte field
of the struct (magic). This is INDEPENDENT of the Modbus wire, which carries the
transfer `len` in BIG-ENDIAN (see modbus_pdu.cpp / modbus_debug.cpp).

    ENDIANNESS DUALITY (risk #1): blob CONTENT is LITTLE-ENDIAN; the Modbus wire
    `len` field is BIG-ENDIAN. Do not confuse the two.

AUTHENTICATION (fmt_version 2, HMAC): the blob is authenticated by an
HMAC-SHA256 tag over the 30-byte payload, truncated to 16 bytes, keyed by the
per-VPP secret selected by key_id. This SUPERSEDES the fmt_version 1 layout
(ECDSA P-256 signature + CRC-32): the tag both authenticates and detects
corruption, so no separate CRC is stored.
*/

#ifndef LICENSE_BLOB_H
#define LICENSE_BLOB_H

#include <stddef.h>
#include <stdint.h>

// Byte layout (packed, contiguous — no padding):
//  off  field         type          size  notes
//   0   magic         uint32_t LE    4    'OPLC' -> bytes 4F 50 4C 43 (LE u32 = 0x434C504F)
//   4   fmt_version   uint8_t        1    2 = HMAC layout
//   5   key_id        uint8_t        1    signing-key id (rotation)
//   6   device_id     uint8_t[16]   16
//  22   product_id    uint8_t[8]     8    vpp id
//  30   (end of authenticated payload — payload = 30 bytes)
//  30   tag           uint8_t[16]   16    HMAC-SHA256(K, payload)[:16]
//  46   (end of blob — sizeof(lic_blob_t) == 46)

#pragma pack(push, 1)
typedef struct {
    uint32_t magic;          // 'OPLC' -> bytes 4F 50 4C 43 (LE u32 = 0x434C504F)
    uint8_t  fmt_version;
    uint8_t  key_id;         // signing-key id (rotation)
    uint8_t  device_id[16];
    uint8_t  product_id[8];  // vpp id
} lic_payload_t;             // 30 bytes

typedef struct __attribute__((packed)) {
    lic_payload_t payload;   // offsets 0..29
    uint8_t  tag[16];        // offsets 30..45 (HMAC-SHA256(K, payload)[:16])
} lic_blob_t;                // 46 bytes
#pragma pack(pop)

// Belt-and-suspenders: both #pragma pack and __attribute__((packed)) so AVR-GCC
// and xtensa-GCC (which treat the two differently) both drop the padding.

#define LIC_MAGIC_LE      0x434C504Fu   /* bytes 4F 50 4C 43 */
#define LIC_FMT_VERSION   2u            /* HMAC layout */
#define LIC_BLOB_SIZE     46u
#define LIC_PAYLOAD_SIZE  30u
#define LIC_TAG_SIZE      16u

// Portable compile-time assert. Every Baremetal .cpp includes this header, so it
// is compiled as C++, where static_assert is a keyword. _Static_assert is C-only
// (C11) and the C++ frontend (xtensa/avr gcc) rejects it. Keep the C form for the
// host golden test, which compiles this header as C11.
#if defined(__cplusplus)
    #define LIC_STATIC_ASSERT(cond, msg) static_assert(cond, msg)
#else
    #define LIC_STATIC_ASSERT(cond, msg) _Static_assert(cond, msg)
#endif

LIC_STATIC_ASSERT(sizeof(lic_payload_t) == 30, "lic_payload_t must be 30 bytes");
LIC_STATIC_ASSERT(sizeof(lic_blob_t)    == 46, "lic_blob_t must be 46 bytes");

#endif
