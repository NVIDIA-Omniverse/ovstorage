/* SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Shared length-aware UTF-8 validation for private runtime inputs.
 */

#include "internal.h"

bool ovc_utf8_is_valid(const void *value, size_t length)
{
    const uint8_t *bytes;
    size_t index;

    if (value == NULL) {
        return length == 0;
    }
    bytes = (const uint8_t *)value;
    index = 0;
    while (index < length) {
        uint8_t first;

        first = bytes[index];
        if (first <= 0x7fu) {
            ++index;
            continue;
        }
        if (first >= 0xc2u && first <= 0xdfu) {
            if (length - index < 2 || bytes[index + 1] < 0x80u ||
                bytes[index + 1] > 0xbfu) {
                return false;
            }
            index += 2;
            continue;
        }
        if (first == 0xe0u) {
            if (length - index < 3 || bytes[index + 1] < 0xa0u ||
                bytes[index + 1] > 0xbfu || bytes[index + 2] < 0x80u ||
                bytes[index + 2] > 0xbfu) {
                return false;
            }
            index += 3;
            continue;
        }
        if ((first >= 0xe1u && first <= 0xecu) ||
            (first >= 0xeeu && first <= 0xefu)) {
            if (length - index < 3 || bytes[index + 1] < 0x80u ||
                bytes[index + 1] > 0xbfu || bytes[index + 2] < 0x80u ||
                bytes[index + 2] > 0xbfu) {
                return false;
            }
            index += 3;
            continue;
        }
        if (first == 0xedu) {
            if (length - index < 3 || bytes[index + 1] < 0x80u ||
                bytes[index + 1] > 0x9fu || bytes[index + 2] < 0x80u ||
                bytes[index + 2] > 0xbfu) {
                return false;
            }
            index += 3;
            continue;
        }
        if (first == 0xf0u) {
            if (length - index < 4 || bytes[index + 1] < 0x90u ||
                bytes[index + 1] > 0xbfu || bytes[index + 2] < 0x80u ||
                bytes[index + 2] > 0xbfu || bytes[index + 3] < 0x80u ||
                bytes[index + 3] > 0xbfu) {
                return false;
            }
            index += 4;
            continue;
        }
        if (first >= 0xf1u && first <= 0xf3u) {
            if (length - index < 4 || bytes[index + 1] < 0x80u ||
                bytes[index + 1] > 0xbfu || bytes[index + 2] < 0x80u ||
                bytes[index + 2] > 0xbfu || bytes[index + 3] < 0x80u ||
                bytes[index + 3] > 0xbfu) {
                return false;
            }
            index += 4;
            continue;
        }
        if (first == 0xf4u) {
            if (length - index < 4 || bytes[index + 1] < 0x80u ||
                bytes[index + 1] > 0x8fu || bytes[index + 2] < 0x80u ||
                bytes[index + 2] > 0xbfu || bytes[index + 3] < 0x80u ||
                bytes[index + 3] > 0xbfu) {
                return false;
            }
            index += 4;
            continue;
        }
        return false;
    }
    return true;
}
