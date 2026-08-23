# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import os
import pathlib

import pytest

import ovstorage
import ovstorage.ovstorage as _native
from ovstorage.file import FileBackend


TCP_GOLDEN = bytes(
    [
        2,
        2, 0, 0, 0, ord("A"), ord("B"),
        0,
        3, 0, 0, 0, ord("h"), ord(":"), ord("1"),
        2, 0, 0, 0, 0xDE, 0xAD,
        0, 0, 0, 0,
    ]
)

UDS_GOLDEN = bytes(
    [
        2,
        0, 0, 0, 0,
        1,
        7, 0, 0, 0,
        8, 0, 0, 0,
        0xFE, 0xFF, 0xFF, 0xFF,
        0, 0, 0, 0,
    ]
)

NAMED_PIPE_GOLDEN = bytes(
    [
        2,
        0, 0, 0, 0,
        2,
        3, 0, 0, 0, ord("S"), ord("-"), ord("1"),
        5, 0, 0, 0,
        0, 0, 0, 0,
    ]
)

FORWARDED_GOLDEN = bytes(
    [
        2,
        0, 0, 0, 0,
        0,
        3, 0, 0, 0, ord("h"), ord(":"), ord("1"),
        0, 0, 0, 0,
        2, 0, 0, 0,
        3, 0, 0, 0, ord("x"), ord("-"), ord("u"),
        5, 0, 0, 0, ord("a"), ord("l"), ord("i"), ord("c"), ord("e"),
        3, 0, 0, 0, ord("x"), ord("-"), ord("t"),
        3, 0, 0, 0, ord("a"), ord("r"), ord("t"),
    ]
)

LEGACY_V1_GOLDEN = bytes(
    [
        1,
        0, 0, 0, 0,
        1,
        7, 0, 0, 0,
        8, 0, 0, 0,
        9, 0, 0, 0,
    ]
)


def test_decode_tcp_golden() -> None:
    credential = ovstorage.AuthCredential.decode(TCP_GOLDEN)

    assert credential.bearer == b"AB"
    assert credential.forwarded is None
    assert isinstance(credential.transport, ovstorage.TcpTransport)
    assert credential.transport.peer_addr == "h:1"
    assert credential.transport.tls_client_cert == bytes([0xDE, 0xAD])


def test_decode_uds_golden_with_negative_pid() -> None:
    credential = ovstorage.AuthCredential.decode(UDS_GOLDEN)

    assert credential.bearer is None
    assert isinstance(credential.transport, ovstorage.UdsTransport)
    assert (credential.transport.uid, credential.transport.gid) == (7, 8)
    assert credential.transport.pid == -2


def test_decode_named_pipe_golden() -> None:
    credential = ovstorage.AuthCredential.decode(NAMED_PIPE_GOLDEN)

    assert isinstance(credential.transport, ovstorage.NamedPipeTransport)
    assert credential.transport.sid == "S-1"
    assert credential.transport.pid == 5


def test_decode_forwarded_headers_golden() -> None:
    credential = ovstorage.AuthCredential.decode(FORWARDED_GOLDEN)

    assert credential.forwarded == [("x-u", "alice"), ("x-t", "art")]


def test_decode_legacy_v1_without_forwarded_tail() -> None:
    credential = ovstorage.AuthCredential.decode(LEGACY_V1_GOLDEN)

    assert isinstance(credential.transport, ovstorage.UdsTransport)
    assert credential.transport.pid == 9
    assert credential.forwarded is None


@pytest.mark.parametrize(
    ("payload", "message"),
    [
        (b"", "truncated buffer"),
        (bytes([99]), "unsupported wire version"),
        (bytes([1, 0, 0, 0, 0, 7]), "bad transport tag"),
        (
            bytes([1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0xFF]),
            "invalid utf-8 in string field",
        ),
        (LEGACY_V1_GOLDEN + b"junk", "trailing data after credential"),
    ],
)
def test_decode_errors_are_value_errors(payload: bytes, message: str) -> None:
    with pytest.raises(ValueError, match=f"^{message}$"):
        ovstorage.AuthCredential.decode(payload)


def test_repr_redacts_bearer_bytes() -> None:
    rendered = repr(ovstorage.AuthCredential.decode(TCP_GOLDEN))

    assert rendered == (
        "AuthCredential(bearer=Some(<redacted; 2 bytes>), "
        "transport=Tcp(tls_client_cert=2 bytes), forwarded_headers=0)"
    )
    for leaked_form in ("AB", "[65, 66]", "41 42", "4142", "h:1", "DEAD"):
        assert leaked_form not in rendered


@pytest.mark.parametrize(
    ("payload", "expected"),
    [
        (
            UDS_GOLDEN,
            "AuthCredential(bearer=None, transport=Uds, forwarded_headers=0)",
        ),
        (
            NAMED_PIPE_GOLDEN,
            "AuthCredential(bearer=None, transport=NamedPipe, forwarded_headers=0)",
        ),
    ],
)
def test_repr_omits_transport_identity(payload: bytes, expected: str) -> None:
    assert repr(ovstorage.AuthCredential.decode(payload)) == expected


def test_well_known_extension_key_constants() -> None:
    assert ovstorage.EXT_AUTH_CREDENTIAL == "org.omniverse.ovstorage/auth-credential@1"
    assert ovstorage.EXT_PRINCIPAL_ID == "org.omniverse.ovstorage/principal@1"
    assert (
        ovstorage.EXT_PRINCIPAL_DISPLAY_NAME
        == "org.omniverse.ovstorage/principal-display-name@1"
    )
    assert ovstorage.ANONYMOUS_PRINCIPAL_ID == "anonymous"


@pytest.mark.asyncio
async def test_python_authored_wrapper_decodes_stamped_credential(
    tmp_path: pathlib.Path,
) -> None:
    probe = getattr(_native, "_probe_stat_with_auth_credential", None)
    if probe is None:
        if os.environ.get("OVSTORAGE_REQUIRE_TEST_PLUGINS") == "1":
            pytest.fail(
                "OVSTORAGE_REQUIRE_TEST_PLUGINS=1 but the extension was built "
                "without the test-probes feature"
            )
        pytest.skip("extension built without the test-probes feature")

    class CredentialDecodingWrapper(ovstorage.LayerBase):
        async def stat(
            self,
            address: str,
            full_metadata: bool = False,
            *,
            extensions: dict[str, bytes],
        ) -> object:
            credential = ovstorage.AuthCredential.decode(
                extensions[ovstorage.EXT_AUTH_CREDENTIAL]
            )
            assert isinstance(credential.transport, ovstorage.UdsTransport)
            self.observed_transport = (
                credential.transport.uid,
                credential.transport.gid,
                credential.transport.pid,
            )
            return await super().stat(address, full_metadata=full_metadata)

    root = tmp_path / "auth-extension-root"
    root.mkdir()
    object_path = root / "object.bin"
    object_path.write_bytes(b"credential bridge")
    connection = ovstorage.ConnectionRequest("file")
    connection.add_config("root", ovstorage.ConfigValue.string(str(root)))
    wrapper = CredentialDecodingWrapper(
        name="credential-decoder",
        layer_type="wrapper",
        inner="files",
    )
    wrapper.observed_transport = None
    stack = await (
        ovstorage.Stack(root="credential-decoder")
        .wrapper(wrapper)
        .backend(FileBackend("files"))
        .connection("files", connection)
        .build()
    )

    info = await probe(stack, object_path.as_uri(), UDS_GOLDEN)

    assert info.size == len(b"credential bridge")
    assert wrapper.observed_transport == (7, 8, -2)
