#!/usr/bin/env python3
import requests
from typing import Mapping, Union, Optional
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from binascii import hexlify, unhexlify

LOCALHOST = "http://127.0.0.1:5000"
SERVER_PATH = "https://pv080.fi.muni.cz"
SEMINAR_PATH = "s04"

SERVER_MESSAGE_PATH = f"{SERVER_PATH}/{SEMINAR_PATH}/message"
SERVER_KEY_PATH = f"{SERVER_PATH}/{SEMINAR_PATH}/key"


def send_message(uco_from: int, uco_to: int, content: bytes) -> str:
    """
    Sends the `content` to pv080.fi.muni.cz/s04 server, where it is readable by
    anyone on the internet.

    :param uco_from: the UCO of the sender
    :param uco_to: the UCO of the receiver
    :param content: the message encoded in bytes

    :return: the textual status of the result of this API call

    Example:
    >>> send_message(uco_from=123456, uco_to=987654, content=b"message"))
    200
    """
    data = {
        "from": uco_from,
        "to": uco_to,
        "content": hexlify(content).decode(),
    }

    resp = requests.post(
        SERVER_MESSAGE_PATH,
        json=data,
    )

    return resp.json()["status"]


def recv_message(uco: int) -> Mapping[str, Union[int, bytes]]:
    """
    Receive the messages that have been sent to `uco`.

    :param uco: the UCO of the addressee/receiver

    :return: a dictionary where keys are UCO of senders and values are their messages

    Example:
    >>> messages = recv_message(uco=987654)
    >>> messages
    {1234656: b'message', 000000: b'another message'}
    >>> message_from_123456 = messages[123456]
    """
    resp = requests.get(
        SERVER_MESSAGE_PATH,
        params={"uco": uco},
    )

    messages = {}
    if resp.status_code == 200:
        data = resp.json()
        for msg in data:
            # NOTE: at the moment there is only a single message per user
            # so no key collisions - apart from no auth/DoS that was there already
            messages[msg["from"]] = unhexlify(msg["content"])

    return messages


def publish_key(uco: int, key: rsa.RSAPublicKey) -> str:
    """
    Publishes the `key` under the `uco` to pv080.fi.muni.cz/s04 server, where it is
    readable by anyone on the internet.

    :param uco: the UCO of the owner of the key
    :param key: the RSA public key of the owner

    :return: the textual status of the result of this API call

    Example:
    >>> key = private_key.public_key()
    >>> public_key(uco=123456, key=key)
    200
    """
    pem_key = key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    resp = requests.post(
        SERVER_KEY_PATH,
        json={
            "uco": uco,
            "key": hexlify(pem_key).decode(),
        },
    )
    return resp.json()["status"]


def fetch_key(uco: int) -> Optional[rsa.RSAPublicKey]:
    """
    Fetches the public key associated with the `uco` from pv080.fi.muni.cz/s04.

    :param uco: the UCO of the party we want to communicate with

    Example:
    >>> key = fetch_key(uco=123456)
    """
    resp = requests.get(
        SERVER_KEY_PATH,
        params={"uco": uco},
    )
    key: Optional[rsa.RSAPublicKey] = None
    data = resp.json()
    if "key" in data:
        key_bytes = bytes.fromhex(data["key"])
        serialized_key = serialization.load_pem_public_key(key_bytes)
        if isinstance(serialized_key, rsa.RSAPublicKey):
            key = serialized_key

    return key
