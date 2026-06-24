"""Diffie-Hellman helpers for the secure chat application."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import math
import random
import secrets


@dataclass(frozen=True)
class DHParams:
    p: int
    g: int


@dataclass(frozen=True)
class DHKeyPair:
    private: int
    public: int


def modular_exponentiation(base: int, exponent: int, modulo: int) -> int:
    if modulo <= 0:
        raise ValueError("the modulus must be positive")

    result = 1
    base %= modulo
    while exponent > 0:
        if exponent % 2 == 1:
            result = (result * base) % modulo
        base = (base * base) % modulo
        exponent //= 2
    return result


def miller_rabin_test(n: int, rounds: int = 40) -> bool:
    if n < 2:
        return False
    if n in (2, 3):
        return True
    if n % 2 == 0:
        return False

    d = n - 1
    s = 0
    while d % 2 == 0:
        d //= 2
        s += 1

    for _ in range(rounds):
        a = random.randrange(2, n - 1)
        x = modular_exponentiation(a, d, n)
        if x == 1 or x == n - 1:
            continue

        is_composite = True
        for _ in range(s - 1):
            x = modular_exponentiation(x, 2, n)
            if x == n - 1:
                is_composite = False
                break

        if is_composite:
            return False

    return True


def generate_prime(bits: int = 32, rounds: int = 40) -> int:
    if bits < 16:
        raise ValueError("use at least 16 bits")

    while True:
        candidate = random.getrandbits(bits)
        if candidate < 2 ** (bits - 1):
            candidate += 2 ** (bits - 1)
        if candidate % 2 == 0:
            candidate += 1

        if miller_rabin_test(candidate, rounds=rounds):
            return candidate


def prime_factorization(n: int) -> set[int]:
    factors: set[int] = set()
    while n % 2 == 0:
        factors.add(2)
        n //= 2

    factor = 3
    limit = int(math.isqrt(n))
    while factor <= limit and n > 1:
        while n % factor == 0:
            factors.add(factor)
            n //= factor
            limit = int(math.isqrt(n))
        factor += 2

    if n > 1:
        factors.add(n)

    return factors


def find_primitive_root(p: int) -> int:
    if p <= 2:
        raise ValueError("p must be greater than 2")

    factors = prime_factorization(p - 1)
    for g in range(2, p):
        valid = True
        for q in factors:
            if modular_exponentiation(g, (p - 1) // q, p) == 1:
                valid = False
                break
        if valid:
            return g

    raise ValueError("unable to find a primitive root")


def generate_parameters(bits: int = 32) -> DHParams:
    p = generate_prime(bits=bits)
    g = find_primitive_root(p)
    return DHParams(p=p, g=g)


def generate_keypair(params: DHParams) -> DHKeyPair:
    private = secrets.randbelow(params.p - 3) + 2
    public = modular_exponentiation(params.g, private, params.p)
    return DHKeyPair(private=private, public=public)


def derive_shared_secret(private: int, peer_public: int, params: DHParams) -> int:
    return modular_exponentiation(peer_public, private, params.p)


def shared_secret_to_key(shared_secret: int, channel_id: str) -> bytes:
    secret_bytes = shared_secret.to_bytes(max(1, (shared_secret.bit_length() + 7) // 8), "big")
    return hashlib.sha256(secret_bytes + channel_id.encode("utf-8")).digest()[:16]
