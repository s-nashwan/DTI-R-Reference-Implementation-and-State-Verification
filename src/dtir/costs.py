from __future__ import annotations

from .constants import DTI_BYTES, NONCE_BYTES, STATE_BYTES, TAG_BYTES


def communication_costs() -> dict[str, int]:
    far = DTI_BYTES + NONCE_BYTES + TAG_BYTES
    bar = NONCE_BYTES + TAG_BYTES
    aka = DTI_BYTES + TAG_BYTES
    return {
        "far_bytes": far,
        "bar_bytes": bar,
        "aka_bytes": aka,
        "device_transmit_bytes": far + aka,
        "server_transmit_bytes": bar,
        "total_exchange_bytes": far + bar + aka,
    }


def storage_costs() -> dict[str, int]:
    confirmed = STATE_BYTES + DTI_BYTES
    pending_minimum = STATE_BYTES + DTI_BYTES + NONCE_BYTES + NONCE_BYTES
    cached_bar = NONCE_BYTES + TAG_BYTES

    # The reference implementation deliberately keeps derived keys and the
    # exact BAR in the pending object for clarity. This is an implementation
    # payload count, not the protocol minimum used for deployment claims.
    reference_pending_payload = (
        STATE_BYTES       # X_next
        + DTI_BYTES       # DTI_next
        + NONCE_BYTES     # ND
        + NONCE_BYTES     # NS
        + STATE_BYTES     # K_auth
        + STATE_BYTES     # K_sess
        + cached_bar      # exact BAR bytes
    )

    return {
        "device_state_bytes": STATE_BYTES,
        "device_state_plus_nd_bytes": STATE_BYTES + NONCE_BYTES,
        "confirmed_record_bytes": confirmed,
        "minimum_pending_rederivable_bytes": pending_minimum,
        "confirmed_plus_minimum_pending_bytes": confirmed + pending_minimum,
        "confirmed_plus_minimum_pending_plus_cached_bar_bytes": confirmed + pending_minimum + cached_bar,
        "reference_pending_payload_bytes": reference_pending_payload,
        "reference_confirmed_plus_pending_payload_bytes": confirmed + reference_pending_payload,
    }


def operation_counts() -> dict[str, int]:
    """Manuscript-level operation accounting for one new successful exchange.

    Device HMAC count includes generation of the current DTI plus FAR, HKDF
    extract/expand, next-DTI generation, BAR verification, and AKA generation.
    Server count includes FAR verification, HKDF extract/expand, next-DTI
    generation, BAR generation, and AKA verification.
    """
    return {
        "device_hmac_sha256": 9,
        "device_sha256": 1,
        "device_fresh_nonce_128": 1,
        "server_hmac_sha256": 8,
        "server_sha256": 1,
        "server_fresh_nonce_128": 1,
    }
