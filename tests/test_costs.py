from dtir.costs import communication_costs, operation_counts, storage_costs


def test_communication_costs_match_wire_format():
    costs = communication_costs()
    assert costs == {
        "far_bytes": 48,
        "bar_bytes": 32,
        "aka_bytes": 32,
        "device_transmit_bytes": 80,
        "server_transmit_bytes": 32,
        "total_exchange_bytes": 112,
    }


def test_protocol_storage_costs_match_manuscript_minimums():
    costs = storage_costs()
    assert costs["device_state_bytes"] == 32
    assert costs["device_state_plus_nd_bytes"] == 48
    assert costs["confirmed_record_bytes"] == 48
    assert costs["minimum_pending_rederivable_bytes"] == 80
    assert costs["confirmed_plus_minimum_pending_bytes"] == 128
    assert costs["confirmed_plus_minimum_pending_plus_cached_bar_bytes"] == 160


def test_cryptographic_operation_counts_match_manuscript_accounting():
    counts = operation_counts()
    assert counts["device_hmac_sha256"] == 9
    assert counts["device_sha256"] == 1
    assert counts["device_fresh_nonce_128"] == 1
    assert counts["server_hmac_sha256"] == 8
    assert counts["server_sha256"] == 1
    assert counts["server_fresh_nonce_128"] == 1
