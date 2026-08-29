from dtir.crypto import aka_tag, bar_tag, derive_schedule, far_tag, generate_dti

ID = b"device-0001"
X = bytes(range(32))
ND = bytes(range(16))
NS = bytes(range(16, 32))


def test_dti_is_deterministic_16_bytes_and_changes_with_state():
    dti1 = generate_dti(ID, X)
    dti2 = generate_dti(ID, X)
    dti3 = generate_dti(ID, bytes(reversed(X)))
    assert dti1 == dti2
    assert len(dti1) == 16
    assert dti1 != dti3


def test_key_schedule_is_three_32_byte_fields():
    dti = generate_dti(ID, X)
    schedule = derive_schedule(X, dti, ND, NS)
    assert len(schedule.x_next) == 32
    assert len(schedule.k_auth) == 32
    assert len(schedule.k_sess) == 32
    assert schedule.okm == schedule.x_next + schedule.k_auth + schedule.k_sess
    assert len(schedule.okm) == 96


def test_protocol_tags_are_16_bytes_and_domain_separated():
    dti = generate_dti(ID, X)
    schedule = derive_schedule(X, dti, ND, NS)
    dti_next = generate_dti(ID, schedule.x_next)
    td = far_tag(X, dti, ND)
    ts = bar_tag(schedule.k_auth, dti, dti_next, ND, NS)
    ta = aka_tag(schedule.k_auth, dti, dti_next, ND, NS)
    assert len(td) == len(ts) == len(ta) == 16
    assert ts != ta
