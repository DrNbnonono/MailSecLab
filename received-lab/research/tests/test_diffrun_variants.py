import sys

sys.path.insert(0, "/mnt/e/MailSecLab/received-lab")

from research.lib.diffrun import VARIANTS, build_raw, variant_name


def test_eight_variants_present():
    assert set(VARIANTS) == {
        "v00-plain", "v01-obs-colon", "v02-case", "v03-nocolon",
        "v04-8bit-name", "v05-cfws-name", "v06-comment-name", "v07-tab-name",
    }


def test_build_raw_shape_and_check():
    raw = build_raw(VARIANTS["v01-obs-colon"], n=3, case_id="t-obs-3")
    # 首条 Received 在偏移 0，前面没有 CRLF——按行本体计数。
    assert raw.count(b"Received : from ") == 3
    assert b"X-Case-ID: t-obs-3" in raw
    head = raw.split(b"\r\n\r\n", 1)[0]
    assert not head.endswith(b"\r\n")  # 无双 CRLF 伪影


def test_variant_name_is_stable():
    assert variant_name("v01-obs-colon", "osmtpd", "capture") == "v01-obs-colon__osmtpd__capture"
