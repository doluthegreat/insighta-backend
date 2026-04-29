"""
Basic unit tests for utility functions and auth helpers.
Integration tests require a live DB and GitHub credentials.
"""
import pytest
from utils import age_to_group, COUNTRY_NAME_TO_ID, VALID_GENDERS, VALID_AGE_GROUPS, VALID_SORT_COLS
from auth import compute_code_challenge, hash_token, new_refresh_token


# ─── utils.py ─────────────────────────────────────────────────────────────────
class TestAgeToGroup:
    def test_child(self):
        assert age_to_group(5)  == "child"
        assert age_to_group(12) == "child"

    def test_teenager(self):
        assert age_to_group(13) == "teenager"
        assert age_to_group(19) == "teenager"

    def test_adult(self):
        assert age_to_group(20) == "adult"
        assert age_to_group(59) == "adult"

    def test_senior(self):
        assert age_to_group(60) == "senior"
        assert age_to_group(90) == "senior"


class TestCountryMapping:
    def test_nigeria(self):
        assert COUNTRY_NAME_TO_ID["nigeria"] == "NG"

    def test_usa_alias(self):
        assert COUNTRY_NAME_TO_ID["usa"] == "US"

    def test_uk_alias(self):
        assert COUNTRY_NAME_TO_ID["uk"] == "GB"


class TestConstants:
    def test_valid_genders(self):
        assert "male" in VALID_GENDERS
        assert "female" in VALID_GENDERS

    def test_valid_age_groups(self):
        for g in ("child", "teenager", "adult", "senior"):
            assert g in VALID_AGE_GROUPS

    def test_valid_sort_cols(self):
        for col in ("age", "created_at", "gender_probability"):
            assert col in VALID_SORT_COLS


# ─── auth.py ──────────────────────────────────────────────────────────────────
class TestPKCE:
    def test_challenge_deterministic(self):
        verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
        # Same verifier always produces same challenge
        assert compute_code_challenge(verifier) == compute_code_challenge(verifier)

    def test_challenge_differs_from_verifier(self):
        verifier = "some-random-verifier-value-here-long-enough"
        assert compute_code_challenge(verifier) != verifier

    def test_challenge_base64url_safe(self):
        verifier  = "test-verifier-string-for-pkce-flow-abc-123"
        challenge = compute_code_challenge(verifier)
        # Must not contain +, /, or =
        assert "+" not in challenge
        assert "/" not in challenge
        assert "=" not in challenge


class TestTokenHelpers:
    def test_hash_token_deterministic(self):
        tok = new_refresh_token()
        assert hash_token(tok) == hash_token(tok)

    def test_hash_token_different_inputs(self):
        assert hash_token("aaa") != hash_token("bbb")

    def test_new_refresh_token_unique(self):
        tokens = {new_refresh_token() for _ in range(20)}
        assert len(tokens) == 20
