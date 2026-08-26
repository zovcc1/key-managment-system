"""i18n: Accept-Language negotiation, catalog parity, and that every
error/threat-model key referenced elsewhere in the codebase actually
resolves in both locales."""
from __future__ import annotations

import re

import pytest

from keyring.core import errors as errors_module
from keyring.core.threat_model import _BOUNDARY_KEYS
from keyring.i18n import negotiate_locale, t
from keyring.i18n.translate import SUPPORTED, _catalogs


# --- negotiate_locale ------------------------------------------------------

def test_negotiate_locale_none_defaults_to_en():
    assert negotiate_locale(None) == "en"


def test_negotiate_locale_empty_string_defaults_to_en():
    assert negotiate_locale("") == "en"


def test_negotiate_locale_plain_ar():
    assert negotiate_locale("ar") == "ar"


def test_negotiate_locale_plain_en():
    assert negotiate_locale("en") == "en"


def test_negotiate_locale_region_subtag_is_truncated_to_language():
    assert negotiate_locale("ar-EG") == "ar"
    assert negotiate_locale("en-US") == "en"


def test_negotiate_locale_is_case_insensitive():
    assert negotiate_locale("AR") == "ar"
    assert negotiate_locale("EN-us") == "en"


def test_negotiate_locale_with_q_values_picks_first_supported_in_order():
    # Accept-Language does not require the browser to sort by q for us to
    # honour order-of-appearance among values we support.
    assert negotiate_locale("fr;q=0.9, ar;q=0.8") == "ar"


def test_negotiate_locale_unsupported_language_falls_back_to_en():
    assert negotiate_locale("fr-FR, de;q=0.5") == "en"


def test_negotiate_locale_unsupported_then_supported_picks_supported():
    assert negotiate_locale("fr, en;q=0.5") == "en"


def test_negotiate_locale_malformed_value_does_not_raise():
    assert negotiate_locale(",,,;q=") == "en"


# --- catalogs ----------------------------------------------------------

def test_supported_locales_are_en_and_ar():
    assert set(SUPPORTED) == {"en", "ar"}


def test_catalogs_have_identical_key_sets():
    assert set(_catalogs["en"].keys()) == set(_catalogs["ar"].keys())


def test_catalogs_are_nonempty():
    assert len(_catalogs["en"]) > 0
    assert len(_catalogs["ar"]) > 0


def test_t_returns_string_for_every_key_in_both_locales():
    for key in _catalogs["en"]:
        for locale in SUPPORTED:
            value = t(key, locale)
            assert isinstance(value, str) and value


def test_t_unknown_key_raises_key_error():
    with pytest.raises(KeyError):
        t("this.key.does.not.exist", "en")


def test_t_unknown_locale_falls_back_to_en_catalog():
    assert t("error.generic", "xx") == t("error.generic", "en")


# --- cross-module key usage --------------------------------------------

def test_every_error_message_key_resolves_in_both_locales():
    """Every KeyringError subclass in core/errors.py must reference a key
    that actually exists in both catalogs — a typo here would only surface
    at runtime, on the exact request that triggers that specific error."""
    for name in dir(errors_module):
        obj = getattr(errors_module, name)
        if (
            isinstance(obj, type)
            and issubclass(obj, errors_module.KeyringError)
            and obj is not errors_module.KeyringError
        ):
            key = obj.message_key
            for locale in SUPPORTED:
                assert t(key, locale)


def test_threat_model_boundary_keys_resolve_in_both_locales():
    for key in _BOUNDARY_KEYS:
        for locale in SUPPORTED:
            assert t(key, locale)


def test_no_leftover_format_placeholder_after_formatting_with_params():
    """format() leaves a literal '{name}' in the output only if the
    catalog string references a param the caller never supplied — this
    would silently leak `{param}` straight into a response to a client."""
    placeholder = re.compile(r"\{[a-zA-Z_][a-zA-Z0-9_]*\}")
    for locale in SUPPORTED:
        for key, raw in _catalogs[locale].items():
            names = placeholder.findall(raw)
            if not names:
                continue
            params = {n.strip("{}"): "x" for n in names}
            formatted = t(key, locale, **params)
            assert not placeholder.search(formatted), f"{locale}:{key} left an unformatted placeholder"
