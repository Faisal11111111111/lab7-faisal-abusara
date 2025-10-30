from unittest import mock
import pytest

from presidio_anonymizer.operators import Encrypt, AESCipher
from presidio_anonymizer.entities import InvalidParamError


# ✅ Task 1: AES encrypt tests
@mock.patch.object(AESCipher, "encrypt")
def test_given_anonymize_then_aes_encrypt_called_and_its_result_is_returned(
    mock_encrypt,
):
    expected_anonymized_text = "encrypted_text"
    mock_encrypt.return_value = expected_anonymized_text

    anonymized_text = Encrypt().operate(text="text", params={"key": "key"})
    assert anonymized_text == expected_anonymized_text


@mock.patch.object(AESCipher, "encrypt")
def test_given_anonymize_with_bytes_key_then_aes_encrypt_result_is_returned(
    mock_encrypt,
):
    expected_anonymized_text = "encrypted_text"
    mock_encrypt.return_value = expected_anonymized_text

    anonymized_text = Encrypt().operate(text="text", params={"key": b"1111111111111111"})
    assert anonymized_text == expected_anonymized_text


# ✅ Task 2: Validation tests
def test_given_verifying_an_valid_length_key_no_exceptions_raised():
    Encrypt().validate(params={"key": "128bitslengthkey"})


def test_given_verifying_an_valid_length_bytes_key_no_exceptions_raised():
    Encrypt().validate(params={"key": b"1111111111111111"})


def test_given_verifying_an_invalid_length_key_then_ipe_raised():
    with pytest.raises(
        InvalidParamError,
        match="Invalid input, key must be of length 128, 192 or 256 bits",
    ):
        Encrypt().validate(params={"key": "key"})


# ✅ Task 3: Mocking invalid bytes key
@mock.patch.object(AESCipher, "is_valid_key_size", return_value=False)
def test_given_verifying_an_invalid_length_bytes_key_then_ipe_raised(mock_is_valid):
    with pytest.raises(
        InvalidParamError,
        match="Invalid input, key must be of length 128, 192 or 256 bits",
    ):
        Encrypt().validate(params={"key": b"1111111111111111"})


# ✅ Task 3: Coverage helpers
def test_operator_name():
    encrypt_instance = Encrypt()
    assert encrypt_instance.operator_name() == "encrypt"  # lowercase


def test_operator_type():
    encrypt_instance = Encrypt()
    from presidio_anonymizer.operators.operator import OperatorType
    assert encrypt_instance.operator_type() == OperatorType.Anonymize


# ✅ Task 4: Parametrized valid key sizes
@pytest.mark.parametrize(
    "key",
    [
        "A" * 16,  # 128-bit string key
        "A" * 24,  # 192-bit string key
        "A" * 32,  # 256-bit string key
        b"A" * 16,  # 128-bit bytes key
        b"A" * 24,  # 192-bit bytes key
        b"A" * 32,  # 256-bit bytes key
    ],
)
def test_valid_keys(key):
    op = Encrypt()
    # Should NOT raise InvalidParamError
    op.validate(params={"key": key})
