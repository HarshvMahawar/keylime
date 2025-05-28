# # def build_keylime_submod(agent_data, attestation_data, runtime_policy_data) -> Submod:
# #     status_str = attestation_data.get("status", "Fail")
# #     results = attestation_data.get("results", {})
# #     quote = results.get("quote", "")
# #     ak_tpm = agent_data.get("ak_tpm", "")
# #     ima_pcrs = agent_data.get("ima_pcrs", [])
# #     pcr10 = agent_data.get("pcr10", "")
# #     runtime_policy_valid = runtime_policy_data is not None and runtime_policy_data != {}

# #     if status_str == "Success":
# #         submod_status = TrustTier.AFFIRMING
# #     elif not quote or attestation_data.get("code") == 500:
# #         submod_status = TrustTier.CONTRAINDICATED
# #     else:
# #         submod_status = TrustTier.WARNING

# #     tv = TrustVector()

# #     # instance_identity
# #     if ak_tpm and quote:
# #         tv.instance_identity = TRUSTWORTHY_INSTANCE_CLAIM
# #     elif not ak_tpm:
# #         tv.instance_identity = UNTRUSTWORTHY_INSTANCE_CLAIM
# #     else:
# #         tv.instance_identity = UNRECOGNIZED_INSTANCE_CLAIM

# #     # hardware
# #     if quote and status_str == "Success":
# #         tv.hardware = GENUINE_HARDWARE_CLAIM
# #     elif status_str == "Fail":
# #         tv.hardware = CONTRAINDICATED_HARDWARE_CLAIM
# #     else:
# #         tv.hardware = UNSAFE_HARDWARE_CLAIM

# #     # executables (IMA)
# #     if ima_pcrs or pcr10:
# #         if status_str == "Success":
# #             tv.executables = APPROVED_RUNTIME_CLAIM
# #         else:
# #             tv.executables = UNSAFE_RUNTIME_CLAIM
# #     else:
# #         tv.executables = UNRECOGNIZED_RUNTIME_CLAIM

# #     # configuration (runtime policy)
# #     if runtime_policy_valid:
# #         tv.configuration = APPROVED_CONFIG_CLAIM
# #     elif runtime_policy_data is None:
# #         tv.configuration = UNSUPPORTABLE_CONFIG_CLAIM
# #     else:
# #         tv.configuration = UNSAFE_CONFIG_CLAIM

# #     return Submod(
# #         status=submod_status,
# #         trust_vector=tv
# #     )


# # from keylime.verifier import cloud_verifier_common

# # def build_keylime_submod(agent_data, attestation_data, runtime_policy_data) -> Submod:
# #     quote = attestation_data["results"]["quote"]
# #     pubkey = attestation_data["results"]["pubkey"]
# #     ak_tpm = agent_data["ak_tpm"]
# #     nonce = agent_data["nonce"]
# #     tpm_policy = ast.literal_eval(agent_data["tpm_policy"])
# #     ima_ml = attestation_data["results"].get("ima_measurement_list")
# #     mb_log = attestation_data["results"].get("mb_measurement_list")
# #     hash_alg = attestation_data["results"]["hash_alg"]

# #     # Use the actual TPM logic to validate
# #     failure = get_tpm_instance().check_quote(
# #         agentAttestState=AgentAttestState(),
# #         nonce=nonce,
# #         public_key=pubkey,
# #         quote=quote,
# #         aik=ak_tpm,
# #         tpm_policy=tpm_policy,
# #         ima_measurement_list=ima_ml,
# #         runtime_policy=runtime_policy_data,
# #         hash_alg=algorithms.Hash(hash_alg),
# #         ima_keyrings=...,   # build from runtime_policy_data
# #         mb_measurement_list=mb_log,
# #         mb_refstate=None,
# #     )

# #     tv = TrustVector()
# #     if not failure:
# #         tv.instance_identity = TRUSTWORTHY_INSTANCE_CLAIM
# #         tv.hardware = GENUINE_HARDWARE_CLAIM
# #         tv.executables = APPROVED_RUNTIME_CLAIM
# #         tv.configuration = APPROVED_CONFIG_CLAIM
# #         submod_status = TrustTier.AFFIRMING
# #     else:
# #         # Use details in `failure.events` to decide further
# #         tv.instance_identity = UNRECOGNIZED_INSTANCE_CLAIM
# #         tv.hardware = CONTRAINDICATED_HARDWARE_CLAIM
# #         ...
# #         submod_status = TrustTier.WARNING  # or CONTRAINDICATED

# #     return Submod(status=submod_status, trust_vector=tv)

# import ast
# from keylime import cloud_verifier_common
# from keylime.tpm.tpm_main import get_tpm_instance
# from keylime.ima.keyrings import ImaKeyring
# from keylime.tpm.tpm_abstract import TPM_Utilities
# from keylime.agentstates import AgentAttestState
# from keylime import algorithms

# # ----------------------------
# # Mock TRUST CLAIM Constants
# # ----------------------------
# TRUST_CLAIMS = {
#     "TRUSTWORTHY_INSTANCE": 2,
#     "UNRECOGNIZED_INSTANCE": 97,
#     "GENUINE_HARDWARE": 2,
#     "CONTRAINDICATED_HARDWARE": 96,
#     "APPROVED_RUNTIME": 2,
#     "UNRECOGNIZED_RUNTIME": 33,
#     "APPROVED_CONFIG": 2,
#     "UNSUPPORTABLE_CONFIG": 96
# }

# TRUST_TIERS = {
#     "AFFIRMING": "affirming",
#     "WARNING": "warning",
#     "CONTRAINDICATED": "contraindicated"
# }

# # ----------------------------
# # Function to build EAR submod
# # ----------------------------
# def build_keylime_submod(agent_data, attestation_data, runtime_policy_data):
#     results = attestation_data.get("results", {})
#     quote = results.get("quote")
#     pubkey = results.get("pubkey")
#     ak_tpm = agent_data.get("ak_tpm")
#     nonce = agent_data.get("nonce")
#     hash_alg = results.get("hash_alg")
#     ima_ml = results.get("ima_measurement_list", None)
#     mb_log = results.get("mb_measurement_list", None)
#     tpm_policy = ast.literal_eval(agent_data.get("tpm_policy", "{}"))
#     runtime_policy = runtime_policy_data or {}

#     # Create ImaKeyring object from policy string (if any)
#     verification_key_string = runtime_policy.get("verification-keys", "")
#     tenant_keyring = ImaKeyring.from_string(verification_key_string)
#     ima_keyrings = TPM_Utilities.get_ima_keyrings()
#     ima_keyrings.set_tenant_keyring(tenant_keyring)

#     agent_attest_state = AgentAttestState()

#     failure = get_tpm_instance().check_quote(
#         agentAttestState=agent_attest_state,
#         nonce=nonce,
#         public_key=pubkey,
#         quote=quote,
#         aik=ak_tpm,
#         tpm_policy=tpm_policy,
#         ima_measurement_list=ima_ml,
#         runtime_policy=runtime_policy,
#         hash_alg=algorithms.Hash(hash_alg),
#         ima_keyrings=ima_keyrings,
#         mb_measurement_list=mb_log,
#         mb_refstate=None,
#         count=agent_data.get("attestation_count", 0),
#         compressed=False,
#     )

#     trust_vector = {
#         "instance_identity": TRUST_CLAIMS["UNRECOGNIZED_INSTANCE"],
#         "hardware": TRUST_CLAIMS["CONTRAINDICATED_HARDWARE"],
#         "executables": TRUST_CLAIMS["UNRECOGNIZED_RUNTIME"],
#         "configuration": TRUST_CLAIMS["UNSUPPORTABLE_CONFIG"]
#     }

#     if not failure:
#         trust_vector.update({
#             "instance_identity": TRUST_CLAIMS["TRUSTWORTHY_INSTANCE"],
#             "hardware": TRUST_CLAIMS["GENUINE_HARDWARE"],
#             "executables": TRUST_CLAIMS["APPROVED_RUNTIME"],
#             "configuration": TRUST_CLAIMS["APPROVED_CONFIG"]
#         })
#         status = TRUST_TIERS["AFFIRMING"]
#     else:
#         status = TRUST_TIERS["WARNING"]  # You can inspect `failure.events` to refine

#     return {
#         "status": status,
#         "trust_vector": trust_vector,
#         "failure_events": failure.events
#     }

# # ----------------------------
# # Sample Test Input
# # ----------------------------
# sample_input = {
#     "agent_data": {
#         "v": "TSsIA2PyJ3q8MMvrdhRY7v/7PUhSUUkqL4nsY54ieMc=",
#         "ip": "127.0.0.1",
#         "port": 9002,
#         "operational_state": 3,
#         "public_key": "",
#         "tpm_policy": "{\"mask\": \"0x400\"}",
#         "meta_data": "{}",
#         "ima_sign_verification_keys": "",
#         "revocation_key": "",
#         "accept_tpm_hash_algs": ["sha512", "sha384", "sha256"],
#         "accept_tpm_encryption_algs": ["ecc", "rsa"],
#         "accept_tpm_signing_algs": ["ecschnorr", "rsassa"],
#         "supported_version": "2.2",
#         "ak_tpm": "ARgAAQALAAUAc...VAD1/sMFNh6X+Kwi/dyncQolor2r",
#         "mtls_cert": "-----BEGIN CERTIFICATE-----\nMIIDGzCCAgOgAwIBAgIBADANBgkqhkiG9...==\n-----END CERTIFICATE-----\n",
#         "hash_alg": "",
#         "enc_alg": "",
#         "sign_alg": "",
#         "agent_id": "d432fbb3-d2f1-4a97-9ef7-75bd81c00000",
#         "boottime": "",
#         "ima_pcrs": [],
#         "pcr10": "",
#         "next_ima_ml_entry": 0,
#         "learned_ima_keyrings": {},
#         "verifier_id": "default",
#         "attestation_count": 0,
#         "last_received_quote": 0,
#         "last_successful_attestation": 0,
#         "verifier_ip": "127.0.0.1",
#         "verifier_port": "8881",
#         "registrar_data": "",
#         "nonce": "G98b8NslrLpd2PEXSXA7",
#         "b64_encrypted_V": "",
#         "provide_V": True,
#         "num_retries": 0,
#         "pending_event": None,
#         "ssl_context": "<ssl.SSLContext object at 0x7f708c90c0d0>"
#     },
#     "attestation_data": {
#         "code": 200,
#         "status": "Success",
#         "results": {
#             "quote": "r/1RDR4AYACIACw+4Qfa6gIVXFFoxJYDmbiU...AAAAAAA=",
#             "hash_alg": "sha256",
#             "enc_alg": "rsa",
#             "sign_alg": "rsassa",
#             "pubkey": "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhki...h84e2d6hAU5\nUwIDAQAB\n-----END PUBLIC KEY-----\n"
#         }
#     },
#     "runtime_policy_data": {
#         "meta": {
#             "version": 1,
#             "generator": 3,
#             "timestamp": "2025-04-01 18:06:05.189717"
#         },
#         "release": 0,
#         "digests": {},
#         "excludes": [],
#         "keyrings": {},
#         "ima": {
#             "ignored_keyrings": [],
#             "log_hash_alg": "sha1",
#             "dm_policy": None
#         },
#         "ima-buf": {},
#         "verification-keys": ""
#     },
#     "mb_policy_data": None
# }

# # ----------------------------
# # Run the test
# # ----------------------------

# import json
# def keylime_ear():
#     result = build_keylime_submod(
#         sample_input["agent_data"],
#         sample_input["attestation_data"],
#         sample_input["runtime_policy_data"]
#     )

#     from pprint import pprint
#     pprint(result)

#     # Save to /home directory
#     output_path = "/home/keylime_ear_result.json"
#     with open(output_path, "w") as f:
#         json.dump(result, f, indent=2)
#     print(f"\nResult saved to {output_path}")

import ast
from typing import Any, Dict, Optional, Union
import json # Explicitly import json

# Import necessary Keylime components
from keylime.cloud_verifier_common import get_tpm_instance, process_quote_response
from keylime.agentstates import AgentAttestState, AgentAttestStates
from keylime.ima.file_signatures import ImaKeyrings
from keylime.ima.types import RuntimePolicyType
from keylime.common import algorithms
from keylime.failure import Failure, Component
from keylime import keylime_logging
logger = keylime_logging.init_logging("durable_attestation_persistent_store")

# ----------------------------
# Mock TRUST CLAIM Constants (as provided previously)
# ----------------------------
TRUST_CLAIMS = {
    "TRUSTWORTHY_INSTANCE": 2,
    "UNRECOGNIZED_INSTANCE": 97,
    "GENUINE_HARDWARE": 2,
    "CONTRAINDICATED_HARDWARE": 96,
    "APPROVED_RUNTIME": 2,
    "UNRECOGNIZED_RUNTIME": 33,
    "APPROVED_CONFIG": 2,
    "UNSUPPORTABLE_CONFIG": 96
}

TRUST_TIERS = {
    "AFFIRMING": "affirming",
    "WARNING": "warning",
    "CONTRAINDICATED": "contraindicated"
}

# ----------------------------
# Function to build EAR submod
# ----------------------------
def build_keylime_submod(agent_data: Dict[str, Any], attestation_data: Dict[str, Any], runtime_policy_data: Optional[Dict[str, Any]], mb_policy_data: Optional[str] = None) -> Dict[str, Any]:

    results = attestation_data.get("results", {})
    quote = results.get("quote", "")
    pubkey = results.get("pubkey", "")
    ak_tpm = agent_data.get("ak_tpm", "")
    nonce = agent_data.get("nonce", "")
    hash_alg = results.get("hash_alg", "sha256")


    ima_ml = results.get("ima_measurement_list", "")
    mb_log = results.get("mb_measurement_list", "")
    mb_refstate_for_check_quote = mb_policy_data if mb_policy_data is not None else "{}"


    tpm_policy = ast.literal_eval(agent_data.get("tpm_policy", "{}"))
    runtime_policy = runtime_policy_data or {}


    agent_id = agent_data.get("agent_id")
    agent_attest_state = AgentAttestStates.get_instance().get_by_agent_id(agent_id)


    verification_key_string = runtime_policy.get("verification-keys", "")
    tenant_keyring = ImaKeyrings.from_string(verification_key_string)

    ima_keyrings = agent_attest_state.get_ima_keyrings()
    ima_keyrings.set_tenant_keyring(tenant_keyring)


    failure = Failure(Component.QUOTE_VALIDATION)

    try:

        quote_validation_failure = get_tpm_instance().check_quote(
            agent_attest_state,
            nonce,
            pubkey,
            quote,
            ak_tpm,
            tpm_policy,
            ima_ml,
            runtime_policy,
            algorithms.Hash(hash_alg),
            ima_keyrings,
            mb_log,
            mb_refstate_for_check_quote,
            compressed=False,
            count=agent_data.get("attestation_count", 0),
        )
        failure.merge(quote_validation_failure)
        process_q = process_quote_response(agent=data, runtime_policy=runtime_policy_data, json_response=data, agentAttestState=agent_attest_state, mb_policy="")
        failure.merge(process_q)
    except Exception as e:
        logger.error("Error verifying quote: %s", str(e))
        failure.add_event("invalid_quote", {"message": f"Quote validation failed: {e}"}, False)

    logger.debug("\n \n \n --- TPM CHECK1 --- \n \n \n")
    logger.debug(print_failure(failure))
    logger.debug("\n \n \n --- TPM CHECK2 --- \n \n \n")


    # except json.decoder.JSONDecodeError as e:
    #     logger.error(f"!!! JSONDecodeError occurred during check_quote call: {e} !!!", exc_info=True)
    #     # To allow the program to continue and produce *some* output,
    #     # we'll create a dummy failure object here.
    #        = Failure(Component.QUOTE_VALIDATION)
    #     quote_validation_failure.add_event(f"JSONDecodeError during quote validation: {e}", "critical", False)
    #     logger.debug("--- Proceeding with dummy failure object after JSONDecodeError ---")
    # except Exception as e:
    #     logger.error(f"!!! An unexpected error occurred during check_quote call: {e} !!!", exc_info=True)
    #     quote_validation_failure = Failure(Component.QUOTE_VALIDATION)
    #     quote_validation_failure.add_event(f"Unexpected error during quote validation: {e}", "critical", False)
    #     logger.debug("--- Proceeding with dummy failure object after unexpected error ---")


    # Merge the result of check_quote into the overall failure
    # failure.merge(quote_validation_failure)

    # Determine trust status based on failure object
    trust_vector = {
        "instance_identity": TRUST_CLAIMS["UNRECOGNIZED_INSTANCE"],
        "hardware": TRUST_CLAIMS["CONTRAINDICATED_HARDWARE"],
        "executables": TRUST_CLAIMS["UNRECOGNIZED_RUNTIME"],
        "configuration": TRUST_CLAIMS["UNSUPPORTABLE_CONFIG"]
    }
    logger.debug("\n \n \n HERE \n \n \n")
    logger.debug(print_failure(failure))

    if not failure.is_failure():
        trust_vector.update({
            "instance_identity": TRUST_CLAIMS["TRUSTWORTHY_INSTANCE"],
            "hardware": TRUST_CLAIMS["GENUINE_HARDWARE"],
            "executables": TRUST_CLAIMS["APPROVED_RUNTIME"],
            "configuration": TRUST_CLAIMS["APPROVED_CONFIG"]
        })
        status = TRUST_TIERS["AFFIRMING"]
    else:
        if failure.has_severity_error():
            status = TRUST_TIERS["CONTRAINDICATED"]
        else:
            status = TRUST_TIERS["WARNING"]

    logger.debug("\n--- EAR Construction Result ---")
    return {
        "status": status,
        "trust_vector": trust_vector,
        "failure_events": failure.events
    }

# ----------------------------
# Sample Test Input (MODIFIED to ensure valid JSON strings for optional fields)
# ----------------------------
sample_input = {
    "agent_data": {
        "v": "uFKRgk5ED0r2srVLjycJCoqS3b0V99cknVGTNk+c0DY=",
        "ip": "127.0.0.1",
        "port": 9002,
        "operational_state": 3,
        "public_key": "",
        "tpm_policy": "{\"mask\": \"0x400\"}",
        "meta_data": "{}",
        "ima_sign_verification_keys": "",
        "revocation_key": "",
        "accept_tpm_hash_algs": ["sha512", "sha384", "sha256"],
        "accept_tpm_encryption_algs": ["ecc", "rsa"],
        "accept_tpm_signing_algs": ["ecschnorr", "rsassa"],
        "supported_version": "2.2",
        "ak_tpm": "ARgAAQALAAUAcgAAABAAFAALCAAAAAAAAQDbCTV+BndhIQrlVaqlwoImzAi6oh1M/8Oihlu+KyY9rS4bq91xhh9CzknltRFmKZZPudB2h2cO/8o8llFRP2tF01SHwFQChJz5HoBKy/7CcK2CBkb8bwm7sOAYpFFmtqywBwF9eQMJzQBObFuqFf24IcdT9AD93sgv4yYXqkBQDgilVYD+bXH63mylzCj8hs/7O2u2E+gvvT+IZBFFPiNkBE8pTM5qlnK000kITVyStejB8quxwNa0gPs5ek0bxJRZcuqgJOmdshp532TAQoMSxMHUFSUorNJQXBkkBoqoI5pqis8gFfqA/UOj4mGGdvjQlfA8Hmfyu0d7OGju4NQt",
        "mtls_cert": "-----BEGIN CERTIFICATE-----\nMIIDGzCCAgOgAwIBAgIBADANBgkqhkiG9w0BAQsFADAvMS0wKwYDVQQDDCRkNDMy\nZmJiMy1kMmYxLTRhOTctOWVmNy03NWJkODFjMDAwMDAwHhcNMjUwMjE4MjA1NjQz\nWhcNMjYwMjE4MjA1NjQzWjAvMS0wKwYDVQQDDCRkNDMyZmJiMy1kMmYxLTRhOTct\nOWVmNy03NWJkODFjMDAwMDAwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIB\nAQDAhCSAtPqoSJFbh/t0Y7cp6RMNe2urS6TxhEVOdkCQye/GySLxsPY6qjFZtARW\nblqIcVqA5kWtfokJn708fID3gbuREF7HEKx0CzI1s4GbHDIt6v72wue2PpZRRKDE\neX1c6zvTckdXk6JCBe0HHj8+ykA+5b5g48NxftvJ64dHMxqbUH6h/snhPRX3tTY1\n5fIg0Fx0AXq9mOtCbnrl0mlkh3vvBmG+ymViPEdT6eS5WX4rTCoMsxzEPgi2Ik7J\nX6OKwY9W4O6r3dXMprtGVyTP1umEQxYYKzNDCYlhDmAEZCIsNERgZ0Mlcy3kq4e9\nhjwvZVvF1+bKHzh7Z3qEBTlTAgMBAAGjQjBAMD4GA1UdEQQ3MDWCCWxvY2FsaG9z\ndIIQbG9jYWxob3N0LmRvbWFpbocEfwAAAYcQAAAAAAAAAAAAAAAAAAAAATANBgkq\nhkiG9w0BAQsFAAOCAQEAMIi1Uu7CL3nKoNz+rEoQUHs1tOZnHvfwv49yvrUMZv7n\n6vG3wo52EQnw+U9dLBP9OXnU4+p+JgvFRnGHU2HkbAnZSR7rm6K7fJxxTZyudmtZ\nSeiXT1+9tFtxElN9YlV/3Bql/uGqcHFu8LLmlSmqEoWuvAOjQiC28pJpZVuXC79y\nKS7m6kn2DS3yxUeG03VhrOb5EOhXq61HYla9Bi22PqFgQKnzn0CA9AaRNf0n51Fj\nq4Fha69DJ/FSa2m+PA9lbNcgFTRzKxQ7fNNJN0BLJo79TpWcAHXuB00uSWKS/zB5\nOO8rNOU3egjV74wHxRsHDKbTkzpeXfqzNy8UaV5W+A==\n-----END CERTIFICATE-----\n",
        "hash_alg": "",
        "enc_alg": "",
        "sign_alg": "",
        "agent_id": "d432fbb3-d2f1-4a97-9ef7-75bd81c00000",
        "boottime": 12345,
        "ima_pcrs": [],
        "pcr10": "",
        "next_ima_ml_entry": 0,
        "learned_ima_keyrings": {},
        "verifier_id": "default",
        "attestation_count": 0,
        "last_received_quote": 0,
        "last_successful_attestation": 0,
        "verifier_ip": "127.0.0.1",
        "verifier_port": "8881",
        "registrar_data": "",
        "nonce": "yBYRtLmH6GlCFhWiIEPG",
        "b64_encrypted_V": "",
        "provide_V": True,
        "num_retries": 0,
        "pending_event": None,
        "ssl_context": "<ssl.SSLContext object at 0x7f18ed0a6750>"
    },
    "attestation_data": {
        "code": 200,
        "status": "Success",
        "results": {
            "quote": "r/1RDR4AYACIAC1JESN1HH5AHxcpWIGxL2DpAtSXE5wOAHp8l2zAOgZa6ABR5QllSdExtSDZHbENGaFdpSUVQRwAAAAABNTqYAAAAAQAAAAABIBkQIwAWNjYAAAABAAsDAAQBACAyUfi/Z4SF7chyKn5PnSpgS5kBSpf5/Zdr9VcMuD6/kQ==:ABQACwEAinfNZFu3ptNRPpcRVybRdu9yvNOHUMpQ7AFunjwELbVcqs/PGVJOclqR4Aemzo5VDIJXDn5eeQGkxEw8ttBgrawbpcnpqLCbXRL02CCi0KjiC+W7HmZ2uwLyhEAsJp1GlCCthX5Jv9Drgov/cdnhmdHPouMFke78L61RWqZvc/lGyLWzV0qKMl5+7XNuQ4tJGSIsXmxlnz4G+OqP/kQ5yLR9rhyiHRpwj16xIb8D5B2B6SLyf9/scpLbIJ8wTKQayf3gi5RBypZ/22CW9PajbJMWjrG6fuPemmsCUcft5i8DeeQEH+t0kzwD8ECNsq+q8NW0MvOmkraDL7tAHkgl8w==:AQAAAAsAAwAEAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAQAAAAIAAAAgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAgABzk5vziAnw6ctj/O6SGL+62YwexZA551fa6L+soNNWkAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
            "hash_alg": "sha256",
            "enc_alg": "rsa",
            "sign_alg": "rsassa",
            "pubkey": "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAwIQkgLT6qEiRW4f7dGO3\nKekTDXtrq0uk8YRFTnZAkMnvxski8bD2OqoxWbQEVm5aiHFagOZFrX6JCZ+9PHyA\n94G7kRBexxCsdAsyNbOBmxwyLer+9sLntj6WUUSgxHl9XOs703JHV5OiQgXtBx4/\nPspAPuW+YOPDcX7byeuHRzMam1B+of7J4T0V97U2NeXyINBcdAF6vZjrQm565dJp\nZId77wZhvsplYjxHU+nkuVl+K0wqDLMcxD4ItiJOyV+jisGPVuDuq93VzKa7Rlck\nz9bphEMWGCszQwmJYQ5gBGQiLDREYGdDJXMt5KuHvYY8L2Vbxdfmyh84e2d6hAU5\nUwIDAQAB\n-----END PUBLIC KEY-----\n"
        }
    },
    "runtime_policy_data": {
        "meta": {
            "version": 1,
            "generator": 3,
            "timestamp": "2025-04-01 18:06:05.189717"
        },
        "release": 0,
        "digests": {},
        "excludes": [],
        "keyrings": {},
        "ima": {
            "ignored_keyrings": [],
            "log_hash_alg": "sha1",
            "dm_policy": None
        },
        "ima-buf": {},
        "verification-keys": "{}"
    },
    "mb_policy_data": None
}

data = {**sample_input["agent_data"], **sample_input["attestation_data"]["results"]}
runtime_policy_data: RuntimePolicyType = {
    "meta": {
        "version": 1,
        "generator": 3,
        "timestamp": "2025-04-01 18:06:05.189717"
    },
    "release": 0,
    "digests": {},  # type: Dict[str, List[str]]
    "excludes": [],  # type: List[str]
    "keyrings": {},  # type: Dict[str, List[str]]
    "ima": {
        "ignored_keyrings": [],
        "log_hash_alg": "sha1",
        "dm_policy": None
    },
    "ima-buf": {},  # type: Dict[str, List[str]]
    "verification-keys": "{}"
}


# ----------------------------
# Run the test
# ----------------------------

import json
from pprint import pprint

def keylime_ear():
    logger.debug("\n \n \n \n TESTING1 \n \n \n \n")
    result = build_keylime_submod(
        sample_input["agent_data"],
        sample_input["attestation_data"],
        sample_input["runtime_policy_data"],
        sample_input["mb_policy_data"]
    )

    pprint(result)

    # Save to /home directory
    output_path = "/home/keylime_ear_result.json"
    with open(output_path, "w") as f:
        json.dump(result, f, indent=2)
    logger.debug(f"\nResult saved to {output_path}")

def print_failure(failure: Failure):
    output = {
        "recoverable": failure.recoverable,
        "highest_severity": failure.highest_severity.name if failure.highest_severity else None,
        "events": []
    }

    for event in failure.events:
        output["events"].append({
            "event_id": event.event_id,
            "severity": event.severity_label.name,
            "context": json.loads(event.context),  # convert JSON string back to dict
            "recoverable": event.recoverable
        })

    # Pretty print
    return json.dumps(output, indent=2)

# Example of how to call it:
if __name__ == '__main__':
    keylime_ear()


# {
#     "recoverable": true,
#     "highest_severity": null,
#     "events": []
# }