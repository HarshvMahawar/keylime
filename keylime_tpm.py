# def build_keylime_submod(agent_data, attestation_data, runtime_policy_data) -> Submod:
#     status_str = attestation_data.get("status", "Fail")
#     results = attestation_data.get("results", {})
#     quote = results.get("quote", "")
#     ak_tpm = agent_data.get("ak_tpm", "")
#     ima_pcrs = agent_data.get("ima_pcrs", [])
#     pcr10 = agent_data.get("pcr10", "")
#     runtime_policy_valid = runtime_policy_data is not None and runtime_policy_data != {}

#     if status_str == "Success":
#         submod_status = TrustTier.AFFIRMING
#     elif not quote or attestation_data.get("code") == 500:
#         submod_status = TrustTier.CONTRAINDICATED
#     else:
#         submod_status = TrustTier.WARNING

#     tv = TrustVector()

#     # instance_identity
#     if ak_tpm and quote:
#         tv.instance_identity = TRUSTWORTHY_INSTANCE_CLAIM
#     elif not ak_tpm:
#         tv.instance_identity = UNTRUSTWORTHY_INSTANCE_CLAIM
#     else:
#         tv.instance_identity = UNRECOGNIZED_INSTANCE_CLAIM

#     # hardware
#     if quote and status_str == "Success":
#         tv.hardware = GENUINE_HARDWARE_CLAIM
#     elif status_str == "Fail":
#         tv.hardware = CONTRAINDICATED_HARDWARE_CLAIM
#     else:
#         tv.hardware = UNSAFE_HARDWARE_CLAIM

#     # executables (IMA)
#     if ima_pcrs or pcr10:
#         if status_str == "Success":
#             tv.executables = APPROVED_RUNTIME_CLAIM
#         else:
#             tv.executables = UNSAFE_RUNTIME_CLAIM
#     else:
#         tv.executables = UNRECOGNIZED_RUNTIME_CLAIM

#     # configuration (runtime policy)
#     if runtime_policy_valid:
#         tv.configuration = APPROVED_CONFIG_CLAIM
#     elif runtime_policy_data is None:
#         tv.configuration = UNSUPPORTABLE_CONFIG_CLAIM
#     else:
#         tv.configuration = UNSAFE_CONFIG_CLAIM

#     return Submod(
#         status=submod_status,
#         trust_vector=tv
#     )


# from keylime.verifier import cloud_verifier_common

# def build_keylime_submod(agent_data, attestation_data, runtime_policy_data) -> Submod:
#     quote = attestation_data["results"]["quote"]
#     pubkey = attestation_data["results"]["pubkey"]
#     ak_tpm = agent_data["ak_tpm"]
#     nonce = agent_data["nonce"]
#     tpm_policy = ast.literal_eval(agent_data["tpm_policy"])
#     ima_ml = attestation_data["results"].get("ima_measurement_list")
#     mb_log = attestation_data["results"].get("mb_measurement_list")
#     hash_alg = attestation_data["results"]["hash_alg"]

#     # Use the actual TPM logic to validate
#     failure = get_tpm_instance().check_quote(
#         agentAttestState=AgentAttestState(),
#         nonce=nonce,
#         public_key=pubkey,
#         quote=quote,
#         aik=ak_tpm,
#         tpm_policy=tpm_policy,
#         ima_measurement_list=ima_ml,
#         runtime_policy=runtime_policy_data,
#         hash_alg=algorithms.Hash(hash_alg),
#         ima_keyrings=...,   # build from runtime_policy_data
#         mb_measurement_list=mb_log,
#         mb_refstate=None,
#     )

#     tv = TrustVector()
#     if not failure:
#         tv.instance_identity = TRUSTWORTHY_INSTANCE_CLAIM
#         tv.hardware = GENUINE_HARDWARE_CLAIM
#         tv.executables = APPROVED_RUNTIME_CLAIM
#         tv.configuration = APPROVED_CONFIG_CLAIM
#         submod_status = TrustTier.AFFIRMING
#     else:
#         # Use details in `failure.events` to decide further
#         tv.instance_identity = UNRECOGNIZED_INSTANCE_CLAIM
#         tv.hardware = CONTRAINDICATED_HARDWARE_CLAIM
#         ...
#         submod_status = TrustTier.WARNING  # or CONTRAINDICATED

#     return Submod(status=submod_status, trust_vector=tv)

import ast
from keylime.verifier import cloud_verifier_common
from keylime.tpm.tpm_main import get_tpm_instance
from keylime.ima.keyrings import ImaKeyring
from keylime.tpm.tpm_abstract import TPM_Utilities
from keylime.agentstates import AgentAttestState
from keylime import algorithms

# ----------------------------
# Mock TRUST CLAIM Constants
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
def build_keylime_submod(agent_data, attestation_data, runtime_policy_data):
    results = attestation_data.get("results", {})
    quote = results.get("quote")
    pubkey = results.get("pubkey")
    ak_tpm = agent_data.get("ak_tpm")
    nonce = agent_data.get("nonce")
    hash_alg = results.get("hash_alg")
    ima_ml = results.get("ima_measurement_list", None)
    mb_log = results.get("mb_measurement_list", None)
    tpm_policy = ast.literal_eval(agent_data.get("tpm_policy", "{}"))
    runtime_policy = runtime_policy_data or {}

    # Create ImaKeyring object from policy string (if any)
    verification_key_string = runtime_policy.get("verification-keys", "")
    tenant_keyring = ImaKeyring.from_string(verification_key_string)
    ima_keyrings = TPM_Utilities.get_ima_keyrings()
    ima_keyrings.set_tenant_keyring(tenant_keyring)

    agent_attest_state = AgentAttestState()

    failure = get_tpm_instance().check_quote(
        agentAttestState=agent_attest_state,
        nonce=nonce,
        public_key=pubkey,
        quote=quote,
        aik=ak_tpm,
        tpm_policy=tpm_policy,
        ima_measurement_list=ima_ml,
        runtime_policy=runtime_policy,
        hash_alg=algorithms.Hash(hash_alg),
        ima_keyrings=ima_keyrings,
        mb_measurement_list=mb_log,
        mb_refstate=None,
        count=agent_data.get("attestation_count", 0),
        compressed=False,
    )

    trust_vector = {
        "instance_identity": TRUST_CLAIMS["UNRECOGNIZED_INSTANCE"],
        "hardware": TRUST_CLAIMS["CONTRAINDICATED_HARDWARE"],
        "executables": TRUST_CLAIMS["UNRECOGNIZED_RUNTIME"],
        "configuration": TRUST_CLAIMS["UNSUPPORTABLE_CONFIG"]
    }

    if not failure:
        trust_vector.update({
            "instance_identity": TRUST_CLAIMS["TRUSTWORTHY_INSTANCE"],
            "hardware": TRUST_CLAIMS["GENUINE_HARDWARE"],
            "executables": TRUST_CLAIMS["APPROVED_RUNTIME"],
            "configuration": TRUST_CLAIMS["APPROVED_CONFIG"]
        })
        status = TRUST_TIERS["AFFIRMING"]
    else:
        status = TRUST_TIERS["WARNING"]  # You can inspect `failure.events` to refine

    return {
        "status": status,
        "trust_vector": trust_vector,
        "failure_events": failure.events
    }

# ----------------------------
# Sample Test Input
# ----------------------------
sample_input = {
    "agent_data": {
        "v": "TSsIA2PyJ3q8MMvrdhRY7v/7PUhSUUkqL4nsY54ieMc=",
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
        "ak_tpm": "ARgAAQALAAUAc...VAD1/sMFNh6X+Kwi/dyncQolor2r",
        "mtls_cert": "-----BEGIN CERTIFICATE-----\nMIIDGzCCAgOgAwIBAgIBADANBgkqhkiG9...==\n-----END CERTIFICATE-----\n",
        "hash_alg": "",
        "enc_alg": "",
        "sign_alg": "",
        "agent_id": "d432fbb3-d2f1-4a97-9ef7-75bd81c00000",
        "boottime": "",
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
        "nonce": "G98b8NslrLpd2PEXSXA7",
        "b64_encrypted_V": "",
        "provide_V": True,
        "num_retries": 0,
        "pending_event": None,
        "ssl_context": "<ssl.SSLContext object at 0x7f708c90c0d0>"
    },
    "attestation_data": {
        "code": 200,
        "status": "Success",
        "results": {
            "quote": "r/1RDR4AYACIACw+4Qfa6gIVXFFoxJYDmbiU...AAAAAAA=",
            "hash_alg": "sha256",
            "enc_alg": "rsa",
            "sign_alg": "rsassa",
            "pubkey": "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhki...h84e2d6hAU5\nUwIDAQAB\n-----END PUBLIC KEY-----\n"
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
        "verification-keys": ""
    },
    "mb_policy_data": None
}

# ----------------------------
# Run the test
# ----------------------------
if __name__ == "__main__":
    result = build_keylime_submod(
        sample_input["agent_data"],
        sample_input["attestation_data"],
        sample_input["runtime_policy_data"]
    )
    from pprint import pprint
    pprint(result)
