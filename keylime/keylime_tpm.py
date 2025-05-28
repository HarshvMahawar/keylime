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

def build_keylime_submod(agent_data: Dict[str, Any], attestation_data: Dict[str, Any],
                         runtime_policy: Optional[Dict[str, Any]],
                         mb_policy_data: Optional[str] = None) -> Dict[str, Any]:
    
    

    results = attestation_data.get("results", {})
    quote = results.get("quote", "")
    pubkey = results.get("pubkey", "")
    ak_tpm = agent_data.get("ak_tpm", "")
    nonce = agent_data.get("nonce", "")
    hash_alg = results.get("hash_alg", "sha256")
    
    ima_ml = results.get("ima_measurement_list", "")
    mb_log = results.get("mb_measurement_list", "")
    mb_refstate_for_check_quote = mb_policy_data or "{}"

    tpm_policy = ast.literal_eval(agent_data.get("tpm_policy", "{}"))

    agent_id = agent_data.get("agent_id")
    agent_attest_state = AgentAttestStates.get_instance().get_by_agent_id(agent_id)

    # Set up IMA keyrings
    verification_key_string = "{}"
    tenant_keyring = ImaKeyrings.from_string(verification_key_string)
    ima_keyrings = agent_attest_state.get_ima_keyrings()
    ima_keyrings.set_tenant_keyring(tenant_keyring)
    logger.debug(f"RTP = {runtime_policy}")
    runtime_policy_data: RuntimePolicyType = json.loads(runtime_policy)

    failure = Failure(Component.QUOTE_VALIDATION)

    try:
        # TPM quote check
        quote_validation_failure = get_tpm_instance().check_quote(
            agentAttestState=agent_attest_state,
            nonce=nonce,
            data=pubkey,
            quote=quote,
            aikTpmFromRegistrar=ak_tpm,
            tpm_policy=tpm_policy,
            ima_measurement_list=ima_ml,
            runtime_policy=runtime_policy_data,
            ima_keyrings=ima_keyrings,
            mb_measurement_list=mb_log,
            mb_policy=mb_refstate_for_check_quote,
            compressed=False,
            count=agent_data.get("attestation_count", 0),
            skip_clock_check=True
        )
        failure.merge(quote_validation_failure)
    except Exception as e:
        logger.error("Error verifying quote: %s", str(e))
        failure.add_event("exception", {"message": f"Exception during check_quote: {e}"}, False)

    

    try:
        # Process quote response (for detailed validation like algo checks)
        process_q = process_quote_response(
            agent=agent_data,
            runtime_policy=runtime_policy_data,
            json_response=results,
            agentAttestState=agent_attest_state,
            mb_policy=mb_policy_data,
        )
        failure.merge(process_q)
        

    except Exception as e:
        logger.error("Error verifying quote: %s", str(e))
        failure.add_event("exception", {"message": f"Exception during process_quote_validation: {e}"}, False)
    
    logger.debug("--- Failure after validations ---")
    logger.debug(print_failure(failure))

    # Build Trust Vector from validated failure object
    trust_vector = {
        "instance_identity": "UNRECOGNIZED_INSTANCE",
        "hardware": "CONTRAINDICATED_HARDWARE",
        "executables": "UNRECOGNIZED_RUNTIME",
        "configuration": "UNSUPPORTABLE_CONFIG",
    }
    event_ids = failure.get_event_ids()
    # Instance Identity
    if any(ev.endswith("no_pubkey") or ev.endswith("invalid_data") for ev in event_ids):
        trust_vector["instance_identity"] = 'UNRECOGNIZED_INSTANCE'
    elif any(ev.startswith("quote_validation.quote_validation") for ev in event_ids):
        trust_vector["instance_identity"] = 'UNTRUSTWORTHY_INSTANCE'
    else:
        trust_vector["instance_identity"] = 'TRUSTWORTHY_INSTANCE'

    # Hardware
    if any(ev.endswith(suffix) for suffix in ["invalid_hash_alg", "invalid_enc_alg", "invalid_sign_alg"] for ev in event_ids):
        trust_vector["hardware"] = 'CONTRAINDICATED_HARDWARE'
    elif any(ev.startswith("pcr_validation.invalid_pcr_") for ev in event_ids):
        trust_vector["hardware"] = 'UNSAFE_HARDWARE'
    else:
        trust_vector["hardware"] = 'GENUINE_HARDWARE'

    # Executables (IMA)
    if any(ev.endswith(e) for e in ["not_in_allowlist", "runtime_policy_hash", "invalid_signature"] for ev in event_ids):
        trust_vector["executables"] = 'UNSAFE_RUNTIME'
    elif any(ev.endswith(e) for e in ["pcr_mismatch", "quote_progress", "entry"] for ev in event_ids):
        trust_vector["executables"] = 'CONTRAINDICATED_RUNTIME'
    elif any(ev.find(f"unused_pcr_") for ev in event_ids):
        trust_vector["executables"] = 'UNRECOGNIZED_RUNTIME'
    else:
        trust_vector["executables"] = 'APPROVED_RUNTIME'

    # Configuration (Measured Boot)
    if any(ev.endswith(e) for e in ["invalid_measured_boot_evaluate"] for ev in event_ids):
        trust_vector["configuration"] = 'UNSUPPORTABLE_CONFIG'
    elif any(ev.startswith("pcr_validation.invalid_pcr_") or ev.startswith("missing_pcr_") for ev in event_ids):
        trust_vector["configuration"] = 'UNSAFE_CONFIG'
    elif "missing_pcrs" in event_ids:
        trust_vector["configuration"] = 'UNSAFE_CONFIG'
    else:
        trust_vector["configuration"] = 'NO_CONFIG_VULNS'


    logger.debug("\n \n \n \n TESTING - MAIN \n \n \n \n")
    logger.debug(f"trust_vector = {trust_vector}")
    return trust_vector


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