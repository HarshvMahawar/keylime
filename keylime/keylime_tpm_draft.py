# def build_keylime_submod(agent_data: Dict[str, Any], attestation_data: Dict[str, Any],
#                          runtime_policy_data: Optional[Dict[str, Any]],
#                          mb_policy_data: Optional[str] = None) -> Dict[str, Any]:
    
#     results = attestation_data.get("results", {})
#     quote = results.get("quote", "")
#     pubkey = results.get("pubkey", "")
#     ak_tpm = agent_data.get("ak_tpm", "")
#     nonce = agent_data.get("nonce", "")
#     hash_alg = results.get("hash_alg", "sha256")
    
#     ima_ml = results.get("ima_measurement_list", "")
#     mb_log = results.get("mb_measurement_list", "")
#     mb_refstate_for_check_quote = mb_policy_data or "{}"

#     tpm_policy = ast.literal_eval(agent_data.get("tpm_policy", "{}"))
#     runtime_policy = runtime_policy_data or {}

#     agent_id = agent_data.get("agent_id")
#     agent_attest_state = AgentAttestStates.get_instance().get_by_agent_id(agent_id)

#     # Set up IMA keyrings
#     verification_key_string = runtime_policy.get("verification-keys", "")
#     tenant_keyring = ImaKeyrings.from_string(verification_key_string)
#     ima_keyrings = agent_attest_state.get_ima_keyrings()
#     ima_keyrings.set_tenant_keyring(tenant_keyring)

#     failure = Failure(Component.QUOTE_VALIDATION)

#     try:
#         # TPM quote check
#         quote_validation_failure = get_tpm_instance().check_quote(
#             agent_attest_state,
#             nonce,
#             pubkey,
#             quote,
#             ak_tpm,
#             tpm_policy,
#             ima_ml,
#             runtime_policy,
#             algorithms.Hash(hash_alg),
#             ima_keyrings,
#             mb_log,
#             mb_refstate_for_check_quote,
#             compressed=False,
#             count=agent_data.get("attestation_count", 0),
#         )
#         failure.merge(quote_validation_failure)

#         # Process quote response (for detailed validation like algo checks)
#         process_q = process_quote_response(
#             agent=agent_data,
#             runtime_policy=runtime_policy_data,
#             json_response=results,
#             agentAttestState=agent_attest_state,
#             mb_policy=mb_policy_data,
#         )
#         failure.merge(process_q)

#     except Exception as e:
#         logger.error("Error verifying quote: %s", str(e))
#         failure.add_event("exception", {"message": f"Exception during quote validation: {e}"}, False)

#     logger.debug("--- Failure after validations ---")
#     logger.debug(print_failure(failure))

#     # Build Trust Vector from validated failure object
#     trust_vector = {
#         "instance_identity": TRUST_CLAIMS["UNRECOGNIZED_INSTANCE"],
#         "hardware": TRUST_CLAIMS["CONTRAINDICATED_HARDWARE"],
#         "executables": TRUST_CLAIMS["UNRECOGNIZED_RUNTIME"],
#         "configuration": TRUST_CLAIMS["UNSUPPORTABLE_CONFIG"],
#     }

#     if not failure.is_failure():
#         trust_vector.update({
#             "instance_identity": TRUST_CLAIMS["TRUSTWORTHY_INSTANCE"],
#             "hardware": TRUST_CLAIMS["GENUINE_HARDWARE"],
#             "executables": TRUST_CLAIMS["APPROVED_RUNTIME"],
#             "configuration": TRUST_CLAIMS["APPROVED_CONFIG"]
#         })
#         status = TRUST_TIERS["AFFIRMING"]
#     else:
#         # Fine-grained tuning based on specific failure events
#         if failure.has_event("no_pubkey") or failure.has_event("invalid_data"):
#             trust_vector["instance_identity"] = TRUST_CLAIMS["UNRECOGNIZED_INSTANCE"]
        
#         if failure.has_event("invalid_hash_alg") or failure.has_event("invalid_enc_alg") or failure.has_event("invalid_sign_alg"):
#             trust_vector["hardware"] = TRUST_CLAIMS["CONTRAINDICATED_HARDWARE"]

#         if failure.has_event("ima_failure") or failure.has_event("invalid_measurements"):
#             trust_vector["executables"] = TRUST_CLAIMS["UNRECOGNIZED_RUNTIME"]

#         if failure.has_event("mb_failure") or failure.has_event("config_policy_mismatch"):
#             trust_vector["configuration"] = TRUST_CLAIMS["UNSUPPORTABLE_CONFIG"]

#         # Determine final status tier
#         status = TRUST_TIERS["CONTRAINDICATED"] if failure.has_severity_error() else TRUST_TIERS["WARNING"]

#     return {
#         "status": status,
#         "trust_vector": trust_vector,
#         "failure_events": failure.events
#     }


"""
    if not failure.is_failure():
        trust_vector.update({
            "instance_identity": TRUST_CLAIMS["TRUSTWORTHY_INSTANCE"],
            "hardware": TRUST_CLAIMS["GENUINE_HARDWARE"],
            "executables": TRUST_CLAIMS["APPROVED_RUNTIME"],
            "configuration": TRUST_CLAIMS["APPROVED_CONFIG"]
        })
        status = TRUST_TIERS["AFFIRMING"]
    else:
        # Instance Identity
        if failure.has_event("no_pubkey") or failure.has_event("invalid_data"):
            trust_vector["instance_identity"] = TRUST_CLAIMS["UNRECOGNIZED_INSTANCE"]

        # Hardware-related
        if any(failure.has_event(ev) for ev in ["invalid_hash_alg", "invalid_enc_alg", "invalid_sign_alg"]):
            trust_vector["hardware"] = TRUST_CLAIMS["CONTRAINDICATED_HARDWARE"]

        # Executables (IMA)
        ima_related_events = [
            "not_in_allowlist", "runtime_policy_hash", "invalid_signature", "pcr_mismatch", "quote_progress", "entry"
        ]
        if any(failure.has_event(ev) for ev in ima_related_events):
            trust_vector["executables"] = TRUST_CLAIMS["UNRECOGNIZED_RUNTIME"]

        # Configuration (Measured Boot)
        mb_related_events = ["config_policy_mismatch", "missing_pcrs", "invalid_measured_boot_evaluate"]
        mb_related_events += [e for e in failure.get_event_names() if e.startswith("invalid_pcr_") or e.startswith("missing_pcr_")]
        if any(failure.has_event(ev) for ev in mb_related_events):
            trust_vector["configuration"] = TRUST_CLAIMS["UNSUPPORTABLE_CONFIG"]

        # Determine final status tier
        status = TRUST_TIERS["CONTRAINDICATED"] if failure.has_severity_error() else TRUST_TIERS["WARNING"]
"""



    # --------------------
    # Instance Identity
    # --------------------
    if any(ev.endswith("no_pubkey") or ev.endswith("invalid_data") for ev in event_ids):
        trust_vector["instance_identity"] = TRUST_CLAIMS["UNRECOGNIZED_INSTANCE"]
    elif any(ev.startswith("quote_validation.quote_validation") for ev in event_ids):
        trust_vector["instance_identity"] = TRUST_CLAIMS["UNTRUSTWORTHY_INSTANCE"]
    else:
        trust_vector["instance_identity"] = TRUST_CLAIMS["TRUSTWORTHY_INSTANCE"]

    # --------------------
    # Hardware
    # --------------------
    if any(ev.endswith(suffix) for suffix in ["invalid_hash_alg", "invalid_enc_alg", "invalid_sign_alg"] for ev in event_ids):
        trust_vector["hardware"] = TRUST_CLAIMS["CONTRAINDICATED_HARDWARE"]
    elif any(ev.startswith("pcr_validation.invalid_pcr_") and int(ev.split("_")[-1]) in range(0, 8) for ev in event_ids):
        trust_vector["hardware"] = TRUST_CLAIMS["UNSAFE_HARDWARE"]
    else:
        trust_vector["hardware"] = TRUST_CLAIMS["GENUINE_HARDWARE"]

    # --------------------
    # Executables (IMA)
    # --------------------
    if any(ev.endswith(e) for e in ["not_in_allowlist", "runtime_policy_hash", "invalid_signature"] for ev in event_ids):
        trust_vector["executables"] = TRUST_CLAIMS["UNSAFE_RUNTIME"]
    elif any(ev.endswith(e) for e in ["pcr_mismatch", "quote_progress", "entry"] for ev in event_ids):
        trust_vector["executables"] = TRUST_CLAIMS["CONTRAINDICATED_RUNTIME"]
    elif any(ev.endswith(f"unused_pcr_{config.IMA_PCR}") for ev in event_ids):
        trust_vector["executables"] = TRUST_CLAIMS["UNRECOGNIZED_RUNTIME"]
    else:
        trust_vector["executables"] = TRUST_CLAIMS["APPROVED_RUNTIME"]

    # --------------------
    # Configuration (Measured Boot)
    # --------------------
    if any(ev.endswith(e) for e in ["config_policy_mismatch", "invalid_measured_boot_evaluate"] for ev in event_ids):
        trust_vector["configuration"] = TRUST_CLAIMS["UNSUPPORTABLE_CONFIG"]
    elif any(ev.startswith("pcr_validation.invalid_pcr_") or ev.startswith("pcr_validation.missing_pcr_") for ev in event_ids if int(ev.split("_")[-1]) in config.MEASUREDBOOT_PCRS):
        trust_vector["configuration"] = TRUST_CLAIMS["UNSAFE_CONFIG"]
    elif "pcr_validation.missing_pcrs" in event_ids:
        trust_vector["configuration"] = TRUST_CLAIMS["UNSAFE_CONFIG"]
    else:
        trust_vector["configuration"] = TRUST_CLAIMS["NO_CONFIG_VULNS"]




# Modified
def build_keylime_submod(agent_data: Dict[str, Any], attestation_data: Dict[str, Any],
                         runtime_policy_data: Optional[Dict[str, Any]],
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
    runtime_policy = runtime_policy_data or {}

    agent_id = agent_data.get("agent_id")
    agent_attest_state = AgentAttestStates.get_instance().get_by_agent_id(agent_id)

    # Set up IMA keyrings
    verification_key_string = runtime_policy.get("verification-keys", "")
    tenant_keyring = ImaKeyrings.from_string(verification_key_string)
    ima_keyrings = agent_attest_state.get_ima_keyrings()
    ima_keyrings.set_tenant_keyring(tenant_keyring)

    failure = Failure(Component.QUOTE_VALIDATION)

    try:
        # TPM quote check
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
        failure.add_event("exception", {"message": f"Exception during quote validation: {e}"}, False)

    logger.debug("--- Failure after validations ---")
    logger.debug(print_failure(failure))

    # Build Trust Vector from validated failure object
    trust_vector = {
        "instance_identity": TRUST_CLAIMS["UNRECOGNIZED_INSTANCE"],
        "hardware": TRUST_CLAIMS["CONTRAINDICATED_HARDWARE"],
        "executables": TRUST_CLAIMS["UNRECOGNIZED_RUNTIME"],
        "configuration": TRUST_CLAIMS["UNSUPPORTABLE_CONFIG"],
    }

    # Instance Identity
    if any(ev.endswith("no_pubkey") or ev.endswith("invalid_data") for ev in event_ids):
        trust_vector.instance_identity = UNRECOGNIZED_INSTANCE
    elif any(ev.startswith("quote_validation") for ev in event_ids):
        trust_vector.instance_identity = UNTRUSTWORTHY_INSTANCE
    else:
        trust_vector.instance_identity = TRUSTWORTHY_INSTANCE

    # Hardware
    if any(ev.endswith(suffix) for suffix in ["invalid_hash_alg", "invalid_enc_alg", "invalid_sign_alg"] for ev in event_ids):
        trust_vector.hardware = CONTRAINDICATED_HARDWARE
    elif any(ev.startswith("invalid_pcr_") for ev in event_ids):
        trust_vector.hardware = UNSAFE_HARDWARE
    else:
        trust_vector.hardware = GENUINE_HARDWARE

    # Executables (IMA)
    if any(ev.endswith(e) for e in ["not_in_allowlist", "runtime_policy_hash", "invalid_signature"] for ev in event_ids):
        trust_vector.executables = UNSAFE_RUNTIME
    elif any(ev.endswith(e) for e in ["pcr_mismatch", "quote_progress", "entry"] for ev in event_ids):
        trust_vector.executables = CONTRAINDICATED_RUNTIME
    elif any(ev.endswith(f"unused_pcr_{config.IMA_PCR}") for ev in event_ids):
        trust_vector.executables = UNRECOGNIZED_RUNTIME
    else:
        trust_vector.executables = APPROVED_RUNTIME

    # Configuration (Measured Boot)
    if any(ev.endswith(e) for e in ["invalid_measured_boot_evaluate"] for ev in event_ids):
        trust_vector.configuration = UNSUPPORTABLE_CONFIG
    elif any(ev.startswith("invalid_pcr_") or ev.startswith("missing_pcr_") for ev in event_ids):
        trust_vector.configuration = UNSAFE_CONFIG
    elif "missing_pcrs" in event_ids:
        trust_vector.configuration = UNSAFE_CONFIG
    else:
        trust_vector.configuration = NO_CONFIG_VULNS


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