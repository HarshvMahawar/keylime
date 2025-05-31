import base64
import struct
import zlib
from typing import Any, Dict, List, Optional, Set, Tuple, Union

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization as crypto_serialization
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePublicKey
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey

from keylime import cert_utils, config, json, keylime_logging
from keylime.agentstates import AgentAttestState, TPMClockInfo
from keylime.common.algorithms import Hash
from keylime.failure import Component, Failure
from keylime.ima import ima
from keylime.ima.file_signatures import ImaKeyrings
from keylime.ima.types import RuntimePolicyType
from keylime.mba import mba
from keylime.tpm import tpm2_objects, tpm_util

import ast
import base64
import time
from typing import Any, Dict, Optional, Union

from keylime import config, crypto, json, keylime_logging
from keylime.agentstates import AgentAttestState, AgentAttestStates, TPMClockInfo
from keylime.common import algorithms
from keylime.db.verifier_db import VerfierMain
from keylime.failure import Component, Event, Failure
from keylime.ima import file_signatures, ima
from keylime.ima.types import RuntimePolicyType
from keylime.tpm import tpm_util
from keylime.tpm.tpm_main import Tpm

logger = keylime_logging.init_logging("keylime_ear_validation")

def validate_quote_response(
    agent: Dict[str, Any],
    mb_policy: Optional[str],
    runtime_policy: RuntimePolicyType,
    json_response: Dict[str, Any],
    agentAttestState: AgentAttestState,
):
    failure = Failure(Component.QUOTE_VALIDATION)
    received_public_key = None
    quote = None
    agent_id = None
    # in case of failure in response content do not continue
    try:
        agent_id = agent["agent_id"]
        received_public_key = json_response.get("pubkey", None)
        quote = json_response["quote"]

        ima_measurement_list = json_response.get("ima_measurement_list", None)
        ima_measurement_list_entry = json_response.get("ima_measurement_list_entry", 0)
        mb_measurement_list = json_response.get("mb_measurement_list", None)
        boottime = json_response.get("boottime", 0)

        logger.debug(
            "received data for agent %s, quote: %s, nonce: %s, public key(b64): %s, ima_measurement_list: %s, ima_measurement_list_entry: %s, measured_boot_log: %s, boottime: %s",
            agent_id,
            quote,
            agent["nonce"],
            base64.b64encode(str(received_public_key).encode("ascii")).decode("ascii"),
            (ima_measurement_list is not None),
            ima_measurement_list_entry,
            (mb_measurement_list is not None),
            boottime,
        )

    except Exception as e:
        failure.add_event("invalid_data", {"message": "parsing agent get quote respone failed", "data": str(e)}, False)
        return failure

    # TODO: Are those separate failures?
    if not isinstance(ima_measurement_list_entry, int):
        raise Exception("ima_measurement_list_entry parameter must be an integer")

    if not isinstance(boottime, int):
        raise Exception("boottime parameter must be an integer")

    # if no public key provided, then ensure we have cached it
    if received_public_key is None:
        if agent.get("public_key", "") == "" or (agent.get("v") and agent.get("b64_encrypted_V", "") == ""):
            logger.error("agent %s did not provide public key and no key or encrypted_v was cached at CV", agent_id)
            failure.add_event(
                "no_pubkey",
                {
                    "message": "agent did not provide public key and no key or encrypted_v was cached at CV",
                    "data": received_public_key,
                },
                False,
            )
            return failure
        agent["provide_V"] = False
        received_public_key = agent["public_key"]

    hash_alg = json_response.get("hash_alg")
    enc_alg = json_response.get("enc_alg")
    sign_alg = json_response.get("sign_alg")

    # Ensure hash_alg is in accept_tpm_hash_alg list
    if (
        not hash_alg
        or not algorithms.is_accepted(hash_alg, agent["accept_tpm_hash_algs"])
        or not algorithms.Hash.is_recognized(hash_alg)
    ):
        logger.error("TPM Quote for agent %s is using an unaccepted hash algorithm: %s", agent_id, hash_alg)
        failure.add_event(
            "invalid_hash_alg",
            {"message": f"TPM Quote is using an unaccepted hash algorithm: {hash_alg}", "data": hash_alg},
            False,
        )
        return failure

    agent["hash_alg"] = hash_alg

    # Ensure enc_alg is in accept_tpm_encryption_algs list
    if not enc_alg or not algorithms.is_accepted(enc_alg, agent["accept_tpm_encryption_algs"]):
        logger.error("TPM Quote for agent %s is using an unaccepted encryption algorithm: %s", agent_id, enc_alg)
        failure.add_event(
            "invalid_enc_alg",
            {"message": f"TPM Quote is using an unaccepted encryption algorithm: {enc_alg}", "data": enc_alg},
            False,
        )
        return failure

    agent["enc_alg"] = enc_alg

    # Ensure sign_alg is in accept_tpm_encryption_algs list
    if not sign_alg or not algorithms.is_accepted(sign_alg, agent["accept_tpm_signing_algs"]):
        logger.error("TPM Quote for agent %s is using an unaccepted signing algorithm: %s", agent_id, sign_alg)
        failure.add_event(
            "invalid_sign_alg",
            {"message": f"TPM Quote is using an unaccepted signing algorithm: {sign_alg}", "data": sign_alg},
            False,
        )
        return failure

    return failure


def validate_quote(
    agentAttestState: AgentAttestState,
    nonce: str,
    data: str,
    quote: str,
    aikTpmFromRegistrar: str,
    tpm_policy: Optional[Union[str, Dict[str, Any]]] = None,
    ima_measurement_list: Optional[str] = None,
    runtime_policy: Optional[RuntimePolicyType] = None,
    hash_alg: Hash = Hash.SHA256,
    ima_keyrings: Optional[ImaKeyrings] = None,
    mb_measurement_list: Optional[str] = None,
    mb_policy: Optional[str] = None,
    compressed: bool = False,
    count: int = -1,
    skip_pcr_check: bool = False,
):
    if tpm_policy is None:
        tpm_policy = {}

    if runtime_policy is None:
        runtime_policy = ima.EMPTY_RUNTIME_POLICY

    failure = Failure(Component.QUOTE_VALIDATION)

    # First and foremost, the quote needs to be validated
    pcrs_dict, err = Tpm._tpm2_checkquote(aikTpmFromRegistrar, quote, nonce, str(hash_alg), compressed)
    if err:
        # If the quote validation fails we will skip all other steps therefore this failure is irrecoverable.
        failure.add_event("quote_validation", {"message": "Quote data validation", "error": err}, False)
        return failure


    if not skip_pcr_check:
        if len(pcrs_dict) == 0:
            logger.warning(
                "Quote for agent %s does not contain any PCRs. Make sure that the TPM supports %s PCR banks",
                agentAttestState.agent_id,
                str(hash_alg),
            )

        return validate_pcrs(
            agentAttestState,
            tpm_policy,
            pcrs_dict,
            data,
            ima_measurement_list,
            runtime_policy,
            ima_keyrings,
            mb_measurement_list,
            mb_policy,
            hash_alg,
            count,
        )

    return failure

def validate_pcrs(
    agentAttestState: AgentAttestState,
    tpm_policy: Union[str, Dict[str, Any]],
    pcrs_dict: Dict[int, str],
    data: str,
    ima_measurement_list: Optional[str],
    runtime_policy: Optional[RuntimePolicyType],
    ima_keyrings: Optional[ImaKeyrings],
    mb_measurement_list: Optional[str],
    mb_policy: Optional[str],
    hash_alg: Hash,
    count: int,
):
    failure = Failure(Component.PCR_VALIDATION)

    agent_id = agentAttestState.get_agent_id()

    if isinstance(tpm_policy, str):
        tpm_policy_dict = json.loads(tpm_policy)
    else:
        tpm_policy_dict = tpm_policy

    pcr_allowlist = tpm_policy_dict.copy()

    if "mask" in pcr_allowlist:
        del pcr_allowlist["mask"]
    # convert all pcr num keys to integers
    pcr_allowlist = {int(k): v for k, v in list(pcr_allowlist.items())}

    mb_pcrs_hashes, boot_aggregates, mb_measurement_data, mb_failure = mba.bootlog_parse(
        mb_measurement_list, hash_alg
    )
    failure.merge(mb_failure)

    pcrs_in_quote: Set[int] = set()  # PCRs in quote that were already used for some kind of validation

    pcr_nums = set(pcrs_dict.keys())

    # Validate data PCR
    if config.TPM_DATA_PCR in pcr_nums and data is not None:
        expectedval = _sim_extend(data, hash_alg)
        if expectedval != pcrs_dict[config.TPM_DATA_PCR]:
            logger.error(
                "PCR #%s: invalid bind data %s from quote (from agent %s) does not match expected value %s",
                config.TPM_DATA_PCR,
                pcrs_dict[config.TPM_DATA_PCR],
                agent_id,
                expectedval,
            )
            failure.add_event(
                f"invalid_pcr_{config.TPM_DATA_PCR}",
                {"got": pcrs_dict[config.TPM_DATA_PCR], "expected": expectedval},
                True,
            )
        pcrs_in_quote.add(config.TPM_DATA_PCR)
    else:
        logger.error(
            "Binding PCR #%s was not included in the quote (from agent %s), but is required",
            config.TPM_DATA_PCR,
            agent_id,
        )
        failure.add_event(
            f"missing_pcr_{config.TPM_DATA_PCR}",
            f"Data PCR {config.TPM_DATA_PCR} is missing in quote, but is required",
            True,
        )
    # Check for ima PCR
    if config.IMA_PCR in pcr_nums:
        if ima_measurement_list is None:
            logger.error("IMA PCR in policy, but no measurement list provided by agent %s", agent_id)
            failure.add_event(
                f"unused_pcr_{config.IMA_PCR}", "IMA PCR in policy, but no measurement list provided", True
            )
        else:
            ima_failure = Tpm._Tpm__check_ima(
                agentAttestState,
                pcrs_dict[config.IMA_PCR],
                ima_measurement_list,
                runtime_policy,
                ima_keyrings,
                boot_aggregates,
                hash_alg,
            )
            failure.merge(ima_failure)

        pcrs_in_quote.add(config.IMA_PCR)

    # Collect mismatched measured boot PCRs as measured_boot failures
    mb_pcr_failure = Failure(Component.MEASURED_BOOT)
    # Handle measured boot PCRs only if the parsing worked
    if not mb_failure:
        for pcr_num in set(config.MEASUREDBOOT_PCRS) & pcr_nums:
            if mba.policy_is_valid(mb_policy):
                if not mb_measurement_list:
                    logger.error(
                        "Measured Boot PCR %d in policy, but no measurement list provided by agent %s",
                        pcr_num,
                        agent_id,
                    )
                    failure.add_event(
                        f"unused_pcr_{pcr_num}",
                        f"Measured Boot PCR {pcr_num} in policy, but no measurement list provided",
                        True,
                    )
                    continue

                val_from_log_int = mb_pcrs_hashes.get(str(pcr_num), 0)
                val_from_log_hex = hex(val_from_log_int)[2:]
                val_from_log_hex_stripped = val_from_log_hex.lstrip("0")
                pcrval_stripped = pcrs_dict[pcr_num].lstrip("0")
                if val_from_log_hex_stripped != pcrval_stripped:
                    logger.error(
                        "For PCR %d and hash %s the boot event log has value %r but the agent %s returned %r",
                        pcr_num,
                        str(hash_alg),
                        val_from_log_hex,
                        agent_id,
                        pcrs_dict[pcr_num],
                    )
                    mb_pcr_failure.add_event(
                        f"invalid_pcr_{pcr_num}",
                        {
                            "context": "SHA256 boot event log PCR value does not match",
                            "got": pcrs_dict[pcr_num],
                            "expected": val_from_log_hex,
                        },
                        True,
                    )

                if pcr_num in pcr_allowlist and pcrs_dict[pcr_num] not in pcr_allowlist[pcr_num]:
                    logger.error(
                        "PCR #%s: %s from quote (from agent %s) does not match expected value %s",
                        pcr_num,
                        pcrs_dict[pcr_num],
                        agent_id,
                        pcr_allowlist[pcr_num],
                    )
                    failure.add_event(
                        f"invalid_pcr_{pcr_num}",
                        {
                            "context": "PCR value is not in allowlist",
                            "got": pcrs_dict[pcr_num],
                            "expected": pcr_allowlist[pcr_num],
                        },
                        True,
                    )
                pcrs_in_quote.add(pcr_num)
    failure.merge(mb_pcr_failure)

    # Check the remaining non validated PCRs
    for pcr_num in pcr_nums - pcrs_in_quote:
        if pcr_num not in list(pcr_allowlist.keys()):
            logger.warning(
                "PCR #%s in quote (from agent %s) not found in tpm_policy, skipping.",
                pcr_num,
                agent_id,
            )
            continue
        if pcrs_dict[pcr_num] not in pcr_allowlist[pcr_num]:
            logger.error(
                "PCR #%s: %s from quote (from agent %s) does not match expected value %s",
                pcr_num,
                pcrs_dict[pcr_num],
                agent_id,
                pcr_allowlist[pcr_num],
            )
            failure.add_event(
                f"invalid_pcr_{pcr_num}",
                {
                    "context": "PCR value is not in allowlist",
                    "got": pcrs_dict[pcr_num],
                    "expected": pcr_allowlist[pcr_num],
                },
                True,
            )

        pcrs_in_quote.add(pcr_num)

    missing = set(pcr_allowlist.keys()) - pcrs_in_quote
    if len(missing) > 0:
        logger.error("PCRs specified in policy not in quote (from agent %s): %s", agent_id, missing)
        failure.add_event("missing_pcrs", {"context": "PCRs are missing in quote", "data": list(missing)}, True)

    if not mb_failure and mba.policy_is_valid(mb_policy):
        mb_evaluate = config.get("verifier", "measured_boot_evaluate", fallback="once")

        # Value of measured_boot_evaluate can be only 'once' or 'always'
        if mb_evaluate not in ("once", "always"):
            logger.error("Invalid value %s of measured_boot_evaluate", mb_evaluate)
            failure.add_event(
                "invalid_measured_boot_evaluate", "correct value of measured_boot_evaluate is required", True
            )

        if mb_evaluate == "always":
            mb_policy_failure = mba.bootlog_evaluate(
                mb_policy,
                mb_measurement_data,
                pcrs_in_quote,
                agentAttestState.get_agent_id(),
            )
            failure.merge(mb_policy_failure)

        elif mb_evaluate == "once" and count == 0:
            mb_policy_failure = mba.bootlog_evaluate(
                mb_policy,
                mb_measurement_data,
                pcrs_in_quote,
                agentAttestState.get_agent_id(),
            )
            failure.merge(mb_policy_failure)

    return failure

def _sim_extend(hashval_1: str, hash_alg: Hash) -> str:
    """Compute expected value  H(0|H(data))"""
    hdata = hash_alg.hash(hashval_1.encode("utf-8"))
    hext = hash_alg.hash(hash_alg.get_start_hash() + hdata)
    return hext.hex()