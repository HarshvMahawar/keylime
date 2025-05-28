import base64
import json
import requests

AGENT_URL = "https://localhost:9002/v2.2/quotes/integrity"
NONCE = "1234567890ABCDEFHIJK"
PCR_MASK = "0x10401"
PARTIAL = "0"

CLIENT_CERT = "/var/lib/keylime/cv_ca/client-cert.crt"
CLIENT_KEY = "/var/lib/keylime/cv_ca/client-private.pem"

CMW_COLLECTION_TYPE = "tag:keylime.org,2025:tpm2-agent"

def get_keylime_quote():
    try:
        response = requests.get(
            AGENT_URL,
            params={
                "nonce": NONCE,
                "mask": PCR_MASK,
                "partial": PARTIAL
            },
            cert=(CLIENT_CERT, CLIENT_KEY),
            verify=False
        )
        response.raise_for_status()
        return response.json()["results"]
    except requests.exceptions.RequestException as e:
        print(f"Error fetching Keylime quote: {e}")
        return None

import base64

def build_event_log(ima_list, mb_list_b64):
    cel = []
    recnum = 0

    # Parse IMA measurement list (PCR 10)
    if ima_list:
        lines = ima_list.strip().splitlines()
        for line in lines:
            parts = line.strip().split()
            if len(parts) < 5:
                continue  # unexpected format

            try:
                pcr_index = int(parts[0])
                # We expect: parts[2] = template type (e.g., ima-ng), parts[3] = hash (e.g., sha256:abcd)
                template_type = parts[2]
                template_hash = parts[3]

                if ':' not in template_hash:
                    continue  # unexpected format : "algo:hash"

                hash_alg, hash_val = template_hash.split(':', 1)
                path = parts[4]
                digest = bytes.fromhex(hash_val)

                cel.append({
                    "recnum": recnum,
                    "pcr": pcr_index,
                    "digests": [{
                        "hashAlg": hash_alg.lower(),  # e.g., "sha256"
                        "digest": base64.urlsafe_b64encode(digest).rstrip(b'=').decode()
                    }],
                    "content_type": "ima_template",
                    "content": {
                        "template_name": template_type,
                        "template_data": base64.urlsafe_b64encode(
                            f"{template_hash} {path}".encode()
                        ).rstrip(b'=').decode()
                    }
                })
                recnum += 1

            except Exception as e:
                print(f"[warning] Skipping IMA line due to error: {e}")
                continue

    # Parse Measured Boot Log (PCR 0)
    if mb_list_b64:
        try:
            raw_mb_log = base64.b64decode(mb_list_b64)
            cel.append({
                "recnum": recnum,
                "pcr": 0,
                "digests": [{
                    "hashAlg": "sha1",  # dynamic
                    "digest": base64.urlsafe_b64encode(raw_mb_log[:20]).rstrip(b'=').decode()
                }],
                "content_type": "pcclient_std",
                "content": base64.urlsafe_b64encode(raw_mb_log).rstrip(b'=').decode()
            })
            recnum += 1
        except Exception as e:
            print(f"[error] Failed to parse measured boot log: {e}")

    return cel

def get_keylime_metadata(keylime_data):
    metadata = {
        "boottime": keylime_data.get("boottime"),
        "pubkey": keylime_data.get("pubkey"),
        "hash_alg": keylime_data.get("hash_alg"),
        "sign_alg": keylime_data.get("sign_alg")
    }
    return metadata

def parse_quote_fields(quote_str):
    parts = quote_str.split(":")
    if len(parts) != 3:
        raise ValueError("Unexpected quote format.")
    return {
        "TPMS_ATTEST": parts[0].encode(),
        "TPMT_SIGNATURE": parts[1].encode(),
        "PCRs": parts[2].encode()
    }

def build_cmw_collection(parsed_quote, event_log_data, metadata):
    cmw = {
        "__cmwc_t": CMW_COLLECTION_TYPE,
        "evidence": {
            "tpms_attest": [
                "application/vnd.keylime.tpm2.tpms_attest",
                base64.urlsafe_b64encode(parsed_quote["TPMS_ATTEST"]).rstrip(b"=").decode()
            ],
            "tpmt_signature": [
                "application/vnd.keylime.tpm2.tpmt_signature",
                base64.urlsafe_b64encode(parsed_quote["TPMT_SIGNATURE"]).rstrip(b"=").decode()
            ],
            "pcr_values": [
                "application/vnd.keylime.tpm2.pcr_values",
                base64.urlsafe_b64encode(parsed_quote["PCRs"]).rstrip(b"=").decode()
            ],
            "event_log": [
                "application/vnd.keylime.cel",
                base64.urlsafe_b64encode(json.dumps(event_log_data).encode()).rstrip(b"=").decode()
            ],
            "keylime_metadata": [
                "application/vnd.keylime.tpm2.metadata",
                base64.urlsafe_b64encode(json.dumps(metadata).encode()).rstrip(b"=").decode()
            ]
        }
    }
    return cmw

if __name__ == "__main__":
    keylime_data = get_keylime_quote()
    if keylime_data:
        try:
            parsed_quote = parse_quote_fields(keylime_data["quote"])
            ima_list = keylime_data.get("ima_measurement_list", "")
            mb_list = keylime_data.get("mb_measurement_list", "")
            cel = build_event_log(ima_list, mb_list)
            metadata = get_keylime_metadata(keylime_data)
            cmw = build_cmw_collection(parsed_quote, cel, metadata)
            print(json.dumps(cmw, indent=2))

        except ValueError as e:
            print(f"Error parsing quote: {e}")
        except Exception as e:
            print(f"An unexpected error occurred: {e}")