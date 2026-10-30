#!/usr/bin/env python3
"""Offline contract: an authorized one-shot ORIGINAL GitHub State App PUT may lose
its response, but the CAS must reconcile original GET without duplicate PUT.
This does not prove a naturally occurring provider transport interruption.
"""
from pathlib import Path
from unittest.mock import patch
import base64
import importlib.util
import json

ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location("r06_ack_canary",
    ROOT/"scripts/issue311-r06-app-fleet-cas-terminal.py")
mod=importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)
assert mod.ACK_LOSS_CANARY=="r-20261030-r06prepareappackloss10"
sent=[]
def actual_http(method,endpoint,token,body):
    sent.append((method,endpoint,token))
    return {"content":{"sha":"a"*40}}
def request(revision):
    proposal={"revision":revision,"terminal":"NO_UPDATE" if revision==2 else None,
              "publisherAuthorized":False,
              "targets":{"pgextwin/test"+str(i):"SUCCESS" for i in range(17)}}
    raw=json.dumps(proposal,sort_keys=True).encode()
    return {"content":base64.b64encode(raw).decode()}
metrics={"putCalls":0,"lostAcks":0}
with patch.object(mod.writer,"api",side_effect=actual_http):
    for revision in (0,1):
        mod.app_cas_api_with_one_shot_ack_loss("PUT","endpoint",request(revision),
                  "one-use-scoped-test-token",mod.ACK_LOSS_CANARY,metrics)
    try:
        mod.app_cas_api_with_one_shot_ack_loss("PUT","endpoint",request(2),
                  "one-use-scoped-test-token",mod.ACK_LOSS_CANARY,metrics)
    except TimeoutError as error:
        assert "AFTER actual" in str(error)
    else:
        raise AssertionError("expected original ACK loss not injected")
    assert metrics=={"putCalls":3,"lostAcks":1}
    assert len(sent)==3
    # A second ambiguous PUT cannot even reach the real transport adapter.
    try:
        mod.app_cas_api_with_one_shot_ack_loss("PUT","endpoint",request(2),
                  "one-use-scoped-test-token",mod.ACK_LOSS_CANARY,metrics)
    except ValueError:
        pass
    else:
        raise AssertionError("duplicate terminal PUT not blocked")
    assert len(sent)==3
    # Any other authenticated central request remains unchanged.
    normal={"putCalls":0,"lostAcks":0}
    mod.app_cas_api_with_one_shot_ack_loss("PUT","endpoint",request(2),
            "one-use-scoped-test-token","r-20261030-r06prepareother11",normal)
    assert normal=={"putCalls":1,"lostAcks":0}
    # A credential-free GET never injects loss.
    mod.app_cas_api_with_one_shot_ack_loss("GET","endpoint",None,
            "one-use-scoped-test-token",mod.ACK_LOSS_CANARY,metrics)
    assert len(sent)==5
print("R06_REAL_APP_ACK_LOSS_AFTER_ACTUAL_PUT_NEGATIVE_CONTRACT_PASS_OFFLINE")
