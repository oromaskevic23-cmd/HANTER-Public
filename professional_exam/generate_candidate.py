"""One real local model call after signed test gates + VELION v2 planning.

Untrusted candidate is saved as DATA; never executed in this job. Independent
second GitHub Actions job alone runs it in isolated Docker under secretless QA.
"""
from __future__ import annotations
import hashlib
import json
import os
from pathlib import Path
import re
import time
import urllib.request
from velion_fabric import Task,ModelDescriptor,plan_proposal
from professional_exam.governance import (
    AGENT,ORCHESTRATOR,TENANT,issue_test_only,verify_test_only
)
from hanter_pilot.pilot import Denied

OLLAMA_MODEL="qwen2.5-coder:1.5b"  # Third-party weights; not a VELION-trained foundation model
OLLAMA_URL="http://127.0.0.1:11434/api/generate"
TASK_SPEC=("TRAINING ITERATION 2: A previous implementation omitted the named export and got the bounds wrong. Correct both mistakes. Implement exactly one JavaScript ES module. Use the literal syntax: export function clamp(value, lower, upper) { ... }. Export a named function "
           "clamp(value, lower, upper). Requirements: all three arguments "
           "must be finite primitive JavaScript numbers; otherwise throw TypeError. "
           "If lower > upper, throw RangeError. Return value constrained to the "
           "inclusive interval [lower, upper]. Examples: clamp(10,0,5) is 5, " "clamp(-3,0,5) is 0, clamp(3,0,5) is 3, and clamp(5,5,5) is 5. " "Check all inputs using Number.isFinite (no coercion). No side effects, no imports, no "
           "other exports. Output only JavaScript source, without markdown.")
MAX_BYTES=16384

class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self,req,fp,code,msg,headers,newurl): return None

def canonical(obj):
    return json.dumps(obj,sort_keys=True,separators=(",",":"),ensure_ascii=False,allow_nan=False).encode()

def fetch_candidate(prompt:str)->tuple[str,dict]:
    body=canonical({"model":OLLAMA_MODEL,"prompt":prompt,"stream":False,
                    "keep_alive":0,"options":{"temperature":0,"num_predict":640}})
    request=urllib.request.Request(OLLAMA_URL,data=body,method="POST",headers={
        "Content-Type":"application/json","Accept":"application/json"})
    opener=urllib.request.build_opener(urllib.request.ProxyHandler({}),NoRedirect()).open
    with opener(request,timeout=180) as response:
        if "application/json" not in response.headers.get("Content-Type",""):
            raise Denied("MODEL_RESPONSE_CONTENT_TYPE_DENIED")
        raw=response.read(MAX_BYTES+1)
    if len(raw)>MAX_BYTES: raise Denied("MODEL_RESPONSE_TOO_BIG")
    result=json.loads(raw.decode("utf-8"))
    content=result.get("response")
    if (result.get("model")!=OLLAMA_MODEL or result.get("done") is not True or
        type(content) is not str or not 1<=len(content)<=12000):
        raise Denied("MODEL_RESPONSE_INVALID")
    # Remove formatting, not code. Do not evaluate or import the candidate.
    text=content.strip()
    text=re.sub(r"^\x60\x60\x60(?:javascript|js)?\s*\n","",text,flags=re.I)
    text=re.sub(r"\n\x60\x60\x60\s*$","",text)
    if not text: raise Denied("EMPTY_MODEL_PROPOSAL")
    return text,{"generated_tokens":result.get("eval_count"),
                 "inference_nanoseconds":result.get("eval_duration")}

def main():
    if os.environ.get("HANTER_CI_EXAM_OPT_IN")!="CI_SANDBOX_ONLY":
        raise Denied("NO_CI_EXAM_PERMISSION")
    if os.environ.get("IMPERIAL_OWNER_KILL_SWITCH","1")!="0":
        raise Denied("OWNER_KILL_SWITCH")
    model_root=Path(os.environ.get("OLLAMA_MODELS",""))
    manifest=model_root/"manifests/registry.ollama.ai/library/qwen2.5-coder/1.5b"
    if not manifest.is_file(): raise Denied("OLLAMA_MANIFEST_MISSING")
    model_digest=hashlib.sha256(manifest.read_bytes()).hexdigest()
    prompt_sha=hashlib.sha256(TASK_SPEC.encode()).hexdigest()
    plan=plan_proposal(
        Task(task_id="EXAM.WAVE01.SLOT36",tenant_id=TENANT,
             orchestrator_id=ORCHESTRATOR,agent_id=AGENT,
             capability="plan:software",data_class="PUBLIC_SYNTHETIC",
             input_sha256=prompt_sha,mode="MAX"),
        (ModelDescriptor(
            model_id="Qwen2.5Coder.1.5B",provider_id="Ollama.Local",
            capabilities=("plan:software",),
            allowed_data_classes=("PUBLIC_SYNTHETIC",),
            verified_digest=model_digest,local=True,healthy=True,
            supports_max=True,free_only=True,priority=0,
            context_tokens=8192,max_output_tokens=1024),),
        allowed_routes=frozenset({(TENANT,ORCHESTRATOR,AGENT)}),
        kill_switch=False,synthetic_approval=True,
    )
    if (plan["stage"]!="ROUTE_PLAN_ONLY" or plan["execution_authorized"] is not False
        or plan["model_id"]!="Qwen2.5Coder.1.5B"):
        raise Denied("VELION_ROUTE_FAILED")
    t=int(time.time())
    signed=issue_test_only(prompt_sha,now=t)
    auth=verify_test_only(*signed,prompt_sha256=prompt_sha,now=t)
    start=time.monotonic()
    response,metrics=fetch_candidate(TASK_SPEC)
    if time.monotonic()-start>240: raise Denied("MODEL_TIME_BUDGET_EXCEEDED")
    out=Path(os.environ.get("RUNNER_TEMP","/tmp"))/"nca-professional-exam"
    out.mkdir(parents=True,exist_ok=True)
    candidate=out/"candidate.mjs"
    candidate.write_text(response+"\n",encoding="utf-8")
    data={
      "schema":"imperial.nca.professional.exam.v1",
      "team":"NCA-WAVE-01-100","agent_id":AGENT,"orchestrator":ORCHESTRATOR,
      "tenant":TENANT,"model":OLLAMA_MODEL,
      "model_manifest_sha256":model_digest,
      "model_manifest_is_full_weights_verification":False,
      "prompt_sha256":prompt_sha,
      "candidate_sha256":hashlib.sha256(candidate.read_bytes()).hexdigest(),
      "velion_plan":plan,
      "signed_exam_gate":auth,
      "worker":"EPHEMERAL_GITHUB_ACTIONS_RUNNER",
      "real_local_llm_inference":True,"independent_qa_performed":False,
      "production_authorized":False,"owner_cryptographic_approval":False,
      "external_effects":0,"cost_usd_claim":"NOT_MEASURED",
      "metrics":metrics,
    }
    (out/"evidence.json").write_bytes(canonical(data)+b"\n")
    print(json.dumps({"status":"REAL_MODEL_PROPOSAL_COMPLETED_NOT_QA",
                      "agent":AGENT,"candidate_sha256":data["candidate_sha256"],
                      "model":OLLAMA_MODEL,"production_authorized":False},sort_keys=True))

if __name__=="__main__":
    main()
