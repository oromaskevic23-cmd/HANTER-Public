"""Adversarial Ed25519 signed sandbox gate tests for one registry-selected NCA."""
import hashlib
import os
import time
import unittest
from hanter_pilot.pilot import Denied
from professional_exam.governance import AGENT,issue_test_only,verify_test_only

DIGEST=hashlib.sha256(b"synthetic exam task").hexdigest()
class TestSignedGate(unittest.TestCase):
 def setUp(self):
  self.old_kill=os.environ.get("IMPERIAL_OWNER_KILL_SWITCH")
  self.old_opt=os.environ.get("HANTER_CI_EXAM_OPT_IN")
  os.environ["IMPERIAL_OWNER_KILL_SWITCH"]="0"
  os.environ["HANTER_CI_EXAM_OPT_IN"]="CI_SANDBOX_ONLY"
  self.t=int(time.time())
  self.docs=issue_test_only(DIGEST,now=self.t)
 def tearDown(self):
  for k,v in (("IMPERIAL_OWNER_KILL_SWITCH",self.old_kill),
              ("HANTER_CI_EXAM_OPT_IN",self.old_opt)):
   if v is None:os.environ.pop(k,None)
   else:os.environ[k]=v
 def verify(self,docs=None,**kw):
  return verify_test_only(*(docs or self.docs),prompt_sha256=DIGEST,now=self.t,**kw)
 def test_valid_sandbox_signed_gate(self):
  proof=self.verify()
  self.assertEqual(proof["agent_id"],AGENT)
  self.assertEqual(proof["signed_role_count"],3)
  self.assertFalse(proof["production_authorized"])
 def test_kill_switch_blocks(self):
  os.environ["IMPERIAL_OWNER_KILL_SWITCH"]="1"
  with self.assertRaises(Denied):self.verify()
 def test_missing_synthetic_optin_denies(self):
  os.environ.pop("HANTER_CI_EXAM_OPT_IN")
  with self.assertRaises(Denied):self.verify()
 def test_tampered_passport_denied(self):
  p,g,a,t=self.docs
  changed={"payload":{**p["payload"],"agent":"NCA-INTRUDER"},"signature":p["signature"]}
  with self.assertRaises(Denied):self.verify((changed,g,a,t))
 def test_forged_guardian_denied(self):
  p,g,a,t=self.docs
  changed={"payload":{**g["payload"],"decision":"DENY"},"signature":g["signature"]}
  with self.assertRaises(Denied):self.verify((p,changed,a,t))
 def test_expired_passport_denied(self):
  with self.assertRaises(Denied):
   verify_test_only(*self.docs,prompt_sha256=DIGEST,now=self.t+200)
 def test_revocation_denied(self):
  with self.assertRaises(Denied):self.verify(revoked=frozenset({self.docs[0]["payload"]["jti"]}))
 def test_cross_task_scope_denied(self):
  with self.assertRaises(Denied):
   verify_test_only(*self.docs,prompt_sha256="1"*64,now=self.t)
 def test_swap_approval_invalid(self):
  p,g,a,t=self.docs
  p2,g2,a2,t2=issue_test_only(DIGEST,now=self.t)
  with self.assertRaises(Denied):self.verify((p,g,a2,t))
 def test_altered_task_agent_denied(self):
  p,g,a,t=self.docs
  changed=dict(p);changed["payload"]={**p["payload"],"agent":"OTHER-NCA-001"}
  with self.assertRaises(Denied):self.verify((changed,g,a,t))
 def test_wrong_key_rejected(self):
  p,g,a,t=self.docs
  p2,g2,a2,t2=issue_test_only(DIGEST,now=self.t)
  with self.assertRaises(Denied):self.verify((p,g,a,t2))
 def test_issuer_roles_separated(self):
  p,g,a,t=self.docs
  self.assertNotEqual(p["payload"]["kid"],g["payload"]["kid"])
  self.assertNotEqual(g["payload"]["kid"],a["payload"]["kid"])
 def test_invalid_prompt_digest(self):
  with self.assertRaises(Denied):issue_test_only("not-a-digest",now=self.t)
 def test_no_model_auth_claim(self):
  self.assertFalse(self.verify()["real_owner_authorized"])

if __name__=="__main__":unittest.main()
