import json
from pathlib import Path
import sys
import tempfile
import unittest
import zipfile
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"tools"))
from build_skill_plugin import build, build_existing
import posixpath
import re

class TestSkillPluginArchive(unittest.TestCase):
    def test_skill_and_plugin_deterministic_and_manifest_valid(self):
        with tempfile.TemporaryDirectory() as td:
            directory=Path(td)
            a=directory/"skill-a.zip"
            b=directory/"skill-b.zip"
            sa=build(ROOT,a,"skill")
            sb=build(ROOT,b,"skill")
            self.assertEqual(sa["sha256"],sb["sha256"])
            self.assertFalse(sa["installed_in_chatgpt"])
            with zipfile.ZipFile(a) as z:
                self.assertIn("SKILL.md",z.namelist())
                self.assertIn("references/PERMISSIONS.md",z.namelist())
            p=directory/"plugin.zip"
            info=build(ROOT,p,"plugin")
            self.assertFalse(info["remote_permission_granted"])
            with zipfile.ZipFile(p) as z:
                manifest=json.loads(z.read("plugin.json"))
                self.assertEqual(manifest["name"],"windows-bridge-agent")
                self.assertEqual(manifest["extensions"]["com.openai"]["onboardingSkill"],"./skills/setup/SKILL.md")
                self.assertIn("skills/windows-bridge/SKILL.md",z.namelist())

    def test_all_packaged_local_markdown_links_exist(self):
        with tempfile.TemporaryDirectory() as td:
            for mode in ("skill","plugin"):
                output=Path(td)/(mode+".zip")
                build(ROOT,output,mode)
                with zipfile.ZipFile(output) as z:
                    names=set(z.namelist())
                    for name in names:
                        if not name.endswith(".md"):continue
                        for target in re.findall(r"\[[^\]]+\]\(([^\s)]+)\)",z.read(name).decode()):
                            if target.startswith(("https://","http://","#")):continue
                            resolved=posixpath.normpath(posixpath.join(posixpath.dirname(name),target))
                            self.assertIn(resolved,names,(mode,name,target))

    def original(self,path,extra=None):
        metadata={"name":"synthetic-existing-plugin","version":"1.0.0",
                  "apps":"./.app.json","interface":{"displayName":"Existing"}}
        mapping=b'{"apps":{"synthetic-app":{"id":"synthetic-registered-server"}}}\n'
        with zipfile.ZipFile(path,"w") as z:
            z.writestr(".codex-plugin/plugin.json",json.dumps(metadata))
            z.writestr(".app.json",mapping)
            z.writestr("assets/existing.txt",b"KEEP")
            if extra:
                for name,raw in extra.items():z.writestr(name,raw)
        return metadata,mapping

    def test_existing_plugin_mapping_identity_and_other_resources_preserved(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td);original=root/"original.zip"
            meta,mapping=self.original(original)
            before=original.read_bytes()
            out=root/"complete.zip";again=root/"again.zip"
            result=build_existing(ROOT,original,out,"1.1.1")
            repeated=build_existing(ROOT,original,again,"1.1.1")
            self.assertEqual(result["sha256"],repeated["sha256"])
            self.assertTrue(result["mcp_mapping_byte_identical"])
            self.assertFalse(result["installed_in_chatgpt"])
            self.assertEqual(original.read_bytes(),before)
            with zipfile.ZipFile(out) as z:
                self.assertEqual(z.read(".app.json"),mapping)
                self.assertEqual(z.read("assets/existing.txt"),b"KEEP")
                updated=json.loads(z.read(".codex-plugin/plugin.json"))
                self.assertEqual(updated["name"],meta["name"])
                self.assertEqual(updated["version"],"1.1.1")
                self.assertEqual(updated["skills"],"./skills/")
                self.assertIn("skills/windows-bridge/SKILL.md",z.namelist())

    def test_rejects_unsafe_existing_archive_and_preserves_original(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td);original=root/"original.zip"
            self.original(original,{"../outside":b"BAD"})
            with self.assertRaisesRegex(ValueError,"UNSAFE_MEMBER"):
                build_existing(ROOT,original,root/"out.zip","1.1.1")
            self.original(original)
            with self.assertRaisesRegex(ValueError,"PRESERVED"):
                build_existing(ROOT,original,original,"1.1.1")

    def test_duplicate_mapping_and_portable_override_are_not_silently_accepted(self):
        import warnings
        with tempfile.TemporaryDirectory() as td:
            root=Path(td);original=root/"original.zip"
            self.original(original)
            with warnings.catch_warnings():
                warnings.simplefilter("ignore",UserWarning)
                with zipfile.ZipFile(original,"a") as z:z.writestr(".app.json",b"{}")
            with self.assertRaisesRegex(ValueError,"DUPLICATE_MEMBER"):
                build_existing(ROOT,original,root/"out.zip","1.1.1")
            self.original(original,{"plugin.json":b'{"name":"wrong-entry-point"}'})
            with self.assertRaisesRegex(ValueError,"LAYOUT_REQUIRED"):
                build_existing(ROOT,original,root/"out.zip","1.1.1")

if __name__=="__main__":
    unittest.main()
