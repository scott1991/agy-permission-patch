"""Offline checks: no model calls, live installation, or real backup deletion."""
import hashlib
import contextlib
import io
import json
from pathlib import Path
import shutil
import struct
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import fast_patch_update as fast
from patch_skip_permissions import adrp


def digest(data):
    return hashlib.sha256(data).hexdigest()


def fixture(base=0x100000000):
    raw = bytearray(0x1000)
    struct.pack_into('<IIIIIIII', raw, 0, 0xfeedfacf, 0x100000c, 0, 2, 1, 72, 0, 0)
    struct.pack_into('<II16sQQQQiiII', raw, 32, 0x19, 72, b'__TEXT',
                     base, len(raw), 0, len(raw), 7, 7, 0, 0)
    raw[0x200:0x200 + 28] = b'dangerously-skip-permissions'
    marker = b'Always-proceed: auto-approving tool confirmation %q at step %d'
    raw[0x300:0x300 + len(marker)] = marker

    def pair(pc, address, reg):
        return [adrp(pc, address, reg), 0x91000000 | ((address & 4095) << 10) | reg << 5 | reg]

    init_words = (pair(base + 0x100, base + 0x700, 2)
                  + pair(base + 0x108, base + 0x200, 3)
                  + [0xb27e0be4, 0xd503201f, 0xd503201f, 0xd503201f, 0x94000000])
    handler_words = list(fast.MODE_CHECK) + pair(base + 0x400 + len(fast.MODE_CHECK) * 4, base + 0x300, 6)
    handler_words += [0xd503201f] * 6
    init = [(base + 0x100 + i * 4, word, 'test') for i, word in enumerate(init_words)]
    handler = [(base + 0x400 + i * 4, word, 'test') for i, word in enumerate(handler_words)]
    for pc, word, _ in init + handler:
        struct.pack_into('<I', raw, pc - base, word)
    plan = {'padding_candidates': [{'address': hex(base + 0xf00)}]}
    return bytes(raw), plan, init, handler


class LocatorTests(unittest.TestCase):
    def test_relocates_instead_of_reusing_absolute_addresses(self):
        for base in (0x100000000, 0x200008000):
            recipe, _ = fast.locate_recipe(*fixture(base))
            self.assertEqual(int(recipe['flag'], 16), base + 0x700)
            self.assertEqual(int(recipe['site'], 16), base + 0x400)
            self.assertEqual(int(recipe['approve'], 16), base + 0x460)
            self.assertFalse(recipe['review']['approve_branch_verified'])

    def test_changed_permission_branch_is_rejected(self):
        raw, plan, init, handler = fixture()
        pc, word, asm = handler[7]
        handler[7] = (pc, word ^ 1, asm)
        with self.assertRaisesRegex(ValueError, 'pattern changed'):
            fast.locate_recipe(raw, plan, init, handler)

    def test_wrong_flag_string_is_rejected(self):
        raw, plan, init, handler = fixture()
        raw = raw[:0x200] + b'X' + raw[0x201:]
        with self.assertRaisesRegex(ValueError, 'Flag binding'):
            fast.locate_recipe(raw, plan, init, handler)

    def test_duplicate_site_is_rejected(self):
        raw, plan, init, handler = fixture()
        handler += [(pc + 0x100, word, asm) for pc, word, asm in handler]
        with self.assertRaisesRegex(ValueError, 'ambiguous'):
            fast.locate_recipe(raw, plan, init, handler)

    def test_scratch_register_liveness_is_rejected(self):
        raw, plan, init, handler = fixture()
        pc, word, _ = handler[-1]
        handler[-1] = (pc, word, 'mov x0, x16')
        with self.assertRaisesRegex(ValueError, 'x16 use'):
            fast.locate_recipe(raw, plan, init, handler)

    def test_automated_review_requires_the_flag_registrar(self):
        raw, plan, init, handler = fixture()
        pc = init[5][0]
        init[5:8] = [(pc, adrp(pc, pc, 5), 'adrp x5'),
                     (pc + 4, 0x910000a5, 'add x5, x5, #0'),
                     (pc + 8, 0xd2800766, 'mov x6, #59')]
        with self.assertRaisesRegex(ValueError, 'Flag registration call changed'):
            fast.locate_recipe(raw, plan, init, handler, {init[8][0]: 'unrelated'})
        with self.assertRaisesRegex(ValueError, 'Auto-approve path changed'):
            fast.locate_recipe(raw, plan, init, handler, {init[8][0]: fast.FLAG_REGISTRAR})

    def test_disassembly_requires_every_instruction_and_the_snapshot_bytes(self):
        raw, _, _, handler = fixture()
        target = dict(name='handleToolConfirmation', address=hex(handler[0][0]),
                      end=hex(handler[-1][0] + 4))
        fast.verify_disassembly(raw, target, handler)
        with self.assertRaisesRegex(ValueError, 'Incomplete disassembly'):
            fast.verify_disassembly(raw, target, handler[:1] + handler[2:])
        pc, word, asm = handler[0]
        with self.assertRaisesRegex(ValueError, 'bytes differ'):
            fast.verify_disassembly(raw, target, [(pc, word ^ 1, asm)] + handler[1:])


class DeliveryTests(unittest.TestCase):
    def test_model_claim_without_approval_log_does_not_pass(self):
        with tempfile.TemporaryDirectory() as tmp:
            case = Path(tmp)

            def fake_run(command, **kwargs):
                kwargs['stdout'].write('AGY_FAST_PATCH_OK\n')
                (case / 'probe.log').write_text('No command executed\n')
                return type('Result', (), {'returncode': 0})()

            with patch.object(fast.subprocess, 'run', side_effect=fake_run):
                with self.assertRaisesRegex(ValueError, 'Smoke test failed'):
                    fast.smoke(case / 'candidate', case, 'probe')

    def test_target_change_prevents_install(self):
        with tempfile.TemporaryDirectory() as tmp:
            case = Path(tmp)
            target, candidate = case / 'agy', case / 'candidate'
            target.write_bytes(b'updated elsewhere')
            candidate.write_bytes(b'patched')
            with self.assertRaisesRegex(ValueError, 'changed since preparation'):
                fast.install(candidate, target, digest(b'original'), case)
            self.assertEqual(target.read_bytes(), b'updated elsewhere')
            self.assertEqual(list(case.glob('agy.original-*')), [])

    def test_install_then_cleanup_keeps_exactly_current_backup(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            case = root / 'updates/current'
            case.mkdir(parents=True)
            target, candidate = root / 'agy', case / 'candidate'
            target.write_bytes(b'original')
            candidate.write_bytes(b'patched')
            with patch.object(fast, 'run'):
                receipt = fast.install(candidate, target, digest(b'original'), case)
            backup = Path(receipt['backup'])
            self.assertEqual(target.read_bytes(), b'patched')
            self.assertEqual(backup.read_bytes(), b'original')
            old = root / ('agy.original-' + digest(b'old')[:12])
            old.write_bytes(b'old')
            unknown = root / 'agy.original-000000000000'
            unknown.write_bytes(b'unknown')
            result = fast.cleanup(receipt, case, toolkit=root)
            self.assertFalse(old.exists())
            self.assertTrue(unknown.exists())
            self.assertTrue(backup.exists())
            self.assertEqual(result['removed_bytes'], 3)
            self.assertEqual(list(root.glob('agy.new-*')), [])

    def test_bad_current_backup_prevents_any_cleanup(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            target = root / 'agy'
            backup = root / ('agy.original-' + digest(b'original')[:12])
            target.write_bytes(b'patched')
            backup.write_bytes(b'corrupt')
            old = root / ('agy.original-' + digest(b'old')[:12])
            old.write_bytes(b'old')
            receipt = dict(installed=str(target), backup=str(backup),
                           signed_sha256=digest(b'patched'), source_sha256=digest(b'original'))
            with self.assertRaisesRegex(ValueError, 'backup invalid'):
                fast.cleanup(receipt, root, toolkit=root)
            self.assertTrue(old.exists())

    def test_complete_fast_apply_uses_one_smoke_and_prunes_duplicates(self):
        """Real patcher + file operations; mock only OS codesign/model execution."""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            raw, plan, init, handler = fixture()
            recipe, _ = fast.locate_recipe(raw, plan, init, handler)
            target = root / 'agy'
            target.write_bytes(raw)
            target.chmod(0o755)
            case = root / 'updates' / digest(raw)[:12]
            (case / 'input').mkdir(parents=True)
            (case / 'input/agy').write_bytes(raw)
            (root / 'recipes').mkdir()
            shutil.copy2(fast.ROOT / 'patch_skip_permissions.py', root / 'patch_skip_permissions.py')
            plan.update(source=str(target), sha256=digest(raw))
            fast.write_json(case / 'analysis-plan.json', plan)
            fast.write_json(case / 'recipe.proposed.json', recipe)
            old = root / ('agy.original-' + digest(b'old')[:12])
            old.write_bytes(b'old')
            actual_run = subprocess.run
            model_calls = []

            def fake_run(argv, **kwargs):
                if argv[0] == 'codesign':
                    return subprocess.CompletedProcess(argv, 0)
                if argv[-1] == '--version':
                    return subprocess.CompletedProcess(argv, 0, stdout='1.3.5\n')
                if '--log-file' in argv:
                    model_calls.append(argv)
                    kwargs['stdout'].write('AGY_FAST_PATCH_OK\n')
                    Path(argv[argv.index('--log-file') + 1]).write_text(
                        'Always-proceed: auto-approving tool confirmation "RunCommand" at step 2\n')
                    return subprocess.CompletedProcess(argv, 0)
                return actual_run(argv, **kwargs)

            with patch.object(fast, 'ROOT', root), patch.object(fast.subprocess, 'run', side_effect=fake_run):
                with contextlib.redirect_stdout(io.StringIO()):
                    fast.apply(case, reviewed=True, full_tests=False)
            receipt = json.loads((case / 'install-receipt.json').read_text())
            self.assertEqual(len(model_calls), 1)
            self.assertEqual(fast.sha(target), receipt['signed_sha256'])
            self.assertEqual(Path(receipt['backup']).read_bytes(), raw)
            self.assertFalse(old.exists())
            self.assertFalse(Path(receipt['candidate']).exists())
            self.assertFalse((case / 'input/agy').exists())
            self.assertTrue((case / 'FAST-RESULT.md').exists())
            self.assertTrue((case / 'cleanup-receipt.json').exists())


if __name__ == '__main__':
    unittest.main()
