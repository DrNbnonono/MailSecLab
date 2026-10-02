import importlib.util
import tempfile
import unittest
from pathlib import Path

try:
    from research import structure, evidence, reference, corpus
except ImportError:
    structure = evidence = reference = corpus = None


class RawStructureTests(unittest.TestCase):
    def setUp(self):
        self.assertIsNotNone(structure, 'raw byte inspector is not implemented')

    def test_obs_and_non_ascii_are_not_silently_normalized(self):
        raw = b'Received : x; Thu, 1 Oct 2026 00:00:00 +0000\r\nRece\xc3\xadved: bad\r\nFrom: a@lab.test\r\n\r\nbody\r\n'
        info = structure.inspect(raw)
        self.assertEqual(info['boundary'], raw.index(b'\r\n\r\n'))
        self.assertEqual([f['syntax'] for f in info['fields']], ['obs', 'invalid', 'modern'])
        self.assertEqual(raw[info['fields'][2]['start']:info['fields'][2]['end']], b'From: a@lab.test\r\n')

    def test_blank_line_is_boundary_even_if_header_follows(self):
        raw = b'X: one\r\n\r\nFrom: victim@lab.test\r\n\r\n'
        self.assertEqual(len(structure.inspect(raw)['fields']), 1)

    def test_bare_lf_and_orphan_folding_are_flagged(self):
        info = structure.inspect(b' orphan\r\nX: a\nb\r\n\r\nb')
        self.assertIn('bare-lf', info['issues'])
        self.assertIn('orphan-continuation', info['issues'])


class EvidenceTests(unittest.TestCase):
    def setUp(self):
        self.assertIsNotNone(evidence, 'immutable evidence writer is not implemented')

    def test_reusing_path_cannot_overwrite_old_raw(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            evidence.write_once(root / 'input.eml', b'original')
            with self.assertRaises(FileExistsError):
                evidence.write_once(root / 'input.eml', b'changed')
            self.assertEqual((root / 'input.eml').read_bytes(), b'original')

    def test_run_id_cannot_escape_results_directory(self):
        with self.assertRaises(ValueError):
            evidence.validate_id('../old-results')
        self.assertEqual(evidence.validate_id('R20261001-bootstrap'), 'R20261001-bootstrap')


class SignatureSelectionTests(unittest.TestCase):
    def setUp(self):
        self.assertIsNotNone(reference, 'independent reference is not implemented')

    def test_bottom_up_and_oversigning_absence(self):
        raw = b'From: first@lab.test\r\nFrom: last@lab.test\r\nSubject: t\r\n\r\nb\r\n'
        selected = reference.select(raw, ['from', 'from', 'from', 'subject'])
        self.assertEqual([item['index'] if item else None for item in selected], [1, 0, None, 2])

    def test_relaxed_canonicalization_has_exact_octets(self):
        self.assertEqual(reference.canonical_header(b'SuBJeCt : \t a\r\n\t b \t\r\n', 'relaxed'), b'subject:a b\r\n')
        self.assertEqual(reference.canonical_body(b'a \t\r\n\r\n', 'relaxed'), b'a\r\n')
        self.assertEqual(reference.canonical_body(b'', 'simple'), b'\r\n')
        self.assertEqual(reference.canonical_body(b'', 'relaxed'), b'')

    def test_mutation_preserves_signature_and_other_fields(self):
        self.assertIsNotNone(corpus, 'fixed-signature corpus is not implemented')
        raw = b'DKIM-Signature: v=1; b=ABC; h=from\r\nFrom: first@lab.test\r\nSubject: t\r\nMessage-ID: <one@lab.test>\r\n\r\nb\r\n'
        changed = corpus.mutate(raw, 'from', 'insert-after')
        self.assertEqual(structure.field_bytes(raw, 'dkim-signature'), structure.field_bytes(changed, 'dkim-signature'))
        self.assertEqual(len(structure.field_bytes(changed, 'message-id')), 1)
        self.assertEqual(len(structure.field_bytes(changed, 'from')), 2)

    def test_wrong_dns_name_returns_no_key(self):
        self.assertEqual(reference.lookup_key('research._domainkey.other.test', {'research._domainkey.lab.test': b'KEY'}), None)
        self.assertEqual(reference.lookup_key('RESEARCH._DOMAINKEY.LAB.TEST.', {'research._domainkey.lab.test': b'KEY'}), b'KEY')


if __name__ == '__main__':
    unittest.main()
