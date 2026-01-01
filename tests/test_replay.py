from __future__ import annotations

import tempfile
from pathlib import Path

from ledger.cas import CasPaths, sha256_bytes, sha256_file, store_blob
from ledger.manifest import Node, Transform, write_node_manifest
from ledger.replay import replay_node


def _init_repo(root: Path) -> None:
    (root / "ledger" / "objects").mkdir(parents=True, exist_ok=True)
    (root / "ledger" / "nodes").mkdir(parents=True, exist_ok=True)
    (root / "ledger" / "refs").mkdir(parents=True, exist_ok=True)


def test_replay_ok_for_derived_node() -> None:
    with tempfile.TemporaryDirectory() as td:
        repo = Path(td)
        _init_repo(repo)
        cas = CasPaths.from_repo_root(repo)

        # Parents (admission nodes)
        p1_path = repo / "p1.bin"
        p2_path = repo / "p2.bin"
        p1_path.write_bytes(b"hello")
        p2_path.write_bytes(b"world")
        p1_id = sha256_file(p1_path)
        p2_id = sha256_file(p2_path)
        store_blob(p1_path, cas, p1_id)
        store_blob(p2_path, cas, p2_id)

        admit_digest = sha256_bytes(b"admit")
        write_node_manifest(
            repo,
            Node(id=p1_id, parents=[], transform=Transform(name="admit", digest=admit_digest, params={})),
        )
        write_node_manifest(
            repo,
            Node(id=p2_id, parents=[], transform=Transform(name="admit", digest=admit_digest, params={})),
        )

        # Transform definition (replayable python script)
        tf = repo / "transform.py"
        tf.write_text(
            """
import argparse, json
from pathlib import Path

ap = argparse.ArgumentParser()
ap.add_argument('--parents-manifest', required=True)
ap.add_argument('--parents-dir', required=True)
ap.add_argument('--params-path', required=True)
ap.add_argument('--out', required=True)
args = ap.parse_args()

parents_manifest = json.loads(Path(args.parents_manifest).read_text())
params = json.loads(Path(args.params_path).read_text())

out = bytearray()
parents_dir = Path(args.parents_dir)
for item in parents_manifest:
    out.extend((parents_dir / item['path']).read_bytes())

suffix = params.get('suffix')
if isinstance(suffix, str):
    out.extend(suffix.encode('utf-8'))

Path(args.out).write_bytes(bytes(out))
""".strip()
            + "\n",
            encoding="utf-8",
        )
        t_id = sha256_file(tf)
        store_blob(tf, cas, t_id)

        # Derived artifact (must equal transform(parents, params))
        out_path = repo / "out.bin"
        out_path.write_bytes(b"helloworld!")
        out_id = sha256_file(out_path)
        store_blob(out_path, cas, out_id)

        write_node_manifest(
            repo,
            Node(
                id=out_id,
                parents=[p1_id, p2_id],
                transform=Transform(
                    name="concat",
                    digest=t_id,
                    params={"suffix": "!"},
                    runner=["python3"],
                ),
            ),
        )

        rr = replay_node(repo, out_id)
        assert rr.ok, rr.errors


def test_replay_detects_mismatch() -> None:
    with tempfile.TemporaryDirectory() as td:
        repo = Path(td)
        _init_repo(repo)
        cas = CasPaths.from_repo_root(repo)

        # Parent
        p1_path = repo / "p1.bin"
        p1_path.write_bytes(b"hello")
        p1_id = sha256_file(p1_path)
        store_blob(p1_path, cas, p1_id)
        admit_digest = sha256_bytes(b"admit")
        write_node_manifest(
            repo,
            Node(id=p1_id, parents=[], transform=Transform(name="admit", digest=admit_digest, params={})),
        )

        # Transform: identity of single parent
        tf = repo / "transform.py"
        tf.write_text(
            """
import argparse, json
from pathlib import Path

ap = argparse.ArgumentParser()
ap.add_argument('--parents-manifest', required=True)
ap.add_argument('--parents-dir', required=True)
ap.add_argument('--params-path', required=True)
ap.add_argument('--out', required=True)
args = ap.parse_args()

parents_manifest = json.loads(Path(args.parents_manifest).read_text())
parents_dir = Path(args.parents_dir)
Path(args.out).write_bytes((parents_dir / parents_manifest[0]['path']).read_bytes())
""".strip()
            + "\n",
            encoding="utf-8",
        )
        t_id = sha256_file(tf)
        store_blob(tf, cas, t_id)

        # Child artifact that does *not* match transform output
        bad = repo / "bad.bin"
        bad.write_bytes(b"EVIL")
        bad_id = sha256_file(bad)
        store_blob(bad, cas, bad_id)

        write_node_manifest(
            repo,
            Node(
                id=bad_id,
                parents=[p1_id],
                transform=Transform(name="id", digest=t_id, params={}, runner=["python3"]),
            ),
        )

        rr = replay_node(repo, bad_id)
        assert not rr.ok
        assert any("derivation mismatch" in e for e in rr.errors)
