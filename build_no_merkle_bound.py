"""Build isolated experimental artifacts. Existing original keys are untouched."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import secrets
import shutil
import subprocess

ROOT = Path(__file__).resolve().parent


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--circom", help="Path to a Circom 2 compiler")
    args = parser.parse_args()
    local = ROOT / ("circom.exe" if os.name == "nt" else "circom")
    compiler = args.circom or (str(local) if local.exists() else shutil.which("circom"))
    if not compiler:
        raise SystemExit("Circom compiler not found; use --circom PATH")
    cli = ROOT / "node_modules/snarkjs/build/cli.cjs"
    ptau = ROOT / "pot12_final.ptau"
    source = ROOT / "no_merkle_bound.circom"
    for path in (cli, ptau, source):
        if not path.is_file():
            raise SystemExit(f"Missing: {path}")
    out = ROOT / "research_results/no_merkle_bound_v1"
    if out.exists():
        raise SystemExit(f"Output already exists: {out}\nRename it before rebuilding; no files overwritten.")
    out.mkdir(parents=True)

    def run(label, command):
        result = subprocess.run([str(x) for x in command], cwd=ROOT,
                                capture_output=True, text=True,
                                encoding="utf-8", errors="replace")
        text = result.stdout + result.stderr
        (out / f"{label}.log").write_text(text, encoding="utf-8")
        print(text, end="", flush=True)
        if result.returncode:
            raise SystemExit(f"{label} failed ({result.returncode}); see {out}")
        return text

    version = run("compiler_version", [compiler, "--version"])
    shutil.copy2(source, out / source.name)
    run("compile_O1", [compiler, source, "--r1cs", "--wasm", "--sym", "--O1", "-o", out])
    snark = ["node", cli]
    r1cs = out / "no_merkle_bound.r1cs"
    run("r1cs_info_O1", snark + ["r1cs", "info", r1cs])
    run("setup", snark + ["groth16", "setup", r1cs, ptau, out / "initial.zkey"])
    # Local simulation setup only: not an independently conducted MPC ceremony.
    run("contribute", snark + ["zkey", "contribute", out / "initial.zkey",
        out / "final.zkey", "--name=local-binding-experiment", "-e=" + secrets.token_hex(32)])
    run("zkey_verify", snark + ["zkey", "verify", r1cs, ptau, out / "final.zkey"])
    run("export_vkey", snark + ["zkey", "export", "verificationkey", out / "final.zkey", out / "vkey.json"])
    manifest = {"compiler": version.strip(), "optimization": "O1",
                "public_signals": ["commitment", "binding", "voteHash"],
                "setup_scope": "local simulation", "sha256": {}}
    for path in [source, r1cs, out / "final.zkey", out / "vkey.json"]:
        manifest["sha256"][path.name] = hashlib.sha256(path.read_bytes()).hexdigest()
    (out / "manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    print("BOUND_BUILD_OK")


if __name__ == "__main__":
    main()
