"""R1CS experiment: python build_circuit.py (No-Merkle and depths 1..16).

Python standard library only. Run from the project root on Windows.
Default: --O1, R1CS/WASM/SYM plus logs, no trusted setup.
Each run gets its own directory; existing compiled_circuits is untouched.
Optional: --setup to generate NEW local experimental keys (not a production ceremony).
"""
import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import secrets
import shutil
import subprocess
import sys

MAX_DEPTH = 16
PTAU_FILE = "pot16_final.ptau"
OUTPUT_DIR = "research_results/r1cs_rebuild"
ANSI = re.compile(r"\x1b\[[0-9;]*m")


def merkle_source(depth):
    return f"""pragma circom 2.0.0;
include "node_modules/circomlib/circuits/poseidon.circom";
template DualMux() {{
    signal input in[2]; signal input s; signal output out[2];
    s * (1 - s) === 0;
    out[0] <== (in[1] - in[0])*s + in[0];
    out[1] <== (in[0] - in[1])*s + in[1];
}}
template MerkleVote(levels) {{
    signal input root; signal input voter_id; signal input secret;
    signal input path_elements[levels]; signal input path_indices[levels];
    component leafHasher = Poseidon(2);
    leafHasher.inputs[0] <== voter_id; leafHasher.inputs[1] <== secret;
    signal leaf <== leafHasher.out;
    component hashers[levels]; component mux[levels];
    signal levelHashes[levels + 1]; levelHashes[0] <== leaf;
    for (var i = 0; i < levels; i++) {{
        path_indices[i] * (1 - path_indices[i]) === 0; 
        mux[i] = DualMux();
        mux[i].in[0] <== levelHashes[i]; mux[i].in[1] <== path_elements[i]; mux[i].s <== path_indices[i];
        hashers[i] = Poseidon(2);
        hashers[i].inputs[0] <== mux[i].out[0]; hashers[i].inputs[1] <== mux[i].out[1];
        levelHashes[i + 1] <== hashers[i].out;
    }}
    root === levelHashes[levels];
}}
component main {{public [root]}} = MerkleVote({depth});
"""

def sha256(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def execute(args, root, log):
    result = subprocess.run([str(x) for x in args], cwd=root,
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    output = ANSI.sub('', result.stdout.decode('utf-8', errors='replace'))
    log.write_text(output, encoding='utf-8')
    if result.returncode:
        raise RuntimeError(f"Command failed ({result.returncode}). See {log}\n{output[-2500:]}")
    return output


def metric(text, pattern):
    match = re.search(pattern, text, re.IGNORECASE | re.MULTILINE)
    if not match:
        raise ValueError(f"Missing statistic: {pattern}")
    return int(match.group(1))


def write_results(folder, metadata, rows):
    (folder / 'results.json').write_text(json.dumps(
        {'environment': metadata, 'results': rows}, ensure_ascii=False, indent=2), encoding='utf-8')
    lines = ['# R1CS 約束數實驗', '',
             '資料為本次執行結果；不是歷史數據。非線性與線性約束分開記錄，總數由 snarkjs 讀取 R1CS。', '',
             '## 執行條件', '', '```json',
             json.dumps(metadata, ensure_ascii=False, indent=2), '```', '',
             '## 已完成結果', '',
             '| 電路 | 樹深 | 非線性約束 | 線性約束 | R1CS 總約束 | Wires |',
             '|---|---:|---:|---:|---:|---:|']
    for r in rows:
        lines.append(f"| {r['circuit']} | {r['depth'] if r['depth'] is not None else '-'} | {r['nonlinear']} | {r['linear']} | {r['total']} | {r['wires']} |")
    lines += ['', '此表不代表證明時間或驗證時間；不同電路的驗證關係與公開資訊不同。',
              '各子目錄保留原始電路副本、R1CS、WASM、SYM、compile.log 與 r1cs_info.log。',
              '若執行中途失敗，本表僅列出已完成項目，請查 run_error.txt。',
              '加上 --setup 時產生的金鑰僅供本機實驗，不能作為正式可信設定完成的證據。', '']
    (folder / 'summary.md').write_text('\n'.join(lines), encoding='utf-8')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--project-dir', type=Path, default=Path.cwd())
    parser.add_argument('--compiler', help='Defaults to project circom.exe on Windows, otherwise PATH circom')
    parser.add_argument('--depths', type=int, nargs='+', default=list(range(1, MAX_DEPTH + 1)))
    parser.add_argument('--optimization', choices=['O0', 'O1', 'O2'], default='O1')
    parser.add_argument('--setup', action='store_true', help='Also generate fresh experimental zkey/vkey files')
    parser.add_argument('--ptau', default=PTAU_FILE)
    args = parser.parse_args()
    if any(d < 1 or d > MAX_DEPTH for d in args.depths):
        parser.error('Depth must be in 1..16')
    root = args.project_dir.resolve()
    compiler = args.compiler or (str(root / 'circom.exe') if os.name == 'nt' else shutil.which('circom'))
    if compiler and Path(compiler).exists():
        compiler = str(Path(compiler).resolve())
    elif compiler:
        compiler = shutil.which(compiler)
    node = shutil.which('node')
    cli = root / 'node_modules/snarkjs/build/cli.cjs'
    nm = root / 'no_merkle_vote.circom'
    for path in (cli, nm, root / 'node_modules/circomlib/circuits/poseidon.circom'):
        if not path.is_file():
            parser.error(f'Missing file: {path}')
    if not compiler or not node:
        parser.error('Cannot find Circom or Node.js')
    ptau = (root / args.ptau).resolve()
    if args.setup and not ptau.is_file():
        parser.error(f'Missing ptau: {ptau}')
    folder = root / OUTPUT_DIR / ('run_' + datetime.now().strftime('%Y%m%d_%H%M%S_%f'))
    folder.mkdir(parents=True)
    metadata = {'status': 'running', 'started_utc': datetime.now(timezone.utc).isoformat(),
                'platform': platform.platform(), 'python': platform.python_version(),
                'optimization': args.optimization, 'requested_depths': sorted(set(args.depths)),
                'setup_requested': args.setup, 'packages': {}, 'source_sha256': {}}
    rows = []
    try:
        metadata['circom'] = execute([compiler, '--version'], root, folder / 'circom_version.log').strip()
        metadata['node'] = execute([node, '--version'], root, folder / 'node_version.log').strip()
        for package in ['snarkjs', 'circomlib', 'circomlibjs']:
            package_json = root / 'node_modules' / package / 'package.json'
            metadata['packages'][package] = json.loads(package_json.read_text(encoding='utf-8'))['version'] if package_json.exists() else None
        for path in [Path(__file__).resolve(), nm, root / 'package-lock.json']:
            if path.is_file():
                metadata['source_sha256'][path.name] = sha256(path)
        # Dependency changes are recorded even if package.json versions are unchanged.
        digest = hashlib.sha256()
        dep_root = root / 'node_modules/circomlib/circuits'
        for path in sorted(dep_root.rglob('*.circom')):
            digest.update(path.relative_to(dep_root).as_posix().encode())
            digest.update(b'\0' + path.read_bytes() + b'\0')
        metadata['circomlib_circuits_sha256'] = digest.hexdigest()
        write_results(folder, metadata, rows)
        jobs = [('no_merkle', None, nm.read_text(encoding='utf-8-sig'))]
        jobs += [(f'merkle_d{d}', d, merkle_source(d)) for d in sorted(set(args.depths))]
        for name, depth, source_text in jobs:
            print(f'Building {name}...', flush=True)
            target = folder / (f'd{depth}' if depth is not None else 'no_merkle')
            target.mkdir()
            source = target / f'{name}.circom'
            source.write_text(source_text, encoding='utf-8')
            cmd = [compiler, source, '--r1cs', '--wasm', '--sym', '--' + args.optimization,
                   '-l', root, '-o', target]
            (target / 'compile_command.json').write_text(json.dumps([str(x) for x in cmd], ensure_ascii=False, indent=2), encoding='utf-8')
            compiled = execute(cmd, root, target / 'compile.log')
            r1cs = target / f'{name}.r1cs'
            info = execute([node, cli, 'r1cs', 'info', r1cs], root, target / 'r1cs_info.log')
            row = {'circuit': name, 'depth': depth,
                   'nonlinear': metric(compiled, r'^non-linear constraints:\s*(\d+)'),
                   'linear': metric(compiled, r'^linear constraints:\s*(\d+)'),
                   'total': metric(info, r'# of Constraints:\s*(\d+)'),
                   'wires': metric(info, r'# of Wires:\s*(\d+)'),
                   'source_sha256': sha256(source), 'r1cs_sha256': sha256(r1cs),
                   'wasm_bytes': (target / f'{name}_js' / f'{name}.wasm').stat().st_size}
            if row['nonlinear'] + row['linear'] != row['total']:
                raise ValueError(f'{name}: constraint totals do not match; inspect logs')
            if args.setup:
                execute([node, cli, 'groth16', 'setup', r1cs, ptau, target / '0000.zkey'], root, target / 'setup.log')
                execute([node, cli, 'zkey', 'contribute', target / '0000.zkey', target / 'final.zkey',
                         '--name=local-experiment', '-e=' + secrets.token_hex(32)], root, target / 'contribute.log')
                execute([node, cli, 'zkey', 'export', 'verificationkey', target / 'final.zkey', target / 'vkey.json'], root, target / 'vkey_export.log')
            rows.append(row)
            write_results(folder, metadata, rows)
            print(f"  nonlinear={row['nonlinear']}, linear={row['linear']}, total={row['total']}", flush=True)
        metadata['status'] = 'completed'
        write_results(folder, metadata, rows)
        print(f'Completed. Results: {folder / "summary.md"}', flush=True)
    except Exception as error:
        metadata['status'] = 'failed'
        (folder / 'run_error.txt').write_text(str(error), encoding='utf-8')
        write_results(folder, metadata, rows)
        print(f'ERROR: {error}\nPartial results: {folder}', file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
