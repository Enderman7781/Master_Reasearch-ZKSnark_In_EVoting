const express = require('express');
const snarkjs = require('snarkjs');
const path = require('path');

const app = express();
app.use(express.json());

const CIRCUITS_DIR = path.join(__dirname, 'compiled_circuits');

app.post('/api/prove/merkle', async (req, res) => {
    const { input, depth } = req.body;

    if (!input || !depth) {
        return res.status(400).json({ error: "Missing input or depth parameter" });
    }

    const wasmPath = path.join(CIRCUITS_DIR, `d${depth}`, `merkle_d${depth}_js`, `merkle_d${depth}.wasm`);
    const zkeyPath = path.join(CIRCUITS_DIR, `d${depth}`, `final.zkey`);

    try {
        // Execute the full proving process in memory without booting a new Node process
        const { proof, publicSignals } = await snarkjs.groth16.fullProve(input, wasmPath, zkeyPath);
        
        return res.json({
            success: true,
            proof: proof,
            publicSignals: publicSignals
        });
    } catch (error) {
        console.error(`Proof generation failed for depth ${depth}:`, error);
        return res.status(500).json({ error: error.message });
    }
});

// --- No-Merkle Proving Endpoint ---
app.post('/api/prove/no-merkle', async (req, res) => {
    const { input } = req.body;

    if (!input) {
        return res.status(400).json({ error: "Missing input parameter" });
    }

    // 根據你之前的 Python 程式碼，對應的檔案路徑
    const wasmPath = path.join(__dirname, 'no_merkle_vote_js', 'no_merkle_vote.wasm');
    const zkeyPath = path.join(__dirname, 'no_merkle_vote_final.zkey');

    try {
        const { proof, publicSignals } = await snarkjs.groth16.fullProve(input, wasmPath, zkeyPath);
        
        return res.json({
            success: true,
            proof: proof,
            publicSignals: publicSignals
        });
    } catch (error) {
        console.error(`No-Merkle Proof generation failed:`, error);
        return res.status(500).json({ error: error.message });
    }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`ZKP Proving Server is running on port ${PORT}`);
});