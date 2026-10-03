# Shield ZK Scanner

## QR structure

The scanner expects the compact Groth16 QR structure:

```json
{
  "v": 1,
  "s": 101,
  "a": ["proof_pi_a_x", "proof_pi_a_y"],
  "b": [
    ["proof_pi_b_x1", "proof_pi_b_y1"],
    ["proof_pi_b_x2", "proof_pi_b_y2"]
  ],
  "c": ["proof_pi_c_x", "proof_pi_c_y"],
  "n": ["public_signal_1", "...", "public_signal_24"]
}
```

`v` = QR format version.

`s` = scheme/event identifier.

`a`, `b`, `c` = compact Groth16 proof coordinates.

`n` = the 24 public signals.

The verifier reconstructs the complete snarkJS proof and checks it against
`verification_key.json`.

## Deployment

1. Keep these files in the same directory:

   - `index.html`
   - `app.js`
   - `verification_key.json`

2. Deploy the directory to a static HTTPS host such as GitHub Pages,
   Netlify, Vercel, or Firebase Hosting.

3. Do NOT open `index.html` directly with `file://`.

4. Camera access requires a secure context. `localhost` is also suitable
   for local development.

5. Open the deployed site on a phone/laptop with a camera.

6. Allow camera permission.

7. Scan the proof QR.

8. The verifier:
   QR -> JSON -> proof/public signals -> verification_key.json ->
   snarkjs.groth16.verify() -> VERIFIED or INVALID.

## Local test

From this directory run:

```bash
python3 -m http.server 8000
```

Then open:

```text
http://localhost:8000/
```

Do not use `file:///.../index.html`.

## Important

The verifier does not query Firestore and does not identify a participant
from a registration ID. Cryptographic verification is performed locally
against the supplied verification key.

The QR does not need to be stored as a `.json` file. It carries the JSON
string directly.
