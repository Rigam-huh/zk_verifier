// ============================================================
// SHIELD VERIFY - QR ZKP VERIFIER
// ============================================================
//
// Flow:
//   QR code (compact base64url payload, format v2)
//      ↓
//   Decode bytes -> Groth16 proof + 24 public signals
//      ↓
//   Verify locally with verification_key.json
//      ↓
//   VERIFIED / INVALID
//
// - No Firestore lookup, no participant database.
// - The QR contains only the proof + public signals.
// - verification_key.json MUST come from the same setup (.zkey)
//   the prover page uses, or every valid proof will look invalid.
//
// ============================================================


// ============================================================
// DOM
// ============================================================

const reader = document.getElementById("reader");
const resultSection = document.getElementById("result-section");
const resultCard = document.getElementById("result-card");
const scannerStatus = document.getElementById("scanner-status");
const scanAgainButton = document.getElementById("scan-again");


// ============================================================
// CONFIGURATION
// ============================================================

const VERIFIER_CONFIG = {
    verificationKeyUrl: "./verification_key.json",
    verificationKeyFallbackUrl: "./zkp/verification_key.json",

    expectedPublicSignals: 24,

    // Binary QR formats written by the prover page (app.js):
    //   v3 (current): compressed proof points, 213 bytes
    //   v2 (older):   uncompressed proof points, 341 bytes
    qrBinaryLengths: { 2: 341, 3: 213 },

    // Legacy JSON QR format (older prover builds).
    qrJsonVersion: 1
};

const SIGNAL_LABELS = [
    "Commitment",
    "Nullifier",
    "Scheme ID",
    "Use age",
    "Use income",
    "Use gender",
    "Use education",
    "Use marital status",
    "Use employment",
    "Use pension",
    "Use government employee",
    "Use income tax",
    "Use health coverage",
    "Age min",
    "Age max",
    "Income max",
    "Required gender",
    "Required education min",
    "Required marital status",
    "Required employment",
    "Required pension",
    "Required government employee",
    "Required income tax",
    "Required health coverage"
];


// ============================================================
// GLOBAL STATE
// ============================================================

let scanner = null;
let scanning = false;
let processingScan = false;

let snarkjsPromise = null;
let verificationKeyPromise = null;


// ============================================================
// HTML ESCAPE
// ============================================================

function escapeHTML(value) {
    if (value === null || value === undefined) return "";

    return String(value)
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#039;");
}


// ============================================================
// LOAD SNARKJS
// ============================================================

function loadScript(url) {
    return new Promise((resolve, reject) => {
        const script = document.createElement("script");

        script.src = url;
        script.onload = () => resolve();
        script.onerror = () =>
            reject(new Error(`Could not load ${url}`));

        document.head.appendChild(script);
    });
}

async function loadSnarkJS() {

    if (window.snarkjs) {
        return window.snarkjs;
    }

    if (!snarkjsPromise) {

        snarkjsPromise = (async () => {

            const urls = [
                "./snarkjs.min.js",
                "https://cdn.jsdelivr.net/npm/snarkjs@0.7.5/build/snarkjs.min.js"
            ];

            for (const url of urls) {

                try {

                    await loadScript(url);

                    if (window.snarkjs) {
                        return window.snarkjs;
                    }

                } catch (error) {

                    console.warn(
                        "ShieldVerify: snarkjs load failed:",
                        url,
                        error
                    );
                }
            }

            throw new Error("snarkjs could not be loaded.");
        })();

        snarkjsPromise.catch(() => {
            snarkjsPromise = null;
        });
    }

    return snarkjsPromise;
}


// ============================================================
// LOAD TRUSTED VERIFICATION KEY
// ============================================================

async function loadVerificationKey() {

    if (!verificationKeyPromise) {

        verificationKeyPromise = (async () => {

            let response;

            try {
                response = await fetch(
                    VERIFIER_CONFIG.verificationKeyUrl,
                    { cache: "no-store" }
                );
            } catch (error) {
                console.warn(
                    "Primary verification key request failed.",
                    error
                );
            }

            if (!response || !response.ok) {
                response = await fetch(
                    VERIFIER_CONFIG.verificationKeyFallbackUrl,
                    { cache: "no-store" }
                );
            }

            if (!response.ok) {
                throw new Error(
                    `Could not load verification_key.json (HTTP ${response.status}).`
                );
            }

            const vkey = await response.json();

            validateVerificationKey(vkey);

            return vkey;
        })();

        verificationKeyPromise.catch(() => {
            verificationKeyPromise = null;
        });
    }

    return verificationKeyPromise;
}


function validateVerificationKey(vkey) {

    if (!vkey || typeof vkey !== "object") {
        throw new Error(
            "verification_key.json is not a valid JSON object."
        );
    }

    if (vkey.protocol !== "groth16") {
        throw new Error(
            `Unsupported proving protocol: ${vkey.protocol}`
        );
    }

    if (vkey.curve !== "bn128") {
        throw new Error(`Unsupported curve: ${vkey.curve}`);
    }

    if (
        Number(vkey.nPublic) !==
        VERIFIER_CONFIG.expectedPublicSignals
    ) {
        throw new Error(
            `Verification key expects ${vkey.nPublic} public signals, ` +
            `but this verifier expects ${VERIFIER_CONFIG.expectedPublicSignals}.`
        );
    }

    if (
        !Array.isArray(vkey.IC) ||
        vkey.IC.length !==
            VERIFIER_CONFIG.expectedPublicSignals + 1
    ) {
        throw new Error(
            "verification_key.json has an unexpected IC length."
        );
    }
}


// ============================================================
// QR PAYLOAD DECODING
// ============================================================
//
// FORMAT v3 (current) is the same as v2 below, except the last 256 bytes
// (the proof) are replaced by 128 bytes of COMPRESSED points:
//   32 bytes A (x + y-sign bit), 64 bytes B, 32 bytes C.
// The y coordinates are recomputed here from the curve equation.
//
// FORMAT v2 (older): base64url text, 341 bytes:
//
//   1   byte    version (2)
//   32  bytes   commitment          (public signal 0)
//   32  bytes   nullifier           (1)
//   4   bytes   schemeId            (2)
//   2   bytes   10 use* flags, first flag = highest bit   (3..12)
//   1   byte    ageMin              (13)
//   1   byte    ageMax              (14)
//   4   bytes   incomeMax           (15)
//   8   bytes   required* values    (16..23)
//   256 bytes   proof: a.x a.y  b00 b01 b10 b11  c.x c.y
//
// FORMAT v1 (legacy): JSON  { v, s, a, b, c, n }
//
// ============================================================

function bytesToBig(bytes) {
    let n = 0n;

    for (const b of bytes) {
        n = (n << 8n) | BigInt(b);
    }

    return n;
}

function fromBase64Url(text) {
    const b64 = String(text)
        .trim()
        .replace(/-/g, "+")
        .replace(/_/g, "/");

    const bin = atob(
        b64 + "=".repeat((4 - (b64.length % 4)) % 4)
    );

    const out = new Uint8Array(bin.length);

    for (let i = 0; i < bin.length; i++) {
        out[i] = bin.charCodeAt(i);
    }

    return out;
}

/* ---------- BN254 base-field math (proof point compression) ---------- */

const FQ =
    21888242871839275222246405745257275088696311157297823662689037894645226208583n;

const FQ_HALF = (FQ - 1n) / 2n;

const fqMod = (a) => ((a % FQ) + FQ) % FQ;

function fqPow(base, exp) {
    let result = 1n;
    let b = fqMod(base);
    let e = exp;

    while (e > 0n) {
        if (e & 1n) result = (result * b) % FQ;
        b = (b * b) % FQ;
        e >>= 1n;
    }

    return result;
}

/* Fp2 element = [c0, c1] meaning c0 + c1*u, with u^2 = -1 */
const f2Add = (a, b) => [fqMod(a[0] + b[0]), fqMod(a[1] + b[1])];

const f2Mul = (a, b) => [
    fqMod(a[0] * b[0] - a[1] * b[1]),
    fqMod(a[0] * b[1] + a[1] * b[0])
];

const f2Conj = (a) => [a[0], fqMod(-a[1])];

const f2IsMinusOne = (a) => a[0] === FQ - 1n && a[1] === 0n;

function f2Pow(base, exp) {
    let result = [1n, 0n];
    let b = base;
    let e = exp;

    while (e > 0n) {
        if (e & 1n) result = f2Mul(result, b);
        b = f2Mul(b, b);
        e >>= 1n;
    }

    return result;
}

function f2Inv(a) {
    const norm = fqMod(a[0] * a[0] + a[1] * a[1]);
    const inv = fqPow(norm, FQ - 2n);

    return [fqMod(a[0] * inv), fqMod(-a[1] * inv)];
}

/* G2 twist constant b' = 3 / (9 + u) */
const G2_B = f2Mul([3n, 0n], f2Inv([9n, 1n]));

/* Square root in Fp2 (p = 3 mod 4). Returns null for a non-square. */
function f2Sqrt(a) {
    if (a[0] === 0n && a[1] === 0n) return [0n, 0n];

    const a1 = f2Pow(a, (FQ - 3n) / 4n);
    const alpha = f2Mul(f2Mul(a1, a1), a);
    const a0 = f2Mul(f2Conj(alpha), alpha);

    if (f2IsMinusOne(a0)) return null;

    const x0 = f2Mul(a1, a);

    const x = f2IsMinusOne(alpha)
        ? f2Mul([0n, 1n], x0)
        : f2Mul(
            f2Pow(f2Add([1n, 0n], alpha), (FQ - 1n) / 2n),
            x0
        );

    const check = f2Mul(x, x);

    return check[0] === a[0] && check[1] === a[1]
        ? x
        : null;
}

const fqSign = (y) => y > FQ_HALF;

const f2Sign = (y) => (y[1] !== 0n ? y[1] : y[0]) > FQ_HALF;

/* 32 bytes: x, with the y-sign in the top bit (x < 2^254, so it is free). */
function decompressG1(bytes) {
    const flag = (bytes[0] & 0x80) !== 0;
    const raw = Uint8Array.from(bytes);

    raw[0] &= 0x7f;

    const x = bytesToBig(raw);

    if (x >= FQ) {
        throw new Error("Invalid proof point (x out of range).");
    }

    const rhs = fqMod(x * x * x + 3n);
    let y = fqPow(rhs, (FQ + 1n) / 4n);

    if (fqMod(y * y) !== rhs) {
        throw new Error("Invalid proof point (not on curve).");
    }

    if (fqSign(y) !== flag) y = fqMod(-y);

    return [x, y];
}

/* 64 bytes: x0 (sign in its top bit) then x1. Returns [[x0,x1],[y0,y1]]. */
function decompressG2(bytes) {
    const flag = (bytes[0] & 0x80) !== 0;
    const first = Uint8Array.from(bytes.slice(0, 32));

    first[0] &= 0x7f;

    const x = [bytesToBig(first), bytesToBig(bytes.slice(32, 64))];

    if (x[0] >= FQ || x[1] >= FQ) {
        throw new Error("Invalid proof point (x out of range).");
    }

    const rhs = f2Add(f2Mul(f2Mul(x, x), x), G2_B);
    let y = f2Sqrt(rhs);

    if (!y) {
        throw new Error("Invalid proof point (not on curve).");
    }

    if (f2Sign(y) !== flag) y = [fqMod(-y[0]), fqMod(-y[1])];

    return [x, y];
}


function parseBinaryQR(decodedText) {

    let bytes;

    try {
        bytes = fromBase64Url(decodedText);
    } catch (error) {
        throw new Error(
            "The QR code is not a ShieldVerify proof."
        );
    }

    const version = bytes[0];
    const expected = VERIFIER_CONFIG.qrBinaryLengths[version];

    if (!expected || bytes.length !== expected) {
        throw new Error(
            `Unsupported proof QR (got ${bytes.length} bytes, ` +
            `format ${version}). Generate a new QR with the current prover page.`
        );
    }

    let offset = 1;

    const take = (n) => {
        const slice = bytes.slice(offset, offset + n);
        offset += n;
        return slice;
    };

    const dec = (n) => bytesToBig(take(n)).toString();

    const signals = [];

    signals.push(dec(32));                 // 0  commitment
    signals.push(dec(32));                 // 1  nullifier
    signals.push(dec(4));                  // 2  schemeId

    const flags = bytesToBig(take(2));

    for (let i = 9; i >= 0; i--) {         // 3..12 use* flags
        signals.push(
            ((flags >> BigInt(i)) & 1n).toString()
        );
    }

    signals.push(dec(1));                  // 13 ageMin
    signals.push(dec(1));                  // 14 ageMax
    signals.push(dec(4));                  // 15 incomeMax

    for (let i = 0; i < 8; i++) {          // 16..23 required*
        signals.push(dec(1));
    }

    let pi_a, pi_b, pi_c;

    if (version === 3) {

        const [ax, ay] = decompressG1(take(32));
        const [[bx0, bx1], [by0, by1]] = decompressG2(take(64));
        const [cx, cy] = decompressG1(take(32));

        pi_a = [ax.toString(), ay.toString(), "1"];
        pi_b = [
            [bx0.toString(), bx1.toString()],
            [by0.toString(), by1.toString()],
            ["1", "0"]
        ];
        pi_c = [cx.toString(), cy.toString(), "1"];

    } else {

        const c = Array.from({ length: 8 }, () => dec(32));

        pi_a = [c[0], c[1], "1"];
        pi_b = [[c[2], c[3]], [c[4], c[5]], ["1", "0"]];
        pi_c = [c[6], c[7], "1"];
    }

    return {
        schemeId: signals[2],
        publicSignals: signals,
        proof: {
            pi_a,
            pi_b,
            pi_c,
            protocol: "groth16",
            curve: "bn128"
        }
    };
}


// ---------- legacy JSON support ----------

function parseLegacyJSON(decodedText) {

    let data;

    try {
        data = JSON.parse(decodedText.trim());
    } catch (error) {
        throw new Error(
            "The QR code does not contain valid JSON."
        );
    }

    if (
        data &&
        data.v === VERIFIER_CONFIG.qrJsonVersion &&
        Array.isArray(data.a) && data.a.length === 2 &&
        Array.isArray(data.b) && data.b.length === 2 &&
        Array.isArray(data.b[0]) && Array.isArray(data.b[1]) &&
        Array.isArray(data.c) && data.c.length === 2 &&
        Array.isArray(data.n)
    ) {

        if (data.n.length !== VERIFIER_CONFIG.expectedPublicSignals) {
            throw new Error(
                `QR contains ${data.n.length} public signals; ` +
                `expected ${VERIFIER_CONFIG.expectedPublicSignals}.`
            );
        }

        return {
            schemeId: data.s,
            publicSignals: data.n.map(String),
            proof: {
                pi_a: [String(data.a[0]), String(data.a[1]), "1"],

                /*
                 * snarkjs expects THREE rows in pi_b. The third is the
                 * constant ["1", "0"]. Omitting it (as an older version
                 * of this verifier did) makes valid proofs fail.
                 */
                pi_b: [
                    [String(data.b[0][0]), String(data.b[0][1])],
                    [String(data.b[1][0]), String(data.b[1][1])],
                    ["1", "0"]
                ],

                pi_c: [String(data.c[0]), String(data.c[1]), "1"],
                protocol: "groth16",
                curve: "bn128"
            }
        };
    }

    if (
        data &&
        data.proof &&
        Array.isArray(data.publicSignals)
    ) {

        if (
            data.publicSignals.length !==
            VERIFIER_CONFIG.expectedPublicSignals
        ) {
            throw new Error(
                `QR contains ${data.publicSignals.length} public signals; ` +
                `expected ${VERIFIER_CONFIG.expectedPublicSignals}.`
            );
        }

        return {
            schemeId: data.schemeId ?? data.s ?? null,
            publicSignals: data.publicSignals.map(String),
            proof: normaliseFullProof(data.proof)
        };
    }

    throw new Error("Unsupported ShieldVerify proof JSON.");
}

function normaliseFullProof(proof) {

    if (
        !proof ||
        !Array.isArray(proof.pi_a) ||
        !Array.isArray(proof.pi_b) ||
        !Array.isArray(proof.pi_c)
    ) {
        throw new Error(
            "Proof must contain pi_a, pi_b and pi_c."
        );
    }

    return {
        pi_a: proof.pi_a.map(String),
        pi_b: proof.pi_b.map((point) =>
            Array.isArray(point)
                ? point.map(String)
                : String(point)
        ),
        pi_c: proof.pi_c.map(String),
        protocol: proof.protocol || "groth16",
        curve: proof.curve || "bn128"
    };
}


// ---------- entry point ----------

function parseQRPayload(decodedText) {

    if (!decodedText || !String(decodedText).trim()) {
        throw new Error("QR code is empty.");
    }

    const text = String(decodedText).trim();

    return text.startsWith("{")
        ? parseLegacyJSON(text)
        : parseBinaryQR(text);
}


// ============================================================
// VERIFY QR TEXT
// ============================================================

async function verifyQRText(decodedText) {

    const { proof, publicSignals, schemeId } =
        parseQRPayload(decodedText);

    const snarkjs =
        await loadSnarkJS();

    const verificationKey =
        await loadVerificationKey();

    /*
     * The only cryptographic trust decision: snarkjs checks the
     * Groth16 proof against the trusted verification key and the
     * public signals taken from the QR.
     */
    const verified =
        await snarkjs.groth16.verify(
            verificationKey,
            publicSignals,
            proof
        );

    return {
        verified: verified === true,
        schemeId,
        publicSignals,
        proof
    };
}

async function handleDecodedText(decodedText) {

    scannerStatus.textContent =
        "QR detected — verifying Groth16 proof...";

    try {

        const result = await verifyQRText(decodedText);

        if (result.verified) {
            displayVerified(result);
        } else {
            displayInvalid(
                "The proof is well-formed but does not verify against this " +
                "verification_key.json. Check that the key comes from the same " +
                "setup (.zkey) as the prover page."
            );
        }

    } catch (error) {

        console.error("ZK verification error:", error);

        displayInvalid(
            error.message ||
            "The QR proof could not be verified."
        );
    }
}


// ============================================================
// DISPLAY RESULT
// ============================================================

function displayVerified(result) {

    resultSection.classList.remove("hidden");
    scanAgainButton.classList.remove("hidden");

    scannerStatus.textContent =
        "Proof verified successfully.";

    const signalRows =
        result.publicSignals
            .map(
                (value, index) => `
                    <div class="event event-active">
                        ${escapeHTML(
                            SIGNAL_LABELS[index] ||
                            `Signal ${index + 1}`
                        )}: ${escapeHTML(value)}
                    </div>`
            )
            .join("");

    resultCard.innerHTML = `
        <div class="verification-result verified">
            <h2>✓ VERIFIED</h2>

            <p>
                The QR proof is valid against the trusted
                verification_key.json.
            </p>

            ${
                result.schemeId !== null &&
                result.schemeId !== undefined
                    ? `<p>
                           <strong>Scheme ID:</strong>
                           ${escapeHTML(result.schemeId)}
                       </p>`
                    : ""
            }

            <h3>Public Signals</h3>

            <div class="event-list">
                ${signalRows}
            </div>

            <p class="quiz-hint">
                Verification was performed locally.
                No participant database lookup was used.
            </p>
        </div>`;
}


function displayInvalid(reason) {

    resultSection.classList.remove("hidden");
    scanAgainButton.classList.remove("hidden");

    scannerStatus.textContent =
        "Verification failed.";

    resultCard.innerHTML = `
        <div class="verification-result invalid">
            <h2>✕ INVALID</h2>

            <p>This QR proof could not be verified.</p>

            <p>
                <strong>Reason:</strong>
                ${escapeHTML(reason)}
            </p>
        </div>`;
}


// ============================================================
// SCANNER LIFECYCLE
// ============================================================

async function stopScanner() {

    if (!scanner) {
        scanning = false;
        return;
    }

    try {
        if (scanning) {
            await scanner.stop();
        }
    } catch (error) {
        console.warn("Scanner stop:", error);
    }

    try {
        scanner.clear();
    } catch (error) {
        console.warn("Scanner clear:", error);
    }

    scanner = null;
    scanning = false;
}


function makeQRBox(viewfinderWidth, viewfinderHeight) {

    // Give the decoder a large square region so the finder and
    // alignment patterns of a dense QR are not cropped.
    const minEdge =
        Math.min(viewfinderWidth, viewfinderHeight);

    const boxSize =
        Math.floor(minEdge * 0.90);

    return {
        width: boxSize,
        height: boxSize
    };
}


// ============================================================
// CAMERA START (high resolution, continuous focus)
// ============================================================
//
// Without explicit constraints most browsers hand html5-qrcode a
// 640x480 stream, which is too coarse for a dense QR code. Ask for
// 1080p, and fall back to the library defaults if that is rejected.

function highResConstraints(cameraArg) {

    const size = {
        width: { ideal: 1920 },
        height: { ideal: 1080 }
    };

    return typeof cameraArg === "string"
        ? { deviceId: { exact: cameraArg }, ...size }
        : { facingMode: { ideal: "environment" }, ...size };
}


async function startWithFallback(cameraArg, config) {

    try {

        await scanner.start(
            cameraArg,
            {
                ...config,
                videoConstraints: highResConstraints(cameraArg)
            },
            onScanSuccess,
            onScanError
        );

    } catch (error) {

        console.warn(
            "High-resolution start failed; retrying with defaults.",
            error
        );

        await scanner.start(
            cameraArg,
            config,
            onScanSuccess,
            onScanError
        );
    }

    // Best effort: keep the dense code in focus (not supported everywhere).
    try {
        await scanner.applyVideoConstraints({
            advanced: [{ focusMode: "continuous" }]
        });
    } catch (_) {}
}


async function startScanner() {

    scanning = false;
    processingScan = false;

    resultSection.classList.add("hidden");
    scanAgainButton.classList.add("hidden");
    resultCard.innerHTML = "";

    scannerStatus.textContent =
        "Requesting camera permission...";


    if (
        !navigator.mediaDevices ||
        !navigator.mediaDevices.getUserMedia
    ) {
        scannerStatus.innerHTML =
            "<strong>Camera API is unavailable.</strong><br><br>" +
            "Use HTTPS or localhost in a modern browser.";
        return;
    }


    await stopScanner();


    try {

        const stream =
            await navigator.mediaDevices.getUserMedia({
                video: {
                    facingMode: { ideal: "environment" },
                    width: { ideal: 1920 },
                    height: { ideal: 1080 }
                },
                audio: false
            });

        stream.getTracks().forEach((track) => track.stop());

    } catch (error) {

        console.error("Camera permission error:", error);

        scannerStatus.innerHTML =
            "<strong>Camera permission was denied.</strong><br><br>" +
            "Allow camera access and reload the page.";

        return;
    }


    try {

        scanner = new Html5Qrcode("reader", { verbose: false });

    } catch (error) {

        console.error("Html5Qrcode initialization error:", error);

        scannerStatus.innerHTML =
            "<strong>QR scanner could not be initialized.</strong>";

        return;
    }


    const config = {
        fps: 8,
        qrbox: makeQRBox,
        aspectRatio: 1.0,
        disableFlip: true,
        formatsToSupport: [Html5QrcodeSupportedFormats.QR_CODE],
        experimentalFeatures: {
            useBarCodeDetectorIfSupported: true
        }
    };


    try {

        await startWithFallback(
            { facingMode: "environment" },
            config
        );

        scanning = true;

        scannerStatus.textContent =
            "Camera ready — hold the complete QR inside the square.";

    } catch (error) {

        console.warn(
            "Environment camera failed; trying enumerated camera.",
            error
        );

        try {

            const cameras = await Html5Qrcode.getCameras();

            if (!cameras || cameras.length === 0) {
                throw new Error("No camera was detected.");
            }

            const rear = cameras.find((c) =>
                /back|rear|environment/i.test(c.label || "")
            );

            const cameraId =
                (rear || cameras[cameras.length - 1]).id;

            await startWithFallback(cameraId, config);

            scanning = true;

            scannerStatus.textContent =
                "Camera ready — hold the complete QR inside the square.";

        } catch (fallbackError) {

            console.error("Camera start error:", fallbackError);

            await stopScanner();

            scannerStatus.innerHTML =
                "<strong>Camera could not be started.</strong><br><br>" +
                escapeHTML(
                    fallbackError.message ||
                    "Unknown camera error."
                );
        }
    }
}


// ============================================================
// IMAGE FILE SCANNING
// ============================================================

async function scanQRImageFile(file) {

    if (!file) return;

    processingScan = true;

    await stopScanner();

    scannerStatus.textContent = "Reading QR image...";

    try {

        const imageScanner = new Html5Qrcode("reader");

        const decodedText =
            await imageScanner.scanFile(file, true);

        try {
            imageScanner.clear();
        } catch (_) {}

        await handleDecodedText(decodedText);

    } catch (error) {

        console.error("QR image scan error:", error);

        displayInvalid(
            "The QR image could not be decoded. " +
            (error.message || "")
        );
    }
}


// ============================================================
// QR SCAN CALLBACKS (defined once)
// ============================================================

async function onScanSuccess(decodedText) {

    if (processingScan || !scanning) {
        return;
    }

    processingScan = true;

    console.log(
        "ZK PROOF QR DETECTED, length:",
        decodedText.length
    );

    await stopScanner();

    await handleDecodedText(decodedText);
}


function onScanError() {
    // html5-qrcode calls this continuously while searching.
    // Transient decode failures are not shown.
}


// ============================================================
// FALLBACKS: scan from a photo, or paste the proof text
// ============================================================

function ensureFallbackControls() {

    if (
        !scannerStatus ||
        document.getElementById("scan-fallbacks")
    ) {
        return;
    }

    const box = document.createElement("div");

    box.id = "scan-fallbacks";

    box.style.cssText =
        "display:flex;gap:10px;flex-wrap:wrap;" +
        "justify-content:center;margin:12px 0;";

    box.innerHTML = `
        <label class="button secondary" style="cursor:pointer;">
            Scan from photo
            <input id="scan-photo" type="file" accept="image/*" hidden>
        </label>

        <button
            type="button"
            id="paste-proof"
            class="button secondary"
        >
            Paste proof text
        </button>`;

    scannerStatus.insertAdjacentElement("afterend", box);

    box
        .querySelector("#scan-photo")
        .addEventListener("change", async (event) => {

            const file = event.target.files && event.target.files[0];

            event.target.value = "";

            await scanQRImageFile(file);
        });

    box
        .querySelector("#paste-proof")
        .addEventListener("click", async () => {

            const text = window.prompt(
                "Paste the proof text read from the QR code:"
            );

            if (!text) return;

            processingScan = true;

            await stopScanner();

            await handleDecodedText(text);
        });
}


// ============================================================
// SCAN AGAIN
// ============================================================

if (scanAgainButton) {
    scanAgainButton.addEventListener("click", startScanner);
}


// ============================================================
// INITIALISE
// ============================================================

ensureFallbackControls();

startScanner().catch((error) => {

    console.error("Initial scanner startup failed:", error);

    scannerStatus.textContent =
        error.message ||
        "Unable to start scanner.";
});


// ============================================================
// OPTIONAL GLOBAL API (browser console testing)
//
//   await ShieldVerifyVerifier.verifyQRText("<qr text>")
// ============================================================

window.ShieldVerifyVerifier = {
    verifyQRText,
    verifyQRJSON: verifyQRText,   // old name kept for compatibility
    parseQRPayload,
    loadVerificationKey,
    scanQRImageFile
};
