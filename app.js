// ============================================================
// SHIELD VERIFY - QR ZKP VERIFIER
// ============================================================
//
// Flow:
//   QR code
//      ↓
//   JSON payload
//      ↓
//   Reconstruct Groth16 proof + public signals
//      ↓
//   Verify locally with verification_key.json
//      ↓
//   VERIFIED / INVALID
//
// IMPORTANT:
// - No Firestore lookup.
// - No participant database lookup.
// - No private identity data is extracted from the QR.
// - The QR contains only the proof + public signals.
// - verification_key.json is the verifier's trusted key.
//
// Expected verification_key.json:
//   protocol: groth16
//   curve:    bn128
//   nPublic:  24
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
    // Put verification_key.json beside this app.js.
    verificationKeyUrl: "./verification_key.json",

    // Fallback if your deployment keeps it inside /zkp/.
    verificationKeyFallbackUrl: "./zkp/verification_key.json",

    // Your supplied verification key declares nPublic = 24.
    expectedPublicSignals: 24,

    qrVersion: 1
};


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

            throw new Error(
                "snarkjs could not be loaded."
            );
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

                response =
                    await fetch(
                        VERIFIER_CONFIG.verificationKeyUrl,
                        {
                            cache: "no-store"
                        }
                    );

            } catch (error) {

                console.warn(
                    "Primary verification key request failed.",
                    error
                );
            }

            if (!response || !response.ok) {

                response =
                    await fetch(
                        VERIFIER_CONFIG.verificationKeyFallbackUrl,
                        {
                            cache: "no-store"
                        }
                    );
            }

            if (!response.ok) {

                throw new Error(
                    `Could not load verification_key.json (HTTP ${response.status}).`
                );
            }

            const vkey =
                await response.json();

            validateVerificationKey(vkey);

            return vkey;
        })();

        verificationKeyPromise.catch(() => {
            verificationKeyPromise = null;
        });
    }

    return verificationKeyPromise;
}


// ============================================================
// VALIDATE VERIFICATION KEY
// ============================================================

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
        throw new Error(
            `Unsupported curve: ${vkey.curve}`
        );
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
// QR PAYLOAD FORMAT
// ============================================================
//
// Compact QR format generated by the prover:
//
// {
//   "v": 1,
//   "s": schemeId,
//   "a": [proof.pi_a.x, proof.pi_a.y],
//   "b": [proof.pi_b[0], proof.pi_b[1]],
//   "c": [proof.pi_c.x, proof.pi_c.y],
//   "n": [24 public signals]
// }
//
// The constant Groth16 coordinates are restored here:
//
//   pi_a = [x, y, "1"]
//   pi_b = [[x, y], ["1", "0"]]
//   pi_c = [x, y, "1"]
//
// ============================================================

function parseQRJSON(decodedText) {

    if (!decodedText) {
        throw new Error("QR code is empty.");
    }

    let data;

    try {
        data = JSON.parse(decodedText.trim());
    } catch (error) {
        throw new Error(
            "The QR code does not contain valid JSON."
        );
    }

    if (!data || typeof data !== "object") {
        throw new Error(
            "QR JSON must be an object."
        );
    }

    // --------------------------------------------------------
    // Preferred compact ShieldVerify format
    // --------------------------------------------------------

    if (
        data.v === VERIFIER_CONFIG.qrVersion &&
        Array.isArray(data.a) &&
        Array.isArray(data.b) &&
        Array.isArray(data.c) &&
        Array.isArray(data.n)
    ) {

        if (data.a.length !== 2) {
            throw new Error("Invalid proof field: a.");
        }

        if (
            data.b.length !== 2 ||
            !Array.isArray(data.b[0]) ||
            !Array.isArray(data.b[1])
        ) {
            throw new Error("Invalid proof field: b.");
        }

        if (data.c.length !== 2) {
            throw new Error("Invalid proof field: c.");
        }

        if (
            data.n.length !==
            VERIFIER_CONFIG.expectedPublicSignals
        ) {
            throw new Error(
                `QR contains ${data.n.length} public signals; ` +
                `expected ${VERIFIER_CONFIG.expectedPublicSignals}.`
            );
        }

        return {
            schemeId: data.s,
            publicSignals: data.n.map(String),
            proof: {
                pi_a: [
                    String(data.a[0]),
                    String(data.a[1]),
                    "1"
                ],

                pi_b: [
                    [
                        String(data.b[0][0]),
                        String(data.b[0][1])
                    ],

                    [
                        String(data.b[1][0]),
                        String(data.b[1][1])
                    ]
                ],

                pi_c: [
                    String(data.c[0]),
                    String(data.c[1]),
                    "1"
                ],

                protocol: "groth16",
                curve: "bn128"
            }
        };
    }


    // --------------------------------------------------------
    // Optional full snarkJS JSON format
    //
    // This makes the verifier useful if the QR contains:
    //
    // {
    //   "proof": {...},
    //   "publicSignals": [...]
    // }
    // --------------------------------------------------------

    if (
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
            schemeId:
                data.schemeId ??
                data.s ??
                null,

            publicSignals:
                data.publicSignals.map(String),

            proof:
                normaliseFullProof(
                    data.proof
                )
        };
    }


    throw new Error(
        "Unsupported ShieldVerify proof JSON."
    );
}


// ============================================================
// FULL PROOF NORMALISATION
// ============================================================

function normaliseFullProof(proof) {

    if (!proof || typeof proof !== "object") {
        throw new Error("Proof object is missing.");
    }

    if (
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

        pi_b: proof.pi_b.map(
            point =>
                Array.isArray(point)
                    ? point.map(String)
                    : String(point)
        ),

        pi_c: proof.pi_c.map(String),

        protocol:
            proof.protocol ||
            "groth16",

        curve:
            proof.curve ||
            "bn128"
    };
}


// ============================================================
// VERIFY QR JSON
// ============================================================

async function verifyQRJSON(decodedText) {

    const {
        proof,
        publicSignals,
        schemeId
    } =
        parseQRJSON(decodedText);


    const snarkjs =
        await loadSnarkJS();


    const verificationKey =
        await loadVerificationKey();


    // --------------------------------------------------------
    // The ONLY cryptographic trust decision happens here.
    //
    // snarkJS checks the Groth16 proof against:
    //   1. the trusted verification key
    //   2. the public signals extracted from the QR
    //
    // No database lookup is involved.
    // --------------------------------------------------------

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
                (value, index) =>
                    `
                    <div class="event event-active">
                        Signal ${index + 1}: ${escapeHTML(value)}
                    </div>
                    `
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
                    ? `
                        <p>
                            <strong>Scheme ID:</strong>
                            ${escapeHTML(result.schemeId)}
                        </p>
                    `
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
        </div>
    `;
}


function displayInvalid(reason) {

    resultSection.classList.remove("hidden");
    scanAgainButton.classList.remove("hidden");

    scannerStatus.textContent =
        "Verification failed.";

    resultCard.innerHTML = `
        <div class="verification-result invalid">
            <h2>✕ INVALID</h2>

            <p>
                This QR proof could not be verified.
            </p>

            <p>
                <strong>Reason:</strong>
                ${escapeHTML(reason)}
            </p>
        </div>
    `;
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

        console.warn(
            "Scanner stop:",
            error
        );
    }

    try {
        scanner.clear();
    } catch (error) {

        console.warn(
            "Scanner clear:",
            error
        );
    }

    scanner = null;
    scanning = false;
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
            "Use a modern browser over HTTPS.";

        return;
    }


    await stopScanner();


    let temporaryStream = null;


    try {

        temporaryStream =
            await navigator.mediaDevices.getUserMedia({
                video: true,
                audio: false
            });

    } catch (error) {

        console.error(
            "Camera permission error:",
            error
        );

        scannerStatus.innerHTML =
            "<strong>Camera permission was denied.</strong><br><br>" +
            "Allow camera access for this website and reload.";

        return;
    }


    if (temporaryStream) {

        temporaryStream
            .getTracks()
            .forEach(
                track => track.stop()
            );
    }


    try {

        scanner =
            new Html5Qrcode("reader");

    } catch (error) {

        console.error(
            "Html5Qrcode initialization error:",
            error
        );

        scannerStatus.innerHTML =
            "<strong>QR scanner could not be initialized.</strong>";

        return;
    }


    let cameras;


    try {

        cameras =
            await Html5Qrcode.getCameras();

    } catch (error) {

        console.error(
            "Unable to enumerate cameras:",
            error
        );

        scannerStatus.innerHTML =
            "<strong>Could not detect your camera.</strong><br><br>" +
            "Check your browser camera permissions.";

        return;
    }


    if (!cameras || cameras.length === 0) {

        scannerStatus.innerHTML =
            "<strong>No camera detected.</strong><br><br>" +
            "Make sure your device has a working camera.";

        return;
    }


    let selectedCamera =
        cameras[0];


    const rearCamera =
        cameras.find(
            camera =>
                /back|rear|environment/i
                    .test(
                        camera.label || ""
                    )
        );


    if (rearCamera) {
        selectedCamera = rearCamera;
    }


    const scannerConfig = {

        fps: 10,

        qrbox:
            function (
                viewfinderWidth,
                viewfinderHeight
            ) {

                const minEdge =
                    Math.min(
                        viewfinderWidth,
                        viewfinderHeight
                    );

                const boxSize =
                    Math.floor(
                        minEdge * 0.70
                    );

                return {
                    width: boxSize,
                    height: boxSize
                };
            },

        aspectRatio: 1.0
    };


    try {

        await scanner.start(
            selectedCamera.id,
            scannerConfig,
            onScanSuccess,
            onScanError
        );

        scanning = true;

        scannerStatus.textContent =
            "Camera ready — scan the ZK proof QR code.";

    } catch (error) {

        console.error(
            "Camera start error:",
            error
        );

        scanning = false;

        scannerStatus.innerHTML =
            "<strong>Camera could not be started.</strong><br><br>" +
            escapeHTML(
                error.message ||
                "Unknown camera error."
            );
    }
}


// ============================================================
// QR SCAN SUCCESS
// ============================================================

async function onScanSuccess(
    decodedText,
    decodedResult
) {

    if (
        processingScan ||
        !scanning
    ) {
        return;
    }

    processingScan = true;

    console.log(
        "ZK PROOF QR DETECTED:",
        decodedText
    );


    await stopScanner();


    scannerStatus.textContent =
        "QR detected — extracting proof JSON...";


    try {

        scannerStatus.textContent =
            "QR detected — verifying Groth16 proof...";


        const result =
            await verifyQRJSON(
                decodedText
            );


        if (result.verified) {

            displayVerified(result);

        } else {

            displayInvalid(
                "The Groth16 proof is not valid against the supplied verification key."
            );
        }

    } catch (error) {

        console.error(
            "ZK verification error:",
            error
        );

        displayInvalid(
            error.message ||
            "The QR proof could not be verified."
        );
    }
}


function onScanError(errorMessage) {
    // html5-qrcode calls this continuously while scanning.
    // Do not display transient decode failures.
}


// ============================================================
// SCAN AGAIN
// ============================================================

if (scanAgainButton) {

    scanAgainButton.addEventListener(
        "click",
        startScanner
    );
}


// ============================================================
// INITIALISE
// ============================================================

startScanner().catch(error => {

    console.error(
        "Initial scanner startup failed:",
        error
    );

    scannerStatus.textContent =
        error.message ||
        "Unable to start scanner.";
});


// ============================================================
// OPTIONAL GLOBAL API
// ============================================================
//
// Useful for testing from the browser console:
//
//   ShieldVerifyVerifier.verifyQRJSON(qrText)
//
// ============================================================

window.ShieldVerifyVerifier = {
    verifyQRJSON,
    parseQRJSON,
    loadVerificationKey
};
