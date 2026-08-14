/**
 * PoW Worker - Runs SHA-256 nonce solving in a background Web Worker
 * so the browser UI never freezes during heavy computation.
 *
 * Protocol:
 *   Input (postMessage): { token: string, difficulty: number }
 *   Output (postMessage): { nonce: string, hash: string, attempts: number }
 */

/**
 * Computes SHA-256 of a string using the Web Crypto API.
 * @param {string} data - The data to hash.
 * @returns {Promise<Uint8Array>} The raw SHA-256 digest bytes.
 */
async function sha256(data) {
    const encoder = new TextEncoder();
    const hashBuffer = await crypto.subtle.digest('SHA-256', encoder.encode(data));
    return new Uint8Array(hashBuffer);
}

/**
 * Checks if a hex-encoded SHA-256 hash has the required leading zero hex characters.
 * @param {string} hashHex - Hex-encoded SHA-256 digest.
 * @param {number} difficulty - Number of leading zero hex characters required.
 * @returns {boolean}
 */
function meetsDifficulty(hashHex, difficulty) {
    for (let i = 0; i < difficulty && i < hashHex.length; i++) {
        if (hashHex[i] !== '0') {
            return false;
        }
    }
    return true;
}

/**
 * Attempts to find a nonce such that SHA-256(token + nonce) meets the difficulty.
 * Uses a concurrent approach with multiple workers for speed.
 * @param {string} token - The challenge token.
 * @param {number} difficulty - The required leading-zero difficulty (1-6).
 * @returns {Promise<{nonce: string, hash: string, attempts: number}>}
 */
async function solveChallenge(token, difficulty) {
    const nonceLength = 16;
    const base = token;
    let attempts = 0;
    let nonce = generateRandomNonce(nonceLength);

    // For low difficulties, single-threaded is fine.
    // For higher difficulties, we'll use multiple async workers.
    const workerCount = difficulty > 3 ? navigator.hardwareConcurrency || 4 : 1;
    const chunkSize = 50000;

    if (workerCount === 1) {
        return solveSingleThreaded(base, difficulty, nonceLength);
    }

    // Multi-worker approach for high difficulty.
    const workers = [];
    const results = [];

    for (let i = 0; i < workerCount; i++) {
        const startNonce = generateRandomNonce(nonceLength);
        workers.push(
            solveChunk(base, difficulty, startNonce, chunkSize)
                .then(result => {
                    results.push(result);
                    return result;
                })
                .catch(() => null)
        );
    }

    const result = await Promise.race(workers);
    if (result) {
        return result;
    }

    // If no worker found a solution in the first chunk, keep trying.
    let iteration = 0;
    while (iteration < 1000) {
        iteration++;
        const newWorkers = [];
        for (let i = 0; i < workerCount; i++) {
            const startNonce = generateRandomNonce(nonceLength);
            newWorkers.push(
                solveChunk(base, difficulty, startNonce, chunkSize)
                    .then(r => { if (r) results.push(r); return r; })
                    .catch(() => null)
            );
        }
        const found = await Promise.race(newWorkers);
        if (found) {
            return found;
        }
    }

    throw new Error('PoW solution not found within iteration limit');
}

/**
 * Single-threaded PoW solver (for low difficulty).
 */
async function solveSingleThreaded(token, difficulty, nonceLength) {
    let attempts = 0;
    let nonce = generateRandomNonce(nonceLength);

    while (true) {
        attempts++;
        const data = token + nonce;
        const hashBytes = await sha256(data);
        const hashHex = bufferToHex(hashBytes);

        if (meetsDifficulty(hashHex, difficulty)) {
            return { nonce, hash: hashHex, attempts };
        }

        // Increment nonce as a hex string.
        nonce = incrementHex(nonce);
        if (nonce.length > nonceLength) {
            nonce = generateRandomNonce(nonceLength);
        }
    }
}

/**
 * Solves a chunk of nonces starting from a given nonce.
 */
async function solveChunk(token, difficulty, startNonce, chunkSize) {
    let nonce = startNonce;
    const nonceLength = startNonce.length;

    for (let i = 0; i < chunkSize; i++) {
        const data = token + nonce;
        const hashBytes = await sha256(data);
        const hashHex = bufferToHex(hashBytes);

        if (meetsDifficulty(hashHex, difficulty)) {
            return { nonce, hash: hashHex, attempts: i + 1 };
        }

        nonce = incrementHex(nonce);
        if (nonce.length > nonceLength) {
            nonce = generateRandomNonce(nonceLength);
        }
    }

    return null;
}

/**
 * Generates a random hex nonce of the given length.
 */
function generateRandomNonce(length) {
    const bytes = new Uint8Array(length / 2);
    crypto.getRandomValues(bytes);
    return bufferToHex(bytes);
}

/**
 * Increments a hex string by 1.
 */
function incrementHex(hex) {
    let carry = 1;
    const result = [];
    for (let i = hex.length - 1; i >= 0; i--) {
        const val = parseInt(hex[i], 16) + carry;
        carry = val >> 4;
        result.push((val & 0xf).toString(16));
    }
    if (carry) {
        result.push(carry.toString(16));
    }
    return result.reverse().join('');
}

/**
 * Converts a Uint8Array to a hex string.
 */
function bufferToHex(buffer) {
    return Array.from(buffer)
        .map(b => b.toString(16).padStart(2, '0'))
        .join('');
}

// Worker message handler.
self.onmessage = async function(e) {
    try {
        const { token, difficulty } = e.data;
        const startTime = performance.now();

        const result = await solveChallenge(token, difficulty);
        const elapsed = performance.now() - startTime;

        self.postMessage({
            nonce: result.nonce,
            hash: result.hash,
            attempts: result.attempts,
            elapsed: elapsed,
        });
    } catch (err) {
        self.postMessage({ error: err.message });
    }
};
