/**
 * Trep — config generator UI.
 *
 * Loads a config XML and a CSV of users (user,password per line), hashes each
 * password with SHA-512 crypt ($6$), and generates a merged config XML for download.
 * Hashing runs with limited concurrency and yields to the event loop so the UI
 * stays responsive and a progress counter updates as each hash completes.
 * Selecting a new CSV file cancels any in-progress hashing operation.
 */
import html from './trep.html';
import css from './trep.css';
import user from './user.xml';

document.addEventListener('DOMContentLoaded', async () => {
    let confInput, conf = null, counter, ctr, enableButton, usersInput, users = null, generateButton;
    /** AbortController for cancelling in-progress hashing when a new file is selected. */
    let hashAbortController = null;
    document.body.replaceChildren(...new DOMParser().parseFromString(html, 'text/html').body.children);
    document.adoptedStyleSheets = [await (new CSSStyleSheet()).replace(css)];

    ctr = document.querySelector('#counter');
    confInput = document.querySelector('#conf');
    usersInput = document.querySelector('#users');
    generateButton = document.querySelector('#generate');

    /**
     * Generate merged config XML: clone user template per CSV row, fill hashes/uids,
     * then trigger download. Each user gets a sequential UID starting from 2000.
     */
    generateButton.addEventListener('click', () => {
        let userXml = new DOMParser().parseFromString(user, 'text/xml').documentElement,
            nextuid = conf.querySelector('nextuid'), minuid = 2000,
            system = conf.querySelector('system'),
            a = document.createElement('a');

        users.forEach((u, idx) => {
            let node = conf.importNode(userXml, true),
                hash = node.querySelector('sha512-hash'),
                name = node.querySelector('name'),
                descr = node.querySelector('descr'),
                uid = node.querySelector('uid'),
                cdata = conf.createCDATASection(u.user);
            name.textContent = u.user;
            hash.textContent = u.hashedPassword;
            uid.textContent = minuid + idx;
            descr.replaceChildren(cdata);
            system.insertBefore(node, nextuid);
        });

        nextuid.textContent = minuid + users.length;
        a.href = 'data:text/xml;charset=utf-8,' + encodeURIComponent(new XMLSerializer().serializeToString(conf));
        a.download = 'trep.xml';
        a.click();
    });

    /** Enable generate button only when both config and users are loaded. */
    enableButton = () => { generateButton.disabled = !conf || !users; };

    /**
     * Update progress counter in the UI. Shown only while 0 < processed < total.
     * @param {{ total: number, processed: number }} data
     */
    counter = (data) => {
        let { total, processed } = data;
        processed > 0 && processed < total ? ctr.classList.remove('hidden') : ctr.classList.add('hidden');
        ctr.textContent = `Generando claves de usuarios: ${processed}/${total}`;
    };

    /**
     * Load config XML file. Strips existing ctxNN users (e.g., ctx1, ctx2, ...)
     * before merging new users.
     */
    confInput.addEventListener('change', (event) => {
        const file = event.target.files[0];
        conf = null;
        if (file) {
            const reader = new FileReader();
            reader.onload = (e) => {
                conf = new DOMParser().parseFromString(e.target.result, 'text/xml');
                conf.querySelectorAll('user').forEach(u => u.querySelector('name').textContent.match(/^ctx\d+$/) && u.remove());
                enableButton();
            };
            reader.readAsText(file, 'utf-8');
        } else {
            enableButton();
        }
    });

    /**
     * Load users CSV (header row skipped; empty lines ignored). Hash each password
     * with sha512_crypt, update counter only when a hash is returned, and yield
     * after each update so the browser can paint. Concurrency is limited to avoid
     * freezing on large files.
     *
     * Cancellation: If a new file is selected while hashing is in progress, the
     * previous operation is aborted via AbortController. Workers check the signal
     * before and after each hash, and throw 'Cancelled' if aborted. The catch block
     * resets state and hides the counter. The finally block clears the controller
     * only if it's still the same one (to avoid clearing a newer controller if
     * the user selected yet another file during the abort).
     */
    usersInput.addEventListener('change', (event) => {
        const file = event.target.files[0];
        users = null;
        // Cancel previous hashing operation if still running
        if (hashAbortController) {
            hashAbortController.abort();
            hashAbortController = null;
        }
        if (file) {
            const reader = new FileReader();
            reader.onload = async (e) => {
                // Create new AbortController for this operation
                hashAbortController = new AbortController();
                const signal = hashAbortController.signal;
                const lines = e.target.result.split('\n').filter(line => line.trim() !== '').slice(1);
                let processedCount = 0;
                try {
                    users = await mapWithConcurrency(lines, HASH_CONCURRENCY, async (line) => {
                        if (signal.aborted) throw new Error('Cancelled');
                        let user, password, hashedPassword;
                        [user, password] = line.split(',');
                        hashedPassword = await sha512_crypt(password);
                        if (signal.aborted) throw new Error('Cancelled');
                        processedCount += 1;
                        counter({ total: lines.length, processed: processedCount });
                        await new Promise(r => setTimeout(r, 0)); // yield so the browser can paint
                        return { user, hashedPassword };
                    }, signal);
                    enableButton();
                } catch (err) {
                    if (err.message === 'Cancelled') {
                        // Operation was cancelled, reset state
                        users = null;
                        counter({ total: lines.length, processed: 0 });
                    } else {
                        throw err;
                    }
                } finally {
                    // Only clear if this is still the current operation (not superseded by a newer file)
                    if (hashAbortController?.signal === signal) {
                        hashAbortController = null;
                    }
                }
            };
            reader.readAsText(file);
        } else {
            enableButton();
        }
    });
});

/** Max number of sha512_crypt calls in flight at once (avoids freezing UI on large CSVs). */
const HASH_CONCURRENCY = 4;

/**
 * Map over an array with a concurrency limit (worker pool). At most `limit` calls
 * to `fn` run at once; when one completes, the next item is started. Preserves
 * result order. Used so hashing many rows does not block the main thread.
 * Supports cancellation via AbortSignal.
 *
 * @param {Array<T>} array - Input array
 * @param {number} limit - Max concurrent async operations
 * @param {function(T, number): Promise<R>} fn - Async mapper (element, index) -> result
 * @param {AbortSignal} [signal] - Optional abort signal to cancel the operation
 * @returns {Promise<R[]>} Results in same order as array
 * @template T,R
 */
async function mapWithConcurrency(array, limit, fn, signal = null) {
    const results = [];
    let idx = 0;
    /**
     * Worker function: each worker pulls the next index atomically and processes
     * that element. Workers run concurrently up to `limit`, sharing the `idx` counter.
     */
    async function worker() {
        while (idx < array.length) {
            if (signal?.aborted) throw new Error('Cancelled');
            const i = idx++;
            results[i] = await fn(array[i], i);
        }
    }
    await Promise.all(Array.from({ length: Math.min(limit, array.length) }, () => worker()));
    return results;
}

/** Unix crypt base64 alphabet (glibc): ./0-9A-Za-z */
const B64 = './0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz';
/** Max salt length in chars (glibc sha512-crypt). */
const SALT_MAX_LEN = 16;
/** SHA-512 digest size in bytes. */
const DIGEST_LEN = 64;
/** Default iteration count for key derivation. */
const ROUNDS_DEFAULT = 5000;
/** Offset in S digest repeat count: 16 + altResult[0] (per spec). */
const DS_REPEAT_OFFSET = 16;

/**
 * Encode a string to UTF-8 bytes.
 * @param {string} s - String to encode
 * @returns {Uint8Array}
 */
function utf8Encode(s) {
    return new TextEncoder().encode(s);
}

/**
 * Encode 24 bits (b2,b1,b0) as n base64 chars using the crypt alphabet.
 * @param {number} b2 - High byte
 * @param {number} b1 - Middle byte
 * @param {number} b0 - Low byte
 * @param {number} n - Number of output chars (4 for full 24 bits, 2 for last group in SHA-512)
 * @returns {string}
 */
function b64From24bit(b2, b1, b0, n) {
    let w = (b2 << 16) | (b1 << 8) | b0;
    let out = '';
    while (n-- > 0) {
        out += B64[w & 0x3f];
        w >>= 6;
    }
    return out;
}

/**
 * Compute a SHA-512 crypt hash in glibc format ($6$salt$hash).
 * Compatible with Linux crypt(3), /etc/shadow, and mkpasswd -m sha-512.
 * CPU-heavy (5000 rounds); run with limited concurrency to keep the UI responsive.
 *
 * @param {string} password - Password to hash
 * @param {string|null} [salt=null] - Salt (up to 16 chars from [./0-9A-Za-z]). If omitted, a random salt is generated.
 * @returns {Promise<string>} Hash string e.g. "$6$abc123$..."
 */
async function sha512_crypt(password, salt = null) {
    const keyBytes = utf8Encode(password);
    const keyLen = keyBytes.length;

    if (!salt) {
        const raw = new Uint8Array(SALT_MAX_LEN);
        crypto.getRandomValues(raw);
        salt = Array.from(raw, b => B64[b % 64]).join('').slice(0, SALT_MAX_LEN);
    }
    salt = salt.slice(0, SALT_MAX_LEN);
    const saltBytes = utf8Encode(salt);
    const saltLen = saltBytes.length;

    const rounds = ROUNDS_DEFAULT;

    async function sha512(data) {
        const h = await crypto.subtle.digest('SHA-512', data);
        return new Uint8Array(h);
    }

    /* Step: digest B = SHA512(key || salt || key) */
    const ctxB = new Uint8Array(keyLen + saltLen + keyLen);
    ctxB.set(keyBytes, 0);
    ctxB.set(saltBytes, keyLen);
    ctxB.set(keyBytes, keyLen + saltLen);
    const sumB = await sha512(ctxB);

    /* Step: digest A = SHA512( key || salt || sumB×blocks || sumB[0..rem] || [per bit of keyLen: sumB or key] ) */
    const parts = [keyBytes, saltBytes];
    for (let cnt = keyLen; cnt > DIGEST_LEN; cnt -= DIGEST_LEN) parts.push(sumB);
    if (keyLen % DIGEST_LEN) parts.push(sumB.subarray(0, keyLen % DIGEST_LEN));
    for (let cnt = keyLen; cnt > 0; cnt >>= 1) parts.push((cnt & 1) ? sumB : keyBytes);
    const lenA = parts.reduce((n, p) => n + p.length, 0);
    const streamA = new Uint8Array(lenA);
    let off = 0;
    for (const p of parts) { streamA.set(p, off); off += p.length; }
    let altResult = await sha512(streamA);

    /* Step: P = stretch SHA512(key^keyLen) to length keyLen */
    let dpInput = new Uint8Array(keyLen * keyLen);
    for (let i = 0; i < keyLen; i++) dpInput.set(keyBytes, i * keyLen);
    let dp = await sha512(dpInput);
    const pBytes = new Uint8Array(keyLen);
    for (let i = 0; i < keyLen; i++) pBytes[i] = dp[i % DIGEST_LEN];

    /* Step: S = stretch SHA512(salt^(16+altResult[0])) to length saltLen */
    const dsRepeats = DS_REPEAT_OFFSET + (altResult[0] & 0xff);
    let dsInput = new Uint8Array(saltLen * dsRepeats);
    for (let i = 0; i < dsRepeats; i++) dsInput.set(saltBytes, i * saltLen);
    let ds = await sha512(dsInput);
    const sBytes = new Uint8Array(saltLen);
    for (let i = 0; i < saltLen; i++) sBytes[i] = ds[i % DIGEST_LEN];

    /* Step: rounds loop — alternate P/altResult, S, P; finish with altResult = SHA512(ctxC) */
    for (let r = 0; r < rounds; r++) {
        const ctxC = new Uint8Array(
            (r & 1 ? keyLen : DIGEST_LEN) +
            (r % 3 !== 0 ? saltLen : 0) +
            (r % 7 !== 0 ? keyLen : 0) +
            (r & 1 ? DIGEST_LEN : keyLen)
        );
        let pos = 0;
        if (r & 1) ctxC.set(pBytes.subarray(0, keyLen), pos), pos += keyLen;
        else ctxC.set(altResult, pos), pos += DIGEST_LEN;
        if (r % 3 !== 0) ctxC.set(sBytes, pos), pos += saltLen;
        if (r % 7 !== 0) ctxC.set(pBytes.subarray(0, keyLen), pos), pos += keyLen;
        if (r & 1) ctxC.set(altResult, pos), pos += DIGEST_LEN;
        else ctxC.set(pBytes.subarray(0, keyLen), pos);
        altResult = await sha512(ctxC);
    }

    /* Step: encode 64-byte digest with crypt base64 and SHA-512 byte order (86 chars) */
    const a = altResult;
    let hash = '';
    hash += b64From24bit(a[0], a[21], a[42], 4);
    hash += b64From24bit(a[22], a[43], a[1], 4);
    hash += b64From24bit(a[44], a[2], a[23], 4);
    hash += b64From24bit(a[3], a[24], a[45], 4);
    hash += b64From24bit(a[25], a[46], a[4], 4);
    hash += b64From24bit(a[47], a[5], a[26], 4);
    hash += b64From24bit(a[6], a[27], a[48], 4);
    hash += b64From24bit(a[28], a[49], a[7], 4);
    hash += b64From24bit(a[50], a[8], a[29], 4);
    hash += b64From24bit(a[9], a[30], a[51], 4);
    hash += b64From24bit(a[31], a[52], a[10], 4);
    hash += b64From24bit(a[53], a[11], a[32], 4);
    hash += b64From24bit(a[12], a[33], a[54], 4);
    hash += b64From24bit(a[34], a[55], a[13], 4);
    hash += b64From24bit(a[56], a[14], a[35], 4);
    hash += b64From24bit(a[15], a[36], a[57], 4);
    hash += b64From24bit(a[37], a[58], a[16], 4);
    hash += b64From24bit(a[59], a[17], a[38], 4);
    hash += b64From24bit(a[18], a[39], a[60], 4);
    hash += b64From24bit(a[40], a[61], a[19], 4);
    hash += b64From24bit(a[62], a[20], a[41], 4);
    hash += b64From24bit(0, 0, a[63], 2);

    return `$6$${salt}$${hash}`;
}