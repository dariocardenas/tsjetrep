/**
 * Trep — config generator UI.
 *
 * Loads a config XML and a CSV of users (user,password per line), requests bcrypt
 * hashes from the backend, and generates a merged config XML for download.
 * Selecting a new CSV file cancels any in-flight request.
 */
import html from './trep.html';
import css from './trep.css';
import user from './user.xml';

const TREP_BCRYPT_ENDPOINT = location.hostname === 'localhost' ? null : `${location.protocol}//${location.host}/hashcsv`;

const DEFAULT_BCRYPT_ENDPOINT = 'http://localhost:8787/hashcsv';
const BCRYPT_ENDPOINT = TREP_BCRYPT_ENDPOINT ?? DEFAULT_BCRYPT_ENDPOINT;

console.log('BCRYPT_ENDPOINT', BCRYPT_ENDPOINT);

document.addEventListener('DOMContentLoaded', async () => {
    let confInput, conf = null, counter, ctr, enableButton, usersInput, users = null, generateButton;
    /** AbortController for cancelling in-flight hashing request when a new file is selected. */
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
                hash = node.querySelector('bcrypt-hash'),
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
     * via backend bcrypt endpoint. Shows a progress banner while the request runs.
     *
     * Cancellation: If a new file is selected while a request is in flight, the
     * previous request is aborted via AbortController.
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
                const csvText = String(e.target.result ?? '');
                const total = countCsvDataLines(csvText);
                try {
                    counter({ total: Math.max(total, 1), processed: 0 });
                    const resp = await fetch(BCRYPT_ENDPOINT, {
                        method: 'POST',
                        headers: { 'content-type': 'text/csv' },
                        body: csvText,
                        signal,
                    });
                    if (!resp.ok) {
                        const txt = await resp.text();
                        throw new Error(`Hash service error (${resp.status}): ${txt}`);
                    }
                    /** @type {{user: string, password: string}[]} */
                    const data = await resp.json();
                    users = data.map(({ user, password }) => ({ user, hashedPassword: password }));
                    counter({ total: users.length, processed: users.length });
                    enableButton();
                } catch (err) {
                    if (err.name === 'AbortError' || err.message === 'Cancelled') {
                        // Operation was cancelled, reset state
                        users = null;
                        counter({ total, processed: 0 });
                    } else {
                        users = null;
                        counter({ total, processed: 0 });
                        console.error(err);
                        alert(`Error hashing CSV via backend.\n\nEndpoint: ${BCRYPT_ENDPOINT}\n\n${err?.message ?? err}`);
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

function countCsvDataLines(csvText) {
    const lines = String(csvText)
        .split(/\r?\n/)
        .map((l) => l.trim())
        .filter(Boolean);
    if (lines.length === 0) return 0;
    const first = lines[0];
    const dataLines = /^user\s*,\s*password\s*$/i.test(first) ? lines.slice(1) : lines;
    return dataLines.length;
}