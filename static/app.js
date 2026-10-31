const RSA_PSS = { name: "RSA-PSS", hash: "SHA-256" };
const PEM_HEADER = "-----BEGIN PRIVATE KEY-----";
const PEM_FOOTER = "-----END PRIVATE KEY-----";

let backupPem = null; // held in memory only until the user downloads it

const $ = (id) => document.getElementById(id);
const normalize = (name) => name.trim().toLowerCase();


/* ---------------------------------------------------------- helpers */

async function postJson(url, body) {
    const response = await fetch(url, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body),
    });
    const data = await response.json().catch(() => ({}));
    return { ok: response.ok && data.success, data };
}

function bufferToBase64(buffer) {
    let binary = "";
    for (const byte of new Uint8Array(buffer)) {
        binary += String.fromCharCode(byte);
    }
    return btoa(binary);
}

function base64ToBuffer(base64) {
    const binary = atob(base64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
        bytes[i] = binary.charCodeAt(i);
    }
    return bytes.buffer;
}

/* Request a challenge, sign it with the private key, send it for verification. */
async function authenticate(username, privateKey, output) {
    output.innerText = "Requesting challenge...";
    const challenge = await postJson("/challenge", { username });
    if (!challenge.ok) {
        output.innerText = challenge.data.message || "Authentication failed.";
        return false;
    }

    output.innerText = "Signing challenge...";
    const signature = await crypto.subtle.sign(
        { name: "RSA-PSS", saltLength: 32 },
        privateKey,
        new TextEncoder().encode(challenge.data.challenge)
    );

    output.innerText = "Verifying signature...";
    const verify = await postJson("/verify", {
        username,
        signature: bufferToBase64(signature),
    });
    if (!verify.ok) {
        output.innerText = verify.data.message || "Authentication failed.";
        return false;
    }
    return true;
}


/* -------------------------------------------------------- IndexedDB */

function openDb() {
    return new Promise((resolve, reject) => {
        const request = indexedDB.open("PasswordlessAuth", 1);
        request.onupgradeneeded = () =>
            request.result.createObjectStore("keys", { keyPath: "username" });
        request.onsuccess = () => resolve(request.result);
        request.onerror = () => reject(request.error);
    });
}

async function runStoreRequest(mode, action) {
    const db = await openDb();
    try {
        return await new Promise((resolve, reject) => {
            const transaction = db.transaction("keys", mode);
            const request = action(transaction.objectStore("keys"));
            transaction.oncomplete = () => resolve(request.result);
            transaction.onerror = () => reject(transaction.error);
        });
    } finally {
        db.close();
    }
}

const savePrivateKey = (username, privateKey) =>
    runStoreRequest("readwrite", (store) => store.put({ username, privateKey }));

async function getPrivateKey(username) {
    const record = await runStoreRequest("readonly", (store) => store.get(username));
    return record ? record.privateKey : null;
}


/* --------------------------------------------------------- register */

async function registerUser() {
    const result = $("result");
    const username = normalize($("username").value);

    if (!username) {
        result.innerText = "Enter a username";
        return;
    }

    try {
        result.innerText = "Generating RSA-PSS key pair...";
        const keyPair = await crypto.subtle.generateKey(
            { ...RSA_PSS, modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]) },
            true,
            ["sign", "verify"]
        );
        const publicKey = await crypto.subtle.exportKey("jwk", keyPair.publicKey);

        result.innerText = "Sending public key to server...";
        const response = await postJson("/register", {
            username,
            public_key: JSON.stringify(publicKey),
        });
        if (!response.ok) {
            result.innerText = response.data.message || "Registration failed.";
            return;
        }

        // Only now touch local storage, so a failed or duplicate registration
        // can never overwrite an existing key for this username.
        const pkcs8 = await crypto.subtle.exportKey("pkcs8", keyPair.privateKey);
        backupPem =
            PEM_HEADER + "\n" +
            bufferToBase64(pkcs8).match(/.{1,64}/g).join("\n") + "\n" +
            PEM_FOOTER;
        $("backupSection").hidden = false;

        // Store a non-extractable copy for everyday logins.
        const storedKey = await crypto.subtle.importKey("pkcs8", pkcs8, RSA_PSS, false, ["sign"]);
        await savePrivateKey(username, storedKey);

        result.innerText = "Registration successful!";
    } catch (error) {
        console.error(error);
        result.innerText = "Registration failed: " + error.message;
    }
}

function downloadPrivateKey() {
    if (!backupPem) {
        alert("Private key is not available. Please register again.");
        return;
    }

    const url = URL.createObjectURL(new Blob([backupPem], { type: "application/x-pem-file" }));
    const link = document.createElement("a");
    link.href = url;
    link.download = "passwordless-private-key.pem";
    document.body.appendChild(link);
    link.click();
    link.remove();
    URL.revokeObjectURL(url);

    backupPem = null;
    $("backupSection").hidden = true;
    $("result").innerText = "Private key downloaded. Keep it safe.";
}


/* ------------------------------------------------------------ login */

async function loginUser() {
    const result = $("loginResult");
    const username = normalize($("loginUsername").value);

    if (!username) {
        result.innerText = "Please enter your username.";
        return;
    }

    try {
        const privateKey = await getPrivateKey(username);
        if (!privateKey) {
            result.innerText = "Private key not found in this browser.";
            return;
        }
        if (await authenticate(username, privateKey, result)) {
            window.location.href = "/dashboard";
        }
    } catch (error) {
        console.error(error);
        result.innerText = "Login error: " + error.message;
    }
}


/* --------------------------------------------------------- recovery */

async function importPrivateKey() {
    const result = $("recoveryResult");
    const username = normalize($("recoveryUsername").value);
    const file = $("privateKeyFile").files[0];

    if (!username) {
        result.innerText = "Enter your username.";
        return;
    }
    if (!file) {
        result.innerText = "Select your private-key backup file.";
        return;
    }

    try {
        const pem = await file.text();
        if (!pem.includes(PEM_HEADER) || !pem.includes(PEM_FOOTER)) {
            throw new Error("Invalid PKCS#8 PEM file");
        }

        const body = pem.replace(PEM_HEADER, "").replace(PEM_FOOTER, "").replace(/\s/g, "");
        const privateKey = await crypto.subtle.importKey(
            "pkcs8", base64ToBuffer(body), RSA_PSS, false, ["sign"]
        );

        // The server only accepts the key if it matches the registered public key.
        if (!(await authenticate(username, privateKey, result))) {
            return;
        }

        await savePrivateKey(username, privateKey);
        result.innerText = "Account recovered successfully!";
        setTimeout(() => (window.location.href = "/dashboard"), 1000);
    } catch (error) {
        console.error(error);
        result.innerText = "Recovery failed: " + error.message;
    }
}


/* ----------------------------------------------------------- wiring */

$("registerButton")?.addEventListener("click", registerUser);
$("downloadButton")?.addEventListener("click", downloadPrivateKey);
$("loginButton")?.addEventListener("click", loginUser);
$("recoverButton")?.addEventListener("click", importPrivateKey);
