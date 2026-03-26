// 🔐 HUSHH SECURITY MODULE

// ===============================
// 🔑 RANDOM ID GENERATOR
// ===============================
function generateId(prefix = "ID") {
  return prefix + "-" + Math.floor(Math.random() * 100000);
}

// ===============================
// 🔒 SIMPLE HASH (SHA-256)
// ===============================
async function hashData(data) {
  const encoder = new TextEncoder();
  const buffer = encoder.encode(data);

  const hashBuffer = await crypto.subtle.digest("SHA-256", buffer);
  const hashArray = Array.from(new Uint8Array(hashBuffer));

  return hashArray.map(b => b.toString(16).padStart(2, "0")).join("");
}

// ===============================
// 🔐 ENCRYPT DATA (AES-GCM)
// ===============================
async function encryptData(text, key) {
  const enc = new TextEncoder();
  const encoded = enc.encode(text);

  const iv = crypto.getRandomValues(new Uint8Array(12));

  const encrypted = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv },
    key,
    encoded
  );

  return {
    iv: Array.from(iv),
    data: Array.from(new Uint8Array(encrypted))
  };
}

// ===============================
// 🔓 DECRYPT DATA
// ===============================
async function decryptData(encryptedData, key) {
  const dec = new TextDecoder();

  const decrypted = await crypto.subtle.decrypt(
    {
      name: "AES-GCM",
      iv: new Uint8Array(encryptedData.iv)
    },
    key,
    new Uint8Array(encryptedData.data)
  );

  return dec.decode(decrypted);
}

// ===============================
// 🔑 GENERATE AES KEY
// ===============================
async function generateKey() {
  return await crypto.subtle.generateKey(
    {
      name: "AES-GCM",
      length: 256
    },
    true,
    ["encrypt", "decrypt"]
  );
}

// ===============================
// 🔍 RANDOM HASH STRING
// ===============================
function randomHash() {
  return Math.random().toString(36).substring(2, 10);
}

// ===============================
// 🔐 SECURITY FLAGS
// ===============================
const Security = {
  zk: true,
  e2e: true,
  chain: true,
  redact: true
};

// ===============================
// 🔄 TOGGLE SECURITY
// ===============================
function toggleSecurity(type) {
  if (Security[type] !== undefined) {
    Security[type] = !Security[type];
    console.log(`${type} set to`, Security[type]);
  }
}

// ===============================
// EXPORT (if needed)
// ===============================
window.HushhSecurity = {
  generateId,
  hashData,
  encryptData,
  decryptData,
  generateKey,
  randomHash,
  toggleSecurity,
  Security
};