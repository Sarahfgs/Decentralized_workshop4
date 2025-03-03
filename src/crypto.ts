import { webcrypto } from "crypto";

// #############
// ### Utils ###
// #############

// Function to convert ArrayBuffer to Base64 string
function arrayBufferToBase64(buffer: ArrayBuffer): string {
  return Buffer.from(buffer).toString("base64");
}

// Function to convert Base64 string to ArrayBuffer
function base64ToArrayBuffer(base64: string): ArrayBuffer {
  const buff = Buffer.from(base64, "base64");
  return buff.buffer.slice(buff.byteOffset, buff.byteOffset + buff.byteLength);
}

// ################
// ### RSA keys ###
// ################

// Generates a pair of private/public RSA keys
type GenerateRsaKeyPair = {
  publicKey: webcrypto.CryptoKey;
  privateKey: webcrypto.CryptoKey;
};
export async function generateRsaKeyPair(): Promise<GenerateRsaKeyPair> {
  try {
    const keyPair = await webcrypto.subtle.generateKey(
      {
        name: "RSA-OAEP",
        modulusLength: 2048,
        publicExponent: new Uint8Array([1, 0, 1]),
        hash: "SHA-256",
      },
      true, // Extractable keys
      ["encrypt", "decrypt"]
    );

    return {
      publicKey: keyPair.publicKey,
      privateKey: keyPair.privateKey,
    };
  } catch (error) {
    console.error("Error generating RSA key pair:", error);
    throw error;
  }
}

// Export a crypto public key to a base64 string format
export async function exportPubKey(key: webcrypto.CryptoKey): Promise<string> {
  try {
    const exported = await webcrypto.subtle.exportKey("spki", key);
    return arrayBufferToBase64(exported);
  } catch (error) {
    console.error("Error exporting public key:", error);
    throw error;
  }
}

// Export a crypto private key to a base64 string format
export async function exportPrvKey(key: webcrypto.CryptoKey): Promise<string | null> {
  try {
    if (!key) return null;
    const exported = await webcrypto.subtle.exportKey("pkcs8", key);
    return arrayBufferToBase64(exported);
  } catch (error) {
    console.error("Error exporting private key:", error);
    throw error;
  }
}

// Import a base64 string public key to its native format
export async function importPubKey(strKey: string): Promise<webcrypto.CryptoKey> {
  try {
    const buffer = base64ToArrayBuffer(strKey);
    return await webcrypto.subtle.importKey(
      "spki",
      buffer,
      { name: "RSA-OAEP", hash: "SHA-256" },
      true,
      ["encrypt"]
    );
  } catch (error) {
    console.error("Error importing public key:", error);
    throw error;
  }
}

// Import a base64 string private key to its native format
export async function importPrvKey(strKey: string): Promise<webcrypto.CryptoKey> {
  try {
    const buffer = base64ToArrayBuffer(strKey);
    return await webcrypto.subtle.importKey(
      "pkcs8",
      buffer,
      { name: "RSA-OAEP", hash: "SHA-256" },
      true,
      ["decrypt"]
    );
  } catch (error) {
    console.error("Error importing private key:", error);
    throw error;
  }
}

// Encrypt a message using an RSA public key
export async function rsaEncrypt(b64Data: string, strPublicKey: string): Promise<string> {
  try {
    const publicKey = await importPubKey(strPublicKey);
    const encrypted = await webcrypto.subtle.encrypt(
      { name: "RSA-OAEP" },
      publicKey,
      new TextEncoder().encode(b64Data)
    );
    return arrayBufferToBase64(encrypted);
  } catch (error) {
    console.error("Error encrypting data with RSA:", error);
    throw error;
  }
}

// Decrypts a message using an RSA private key
export async function rsaDecrypt(data: string, privateKey: webcrypto.CryptoKey): Promise<string> {
  try {
    const decrypted = await webcrypto.subtle.decrypt(
      { name: "RSA-OAEP" },
      privateKey,
      base64ToArrayBuffer(data)
    );
    return new TextDecoder().decode(decrypted);
  } catch (error) {
    console.error("Error decrypting data with RSA:", error);
    throw error;
  }
}

// ######################
// ### Symmetric keys ###
// ######################


// Generates a random symmetric key
export async function createRandomSymmetricKey(): Promise<webcrypto.CryptoKey> {
  const key = await webcrypto.subtle.generateKey(
    {
      name: "AES-CBC",
      length: 256,  // 256-bit key
    },
    true,  // Extractable
    ["encrypt", "decrypt"]
  );
  return key;
}


// Export a crypto symmetric key to a base64 string format
export async function exportSymKey(key: webcrypto.CryptoKey): Promise<string> {
  try {
    const exported = await webcrypto.subtle.exportKey("raw", key);
    return arrayBufferToBase64(exported);
  } catch (error) {
    console.error("Error exporting symmetric key:", error);
    throw error;
  }
}


export async function importSymKey(strKey: string): Promise<webcrypto.CryptoKey> {
  try {
    const buffer = base64ToArrayBuffer(strKey);
    return await webcrypto.subtle.importKey(
      "raw", 
      buffer, 
      { name: "AES-CBC", length: 256 },
      true, 
      ["encrypt", "decrypt"]
    );
  } catch (error) {
    console.error("Error importing symmetric key:", error);
    throw error;
  }
}


// Encrypt a message using a symmetric key
export async function symEncrypt(key: webcrypto.CryptoKey, data: string): Promise<string> {
  try {
    // Generate a random IV (16 bytes for AES-CBC)
    const iv = webcrypto.getRandomValues(new Uint8Array(16));
    
    // Encode the data to a buffer
    const encodedData = new TextEncoder().encode(data);
    
    // Encrypt the data
    const encrypted = await webcrypto.subtle.encrypt(
      {
        name: "AES-CBC",
        iv: iv,
      },
      key,
      encodedData
    );
    
    // Combine IV and encrypted data (IV + encrypted data)
    const combined = new Uint8Array(iv.length + encrypted.byteLength);
    combined.set(iv);
    combined.set(new Uint8Array(encrypted), iv.length);
    
    // Return combined buffer as base64 string
    return arrayBufferToBase64(combined.buffer);
  } catch (error) {
    console.error("Error encrypting data with symmetric key:", error);
    throw error;
  }
}


// Decrypt a message using a symmetric key (updated for AES-CBC)
export async function symDecrypt(strKey: string, encryptedData: string): Promise<string> {
  try {
    // Import the symmetric key from the base64 string
    const key = await importSymKey(strKey);
    
    // Convert encrypted data from base64 to ArrayBuffer
    const data = base64ToArrayBuffer(encryptedData);
    
    // Extract the IV (first 16 bytes) from the data
    const iv = data.slice(0, 16);
    
    // Get the actual encrypted data (everything after the IV)
    const actualEncryptedData = data.slice(16);
    
    // Decrypt the data
    const decrypted = await webcrypto.subtle.decrypt(
      {
        name: "AES-CBC",
        iv: iv,
      },
      key,
      actualEncryptedData
    );
    
    // Return the decrypted text as a string
    return new TextDecoder().decode(decrypted);
  } catch (error) {
    console.error("Error decrypting data with symmetric key:", error);
    throw error;
  }
}
