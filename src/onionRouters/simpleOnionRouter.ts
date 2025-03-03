import bodyParser from "body-parser";
import express from "express";
import { BASE_ONION_ROUTER_PORT, REGISTRY_PORT, BASE_USER_PORT } from "../config";
import { generateRsaKeyPair, exportPubKey, exportPrvKey, rsaDecrypt, symDecrypt } from "../crypto";
import { webcrypto } from 'crypto';

export async function simpleOnionRouter(nodeId: number) {
  const onionRouter = express();
  onionRouter.use(express.json());
  onionRouter.use(bodyParser.json());

  let lastReceivedEncryptedMessage: string | null = null;
  let lastReceivedDecryptedMessage: string | null = null;
  let lastMessageDestination: number | null = null;
  let privateKey: webcrypto.CryptoKey | null = null;
  let publicKey: webcrypto.CryptoKey | null = null;

  const initializeNode = async () => {
    try {
      const keys = await generateRsaKeyPair();
      privateKey = keys.privateKey;
      publicKey = keys.publicKey;

      const pubKeyStr = await exportPubKey(publicKey);

      const response = await fetch(`http://localhost:${REGISTRY_PORT}/registerNode`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ nodeId, pubKey: pubKeyStr }),
      });

      if (!response.ok) {
        throw new Error(`Failed to register node: ${response.statusText}`);
      }
    } catch (error) {
      console.error(`Failed to register node ${nodeId}:`, error);
      throw error;
    }
  };

  // Initialize the node before setting up routes
  await initializeNode();

  // Route to check status
  onionRouter.get("/status", (req, res) => res.send("live"));

  // Route to get last received encrypted message
  onionRouter.get("/getLastReceivedEncryptedMessage", (req, res) => res.json({ result: lastReceivedEncryptedMessage }));

  // Route to get last received decrypted message
  onionRouter.get("/getLastReceivedDecryptedMessage", (req, res) => res.json({ result: lastReceivedDecryptedMessage }));

  // Route to get the last message destination
  onionRouter.get("/getLastMessageDestination", (req, res) => res.json({ result: lastMessageDestination }));

  // Route to get private key
  onionRouter.get("/getPrivateKey", async (req, res) => {
    if (!privateKey) {
      return res.status(500).json({ error: "Private key not available" });
    }

    try {
      const exportedKey = await exportPrvKey(privateKey);
      return res.json({ result: exportedKey });
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : String(error);
      return res.status(500).json({ error: "Failed to export private key", details: errorMessage });
    }
  });

  // POST route to forward messages
  onionRouter.post("/forwardMessage", async (req, res) => {
    const { type, nextDestination, encryptedSymKey, encryptedMessage } = req.body;

    try {
      lastReceivedEncryptedMessage = encryptedMessage;

      if (!privateKey) {
        throw new Error("Private key not available");
      }

      // Decrypt the symmetric key using the private key
      const symmetricKey = await rsaDecrypt(encryptedSymKey, privateKey);
      // Decrypt the message using the symmetric key
      const decryptedMessage = await symDecrypt(symmetricKey, encryptedMessage);
      lastReceivedDecryptedMessage = decryptedMessage;

      const parsedMessage = JSON.parse(decryptedMessage);

      // Handle relay messages
      if (type === "relay") {
        lastMessageDestination = parseInt(nextDestination, 10);
        if (nextDestination) {
          await forwardMessageToNextNode(parsedMessage, lastMessageDestination);
        }
      }
      // Handle final messages (send to the user)
      else if (type === "final") {
        handleFinalMessage(parsedMessage);
      }

      res.json({ status: "success" });
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : String(error);
      res.status(500).json({
        status: "error",
        message: "Failed to process message",
        error: errorMessage,
      });
    }
  });

  // Helper function to forward message to the next node
  const forwardMessageToNextNode = async (message: any, destination: number) => {
    const formattedDestination = destination.toString().padStart(10, "0");
    await fetch(`http://localhost:${formattedDestination}/forwardMessage`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(message),
    });
  };

  // Handle the final message type (send to user destination)
  const handleFinalMessage = async (message: any) => {
    if (message.userId !== undefined) {
      const userPort = BASE_USER_PORT + message.userId;
      lastMessageDestination = userPort;
      lastReceivedDecryptedMessage = message.encryptedData;

      await fetch(`http://localhost:${userPort}/message`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ message: message.encryptedData }),
      });
    }
  };

  // Start the server to listen for incoming requests
  const server = onionRouter.listen(BASE_ONION_ROUTER_PORT + nodeId, () => {
    console.log(`Onion router ${nodeId} listening on port ${BASE_ONION_ROUTER_PORT + nodeId}`);
  });

  return server;
}
