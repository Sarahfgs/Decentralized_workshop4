import bodyParser from "body-parser";
import express from "express";
import axios from "axios";
import { BASE_USER_PORT, REGISTRY_PORT, BASE_ONION_ROUTER_PORT } from "../config";
import { rsaEncrypt, symEncrypt, createRandomSymmetricKey, exportSymKey } from "../crypto";

export type SendMessageBody = {
  message: string;
  destinationUserId: number;
};

type Node = {
  nodeId: number;
  pubKey: string;
};

// Extend the type of the layer to allow nextDestination
interface Layer {
  type: string;
  encryptedSymKey: string;
  encryptedMessage: string;
  nextDestination?: string; // Optional property
}

export async function user(userId: number) {
  let lastSentMessage: string | null = null;
  let lastReceivedMessage: string | null = null;
  let lastCircuit: number[] | null = null;

  const _user = express();
  _user.use(express.json());
  _user.use(bodyParser.json());

  // Status route
  _user.get("/status", (req, res) => {
    res.send("live");
  });

  // Route to get last received message
  _user.get("/getLastReceivedMessage", (req, res) => {
    res.json({ result: lastReceivedMessage });
  });

  // Route to get last sent message
  _user.get("/getLastSentMessage", (req, res) => {
    res.json({ result: lastSentMessage });
  });

  // Route to get last circuit
  _user.get("/getLastCircuit", (req, res) => {
    if (!lastCircuit) {
      return res.status(404).json({ result: null });
    }
    return res.json({ result: lastCircuit });
  });

  // Route to receive messages
  _user.post("/message", (req, res) => {
    const { message } = req.body;
    lastReceivedMessage = message;
    res.send("success");
  });

  // Route to send messages
  _user.post("/sendMessage", async (req, res) => {
    try {
      const { message, destinationUserId } = req.body as SendMessageBody;

      // Store the sent message
      lastSentMessage = message;

      console.log(`[User ${userId}] Sending message to user ${destinationUserId}: ${message}`);

      // Fetch registry and select nodes
      const registryResponse = await axios.get(`http://localhost:${REGISTRY_PORT}/getNodeRegistry`);
      const nodes: Node[] = registryResponse.data.nodes;

      if (nodes.length < 3) {
        throw new Error("Not enough onion routers available (minimum 3 required)");
      }

      // Select 3 random nodes for our circuit
      const selectedNodes = selectRandomNodes(nodes, 3);

      // Store the circuit for testing - correct order expected by tests
      lastCircuit = [selectedNodes[0].nodeId, selectedNodes[1].nodeId, selectedNodes[2].nodeId];

      console.log(`[User ${userId}] Created circuit:`, lastCircuit);

      // Create the final payload for the destination user
      const finalPayload = {
        userId: destinationUserId,
        encryptedData: message
      };

      // Encrypt for the exit node
      const layer2SymKey = await createRandomSymmetricKey();
      const exportedLayer2SymKey = await exportSymKey(layer2SymKey);
      const finalPayloadStr = JSON.stringify(finalPayload);

      const layer2 = {
        type: "final",
        encryptedSymKey: await rsaEncrypt(exportedLayer2SymKey, selectedNodes[2].pubKey),
        encryptedMessage: await symEncrypt(layer2SymKey, finalPayloadStr),
      };

      // Encrypt for the middle node
      const layer1SymKey = await createRandomSymmetricKey();
      const exportedLayer1SymKey = await exportSymKey(layer1SymKey);
      const layer1PayloadStr = JSON.stringify(layer2);
      const nextDestination1 = (BASE_ONION_ROUTER_PORT + selectedNodes[2].nodeId).toString().padStart(10, "0");
      const layer1 = {
        type: "relay",
        nextDestination: nextDestination1,
        encryptedSymKey: await rsaEncrypt(exportedLayer1SymKey, selectedNodes[1].pubKey),
        encryptedMessage: await symEncrypt(layer1SymKey, layer1PayloadStr),
      };

      // Encrypt for the entry node
      const layer0SymKey = await createRandomSymmetricKey();
      const exportedLayer0SymKey = await exportSymKey(layer0SymKey);
      const layer0PayloadStr = JSON.stringify(layer1);
      const nextDestination0 = (BASE_ONION_ROUTER_PORT + selectedNodes[1].nodeId).toString().padStart(10, "0");
      const layer0 = {
        type: "relay",
        nextDestination: nextDestination0,
        encryptedSymKey: await rsaEncrypt(exportedLayer0SymKey, selectedNodes[0].pubKey),
        encryptedMessage: await symEncrypt(layer0SymKey, layer0PayloadStr),
      };

      // Send to the entry node
      const entryNodeUrl = `http://localhost:${BASE_ONION_ROUTER_PORT + selectedNodes[0].nodeId}/forwardMessage`;

      await axios.post(entryNodeUrl, layer0);

      res.json({
        status: "Message sent successfully",
        circuit: lastCircuit,
      });
    } catch (error) {
      console.error(`[User ${userId}] Error sending message:`, error);
      res.status(500).json({
        status: "Error sending message",
        error: error instanceof Error ? error.message : String(error)
      });
    }
  });

  const server = _user.listen(BASE_USER_PORT + userId, () => {
    console.log(`User ${userId} is listening on port ${BASE_USER_PORT + userId}`);
  });

  return server;
}

function selectRandomNodes(nodes: Node[], count: number): Node[] {
  const shuffled = [...nodes].sort(() => 0.5 - Math.random());
  return shuffled.slice(0, count);
}
