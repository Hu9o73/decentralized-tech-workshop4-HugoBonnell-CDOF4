import bodyParser from "body-parser";
import express from "express";
import { BASE_ONION_ROUTER_PORT, REGISTRY_PORT } from "../config";
import { generateRsaKeyPair, exportPubKey, exportPrvKey, rsaDecrypt } from "../crypto";
import { webcrypto } from 'crypto';

export async function simpleOnionRouter(nodeId: number) {
  const onionRouter = express();
  onionRouter.use(express.json());
  onionRouter.use(bodyParser.json());

  // State management for the router
  let lastReceivedEncryptedMessage: string | null = null;
  let lastReceivedDecryptedMessage: string | null = null;
  let lastMessageDestination: number | null = null;
  let privateKey: webcrypto.CryptoKey | null = null;
  let publicKey: webcrypto.CryptoKey | null = null;

  // Generate keys and register with registry
  const initializeNode = async () => {
    // Generate keys
    const keys = await generateRsaKeyPair();
    privateKey = keys.privateKey;
    publicKey = keys.publicKey;

    // Export public key to string format
    const pubKeyStr = await exportPubKey(publicKey);

    // Register with registry
    try {
      const response = await fetch(`http://localhost:${REGISTRY_PORT}/registerNode`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          nodeId: nodeId,
          pubKey: pubKeyStr
        })
      });

      if (!response.ok) {
        throw new Error(`Failed to register node: ${response.statusText}`);
      }
    } catch (error) {
      console.error(`Failed to register node ${nodeId}:`, error);
    }
  };

  // Initialize the node
  await initializeNode();

  // Basic status route
  onionRouter.get("/status", (req, res) => {
    res.send("live");
  });

  // Route to get the last received encrypted message
  onionRouter.get("/getLastReceivedEncryptedMessage", (req, res) => {
    res.json({ result: lastReceivedEncryptedMessage });
  });

  // Route to get the last received decrypted message
  onionRouter.get("/getLastReceivedDecryptedMessage", (req, res) => {
    res.json({ result: lastReceivedDecryptedMessage });
  });

  // Route to get the last message destination
  onionRouter.get("/getLastMessageDestination", (req, res) => {
    res.json({ result: lastMessageDestination });
  });

  // Route to get the private key (for testing purposes)
  onionRouter.get("/getPrivateKey", async (req, res) => {
    const exported = await exportPrvKey(privateKey);
    res.json({ result: exported });
  });

  // Route to handle message forwarding
  onionRouter.post("/forwardMessage", async (req, res) => {
    const { encryptedMessage, nextDestination } = req.body;
    console.log("[DEBUG] Received message in forwardMessage:", req.body);
    if (!encryptedMessage) {
      console.error("[ERROR] Encrypted message is missing!");
      return res.status(400).json({ status: "Error: Encrypted message is missing!" });
    }
    lastReceivedEncryptedMessage = encryptedMessage;
    lastMessageDestination = nextDestination;
  
    console.log(`Node ${nodeId} received encrypted message:`, encryptedMessage);
  
    // Check if privateKey is not null before decrypting
    if (privateKey) {
      const decryptedMessage = await rsaDecrypt(encryptedMessage, privateKey);
      lastReceivedDecryptedMessage = decryptedMessage;
      console.log(`Node ${nodeId} decrypted message:`, decryptedMessage);
  
      // Forward the message to the next destination
      await fetch(`http://localhost:${nextDestination}/message`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ message: decryptedMessage }),
      });
  
      console.log(`Node ${nodeId} forwarded message to next destination: ${nextDestination}`);
      res.send("success");
    } else {
      console.error(`Node ${nodeId}: Private key is not available`);
      res.status(500).send("Private key is not available");
    }
    return;
  });

  const server = onionRouter.listen(BASE_ONION_ROUTER_PORT + nodeId, () => {
    console.log(
      `Onion router ${nodeId} is listening on port ${
        BASE_ONION_ROUTER_PORT + nodeId
      }`
    );
  });

  return server;
}
