import bodyParser from "body-parser";
import express from "express";
import { BASE_ONION_ROUTER_PORT, REGISTRY_PORT, BASE_USER_PORT } from "../config";
import { generateRsaKeyPair, exportPubKey, exportPrvKey, rsaDecrypt, symDecrypt } from "../crypto";
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
    try {
      const keys = await generateRsaKeyPair();
      privateKey = keys.privateKey;
      publicKey = keys.publicKey;

      const pubKeyStr = await exportPubKey(publicKey);

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
      throw error; // Re-throw to prevent starting with invalid state
    }
  };

  await initializeNode();

  onionRouter.get("/status", (req, res) => {
    res.send("live");
  });

  onionRouter.get("/getLastReceivedEncryptedMessage", (req, res) => {
    res.json({ result: lastReceivedEncryptedMessage });
  });

  onionRouter.get("/getLastReceivedDecryptedMessage", (req, res) => {
    res.json({ result: lastReceivedDecryptedMessage });
  });

  onionRouter.get("/getLastMessageDestination", (req, res) => {
    res.json({ result: lastMessageDestination });
  });

  onionRouter.get("/getPrivateKey", async (req, res) => {
    const exported = await exportPrvKey(privateKey);
    res.json({ result: exported });
  });

  onionRouter.post("/forwardMessage", async (req, res) => {
    try {
      console.log(`[Node ${nodeId}] Received message:`, req.body);
      
      const { type, nextDestination, encryptedSymKey, encryptedMessage } = req.body;
      
      if (!encryptedMessage || !encryptedSymKey) {
        console.error(`[Node ${nodeId}] Missing required encryption data`);
        res.status(400).json({ 
          status: "error",
          message: "Missing required encryption data" 
        });
        return;
      }
  
      if (!privateKey) {
        console.error(`[Node ${nodeId}] Private key not available`);
        res.status(500).json({ 
          status: "error",
          message: "Private key not available" 
        });
        return;
      }
  
      // First decrypt the symmetric key using our RSA private key
      console.log(`[Node ${nodeId}] Decrypting symmetric key...`);
      const symmetricKey = await rsaDecrypt(encryptedSymKey, privateKey);
      
      // Then use the symmetric key to decrypt the message
      console.log(`[Node ${nodeId}] Decrypting message...`);
      const decryptedMessage = await symDecrypt(symmetricKey, encryptedMessage);
      
      lastReceivedEncryptedMessage = encryptedMessage;
      lastReceivedDecryptedMessage = decryptedMessage;
      lastMessageDestination = nextDestination || null;
  
      console.log(`[Node ${nodeId}] Decrypted message:`, decryptedMessage);
  
      if (type === "final") {
        // If this is the final node, forward to the destination user
        const finalPayload = JSON.parse(decryptedMessage);
        const userId = finalPayload.userId;
        
        // Decrypt the actual message using the symmetric key
        const userSymKey = await rsaDecrypt(finalPayload.encryptedSymmetricKey, privateKey);
        const userMessage = await symDecrypt(userSymKey, finalPayload.encryptedData);
        
        console.log(`[Node ${nodeId}] Forwarding final message to user ${userId}`);
        await fetch(`http://localhost:${BASE_USER_PORT + userId}/message`, {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
          },
          body: JSON.stringify({ message: userMessage }),
        });
      } else if (nextDestination !== undefined) {
        // Forward to next node in circuit
        console.log(`[Node ${nodeId}] Forwarding to next node ${nextDestination}`);
        const nextPayload = JSON.parse(decryptedMessage);
        await fetch(`http://localhost:${BASE_ONION_ROUTER_PORT + nextDestination}/forwardMessage`, {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
          },
          body: JSON.stringify(nextPayload),
        });
      }
  
      res.json({ status: "success" });
    } catch (error) {
      console.error(`[Node ${nodeId}] Error processing message:`, error);
      res.status(500).json({ 
        status: "error",
        message: "Failed to process message",
        error: error instanceof Error ? error.message : String(error)
      });
    }
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