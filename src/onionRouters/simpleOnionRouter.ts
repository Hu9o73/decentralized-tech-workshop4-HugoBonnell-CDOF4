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
      const { type, nextDestination, encryptedSymKey, encryptedMessage } = req.body;
      
      // Store the encrypted message for later verification - must be raw Base64
      lastReceivedEncryptedMessage = encryptedMessage;
      
      if (!privateKey) {
        throw new Error("Private key not available");
      }
  
      // Decrypt the symmetric key using our private key
      const symmetricKey = await rsaDecrypt(encryptedSymKey, privateKey);
      
      // Use the symmetric key to decrypt the message payload
      const decryptedMessage = await symDecrypt(symmetricKey, encryptedMessage);
      
      // Store the decrypted message - must be Base64
      lastReceivedDecryptedMessage = decryptedMessage;
      
      // Parse the JSON content for forwarding
      const parsedMessage = JSON.parse(decryptedMessage);
      
      // Set the destination for reporting in tests
      if (type === "relay") {
        lastMessageDestination = nextDestination;
      } else if (type === "final") {
        const finalPayload = parsedMessage;
        if (finalPayload.userId !== undefined) {
          lastMessageDestination = BASE_USER_PORT + finalPayload.userId;
          // For the last node, update lastReceivedDecryptedMessage to the actual message
          lastReceivedDecryptedMessage = finalPayload.encryptedData;
        }
      }
      
      // Handle forwarding based on message type
      if (type === "relay" && nextDestination) {
        // Forward to the next node in the circuit
        await fetch(`http://localhost:${nextDestination}/forwardMessage`, {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
          },
          body: JSON.stringify(parsedMessage),
        });
      } else if (type === "final") {
        const finalPayload = parsedMessage;
        if (finalPayload.userId !== undefined) {
          // Send to the destination user
          await fetch(`http://localhost:${BASE_USER_PORT + finalPayload.userId}/message`, {
            method: "POST",
            headers: {
              "Content-Type": "application/json",
            },
            body: JSON.stringify({ message: finalPayload.encryptedData }),
          });
        }
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