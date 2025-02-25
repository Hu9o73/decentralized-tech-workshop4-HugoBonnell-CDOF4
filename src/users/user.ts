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

let lastSentMessage: string | null = null;
let lastReceivedMessage: string | null = null;
let lastCircuit: number[] | null = null;

export async function user(userId: number) {
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

  _user.get("/getLastCircuit", (req, res) => {
    console.log(`[DEBUG] Returning lastCircuit:`, lastCircuit);
    
    if (!lastCircuit) {
      return res.status(404).json({ result: null });
    }
  
    res.json({ result: lastCircuit });
    return;
  });

  // Route to receive messages
  _user.post("/message", (req, res) => {
    const { message } = req.body;
    lastReceivedMessage = message;
    console.log(`User ${userId} received message: ${message}`);
    res.send("success");
  });

  // Route to send messages
  _user.post("/sendMessage", async (req, res) => {
    try {
      const { message, destinationUserId } = req.body as SendMessageBody;
      lastSentMessage = message;
  
      // Fetch registry and select nodes
      const registryResponse = await axios.get(`http://localhost:${REGISTRY_PORT}/getNodeRegistry`);
      const nodes: Node[] = registryResponse.data.nodes;
  
      if (nodes.length < 3) {
        throw new Error("Not enough onion routers available (minimum 3 required)");
      }
  
      const selectedNodes = selectRandomNodes(nodes, 3);
      const circuit = selectedNodes.map(node => node.nodeId);
  
      lastCircuit = [...circuit];
      console.log(`[DEBUG] Stored lastCircuit:`, lastCircuit);
      console.log(`[DEBUG] starting debug`);
  
      // Generate AES key for symmetric encryption
      const symmetricKey = await createRandomSymmetricKey();
      console.log(`[DEBUG] symmetricKey :`, symmetricKey);
      const exportedSymKey = await exportSymKey(symmetricKey);
      console.log(`[DEBUG] exportedSymKey :`, symmetricKey);

      // Encrypt the message with the AES symmetric key
      console.log(`[DEBUG] message :`, message);
      const encryptedMessage = await symEncrypt(symmetricKey, message);
      console.log(`[DEBUG] encryptedMessage :`, encryptedMessage);

      // Encrypt the AES key with the RSA public key of the final node (for example, using the last node)
      const finalNode = selectedNodes[selectedNodes.length - 1];
      console.log(exportedSymKey)
      const encryptedSymmetricKey = await rsaEncrypt(exportedSymKey, finalNode.pubKey);
      console.log(`[DEBUG] encryptedSymKey :`, encryptedSymmetricKey);
  
      // Construct the payload to send to the first node in the circuit
      const finalDestination = {
        type: "final",
        userId: destinationUserId,
        encryptedData: encryptedMessage,
        encryptedSymmetricKey: encryptedSymmetricKey,  // Encrypted AES key
      };
  
      let currentPayload = JSON.stringify(finalDestination);
  
      // Relay the message through the circuit
      for (let i = selectedNodes.length - 1; i >= 0; i--) {
        const node = selectedNodes[i];
    
        // Generate AES key for this hop
        const relaySymKey = await createRandomSymmetricKey();
        const exportedRelaySymKey = await exportSymKey(relaySymKey);
    
        // Encrypt the nextHop payload with AES
        const encryptedData = await symEncrypt(relaySymKey, currentPayload);
    
        // Encrypt the AES key with the node's RSA public key
        const encryptedRelaySymKey = await rsaEncrypt(exportedRelaySymKey, node.pubKey);
    
        // New payload for this hop
        currentPayload = JSON.stringify({
            type: "relay",
            nextDestination: i > 0 ? selectedNodes[i - 1].nodeId : undefined,
            encryptedSymKey: encryptedRelaySymKey,
            encryptedMessage: encryptedData,
        });
    }
  
      // Send the wrapped message to the first node in the circuit
      const firstNode = selectedNodes[selectedNodes.length - 1];
      await axios.post(
        `http://localhost:${BASE_ONION_ROUTER_PORT + firstNode.nodeId}/forwardMessage`,
        JSON.parse(currentPayload)
      );
  
      res.json({ 
        status: "Message sent successfully",
        circuit,
      });
    } catch (error) {
      console.error("Failed to send message:", error);
      res.status(500).json({ 
        status: "Error sending message", 
      });
    }
  });

  const server = _user.listen(BASE_USER_PORT + userId, () => {
    console.log(
      `User ${userId} is listening on port ${BASE_USER_PORT + userId}`
    );
  });

  return server;
}

// Helper function to select random nodes
function selectRandomNodes(nodes: Node[], count: number): Node[] {
  const shuffled = [...nodes].sort(() => 0.5 - Math.random());
  return shuffled.slice(0, count);
}