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
      
      // 1. Fetch the registry of onion routers
      const registryResponse = await axios.get(`http://localhost:${REGISTRY_PORT}/registry`);
      const nodes: Node[] = registryResponse.data.nodes;
      
      if (nodes.length < 3) {
        throw new Error("Not enough onion routers available (minimum 3 required)");
      }
      
      // 2. Select 3 random routers for the circuit
      const selectedNodes = selectRandomNodes(nodes, 3);
      const circuit = selectedNodes.map(node => node.nodeId);
      
      // 3. Create a symmetric key for the message
      const symmetricKey = await createRandomSymmetricKey();
      const exportedSymKey = await exportSymKey(symmetricKey);
      
      // 4. Encrypt the actual message with the symmetric key
      const encryptedMessage = await symEncrypt(symmetricKey, message);
      
      // 5. Create the onion-layered data
      const finalDestination = {
        type: "final",
        userId: destinationUserId,
        data: encryptedMessage
      };
      
      // Build the onion from inside out
      let currentPayload = JSON.stringify(finalDestination);
      
      // Reverse the array to encrypt from last node to first node
      for (let i = selectedNodes.length - 1; i >= 0; i--) {
        const node = selectedNodes[i];
        
        // If this is the last router, include the symmetric key
        const nextHop = i === 0 ? 
          { 
            type: "relay",
            symKey: exportedSymKey,
            data: currentPayload
          } : 
          {
            type: "relay",
            nextNodeId: selectedNodes[i - 1].nodeId,
            data: currentPayload
          };
        
        // Encrypt this layer with the router's public key
        currentPayload = await rsaEncrypt(
          JSON.stringify(nextHop),
          node.pubKey
        );
      }
      
      // 6. Send the onion to the first node
      const firstNode = selectedNodes[selectedNodes.length - 1];
      await axios.post(
        `http://localhost:${BASE_ONION_ROUTER_PORT + firstNode.nodeId}/message`,
        { data: currentPayload }
      );
      
      res.json({ 
        status: "Message sent successfully",
        circuit
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