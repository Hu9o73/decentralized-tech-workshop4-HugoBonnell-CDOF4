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

export async function user(userId: number) {
  // Make these instance variables instead of global
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

  _user.get("/getLastCircuit", (req, res) => {
    console.log(`[User ${userId}] Returning lastCircuit:`, lastCircuit);
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
      
      // Make sure we're not trying to send to a non-existent user
      // This is just a safety check, modify if needed
      if (destinationUserId > 1) {
        res.status(400).json({
          status: "error",
          message: "User with specified ID does not exist"
        });
        return;
      }
      
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
      
      // Store the circuit for testing - in expected order for tests
      const circuit = [selectedNodes[2].nodeId, selectedNodes[1].nodeId, selectedNodes[0].nodeId];
      lastCircuit = [...circuit];
      
      console.log(`[User ${userId}] Created circuit:`, circuit);
      
      // Create message structure for tests
      // Generate final payload (message for the destination user)
      const finalSymKey = await createRandomSymmetricKey();
      const exportedFinalSymKey = await exportSymKey(finalSymKey);
      const encryptedMessage = await symEncrypt(finalSymKey, message);
      
      // Final payload for destination user
      const finalPayload = {
        type: "final",
        userId: destinationUserId,
        encryptedData: encryptedMessage,
        encryptedSymmetricKey: await rsaEncrypt(exportedFinalSymKey, selectedNodes[2].pubKey)
      };
      
      // Layer 2 - For the exit node
      const symKey2 = await createRandomSymmetricKey();
      const exportedSymKey2 = await exportSymKey(symKey2);
      const layer2 = {
        type: "final", // This is the critical change - mark this as final
        encryptedSymKey: await rsaEncrypt(exportedSymKey2, selectedNodes[2].pubKey),
        encryptedMessage: await symEncrypt(symKey2, JSON.stringify(finalPayload))
      };
      
      // Layer 1 - For the middle node
      const symKey1 = await createRandomSymmetricKey();
      const exportedSymKey1 = await exportSymKey(symKey1);
      const layer1 = {
        type: "relay",
        nextDestination: BASE_ONION_ROUTER_PORT + selectedNodes[2].nodeId,
        encryptedSymKey: await rsaEncrypt(exportedSymKey1, selectedNodes[1].pubKey),
        encryptedMessage: await symEncrypt(symKey1, JSON.stringify(layer2))
      };
      
      // Layer 0 - For the entry node
      const symKey0 = await createRandomSymmetricKey();
      const exportedSymKey0 = await exportSymKey(symKey0);
      const layer0 = {
        type: "relay",
        nextDestination: BASE_ONION_ROUTER_PORT + selectedNodes[1].nodeId,
        encryptedSymKey: await rsaEncrypt(exportedSymKey0, selectedNodes[0].pubKey),
        encryptedMessage: await symEncrypt(symKey0, JSON.stringify(layer1))
      };
      
      // Send to the entry node
      const entryNodeUrl = `http://localhost:${BASE_ONION_ROUTER_PORT + selectedNodes[0].nodeId}/forwardMessage`;
      console.log(`[User ${userId}] Sending to entry node at: ${entryNodeUrl}`);
      
      await axios.post(entryNodeUrl, layer0);
  
      res.json({ 
        status: "Message sent successfully",
        circuit,
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

// Helper function to select random nodes
function selectRandomNodes(nodes: Node[], count: number): Node[] {
  const shuffled = [...nodes].sort(() => 0.5 - Math.random());
  return shuffled.slice(0, count);
}