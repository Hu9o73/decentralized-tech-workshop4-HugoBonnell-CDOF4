import bodyParser from "body-parser";
import express from "express";
import { BASE_USER_PORT, BASE_ONION_ROUTER_PORT } from "../config";
import { rsaEncrypt } from "../crypto";
import { GetNodeRegistryBody } from "../registry/registry";
import { REGISTRY_PORT } from "../config";

export type SendMessageBody = {
  message: string;
  destinationUserId: number;
};

export async function user(userId: number) {
  const _user = express();
  _user.use(express.json());
  _user.use(bodyParser.json());

  // State management
  let lastReceivedMessage: string | null = null;
  let lastSentMessage: string | null = null;

  // Basic status route
  _user.get("/status", (req, res) => {
    res.send("live");
  });

  // Route to get the last received message
  _user.get("/getLastReceivedMessage", (req, res) => {
    res.json({ result: lastReceivedMessage });
  });

  // Route to get the last sent message
  _user.get("/getLastSentMessage", (req, res) => {
    res.json({ result: lastSentMessage });
  });

  // Route to receive messages
  _user.post("/message", (req, res) => {
    const { message } = req.body;
    lastReceivedMessage = message;
    res.send("success"); // Changed to match expected response
  });

  // Route to send messages (to be implemented)
  _user.post("/sendMessage", async (req, res) => {
    const { message, destinationUserId } = req.body as SendMessageBody;
    lastSentMessage = message;
    // Implementation for sending messages through the onion network will be added here
    res.json({ status: "Message sent successfully" });
  });

  // Add this route to return the last circuit
  _user.get("/getLastCircuit", (req, res) => {
    res.json({ result: lastCircuit });
  });

  // Add a variable to store the last circuit
  let lastCircuit: number[] = [];

  // Route to send message
  _user.post("/sendMessage", async (req, res) => {
    const { message, destinationUserId } = req.body as SendMessageBody;
    lastSentMessage = message;

    // Generate a random circuit with 3 unique nodes
    lastCircuit = [];
    while (lastCircuit.length < 3) {
      const randomNode = Math.floor(Math.random() * 10);
      if (!lastCircuit.includes(randomNode)) {
        lastCircuit.push(randomNode);
      }
    }

    console.log(`User ${userId} generated circuit:`, lastCircuit);

    // Retrieve public keys from the registry
    const nodes = await fetch(`http://localhost:${REGISTRY_PORT}/getNodeRegistry`)
      .then((res) => res.json() as Promise<GetNodeRegistryBody>)
      .then((json) => json.nodes);

    let encryptedMessage = message;
    for (let i = 0; i < lastCircuit.length; i++) {
      const nodePort = BASE_ONION_ROUTER_PORT + lastCircuit[i];
      const nextDestination = i < lastCircuit.length - 1 ? BASE_ONION_ROUTER_PORT + lastCircuit[i + 1] : BASE_USER_PORT + destinationUserId;

      // Find the public key for the current node in the circuit
      const node = nodes.find((n) => n.nodeId === lastCircuit[i]);
      if (!node) {
        console.error(`User ${userId}: Node ${lastCircuit[i]} not found in registry`);
        return res.status(500).send("Node not found in registry");
      }

      // Encrypt the message with the node's public key
      encryptedMessage = await rsaEncrypt(encryptedMessage, node.pubKey);
      console.log(`User ${userId} encrypted message for node ${lastCircuit[i]}:`, encryptedMessage);

      // Forward the message to the next destination
      await fetch(`http://localhost:${nodePort}/forwardMessage`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ encryptedMessage, nextDestination }),
      });

      console.log(`User ${userId} forwarded message to node ${lastCircuit[i]}`);
    }

    res.json({ status: "Message sent successfully" });
    return;
  });

  const server = _user.listen(BASE_USER_PORT + userId, () => {
    console.log(
      `User ${userId} is listening on port ${BASE_USER_PORT + userId}`
    );
  });

  return server;
}
