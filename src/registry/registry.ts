import bodyParser from "body-parser";
import express from "express";
import { REGISTRY_PORT } from "../config";

export type Node = { nodeId: number; pubKey: string };

export type RegisterNodeBody = {
  nodeId: number;
  pubKey: string;
};

export type GetNodeRegistryBody = {
  nodes: Node[];
};

export async function launchRegistry() {
  const _registry = express();
  _registry.use(express.json());
  _registry.use(bodyParser.json());

  // Store registered nodes
  const nodes: Node[] = [];

  // Basic status route
  _registry.get("/status", (req, res) => {
    res.send("live");
  });

  // Route to register new nodes
  _registry.post("/registerNode", (req, res) => {
    const { nodeId, pubKey }: RegisterNodeBody = req.body;
    nodes.push({ nodeId, pubKey });
    res.json({ status: "ok" });
  });

  // Route to get all registered nodes
  _registry.get("/getNodeRegistry", (req, res) => {
    res.json({ nodes });
  });

  const server = _registry.listen(REGISTRY_PORT, () => {
    console.log(`Registry is listening on port ${REGISTRY_PORT}`);
  });

  return server;
}