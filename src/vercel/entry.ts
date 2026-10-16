/**
 * Vercel entry point: builds the hosted handler from environment variables.
 *
 * `api/index.js` re-exports the result as the serverless function. The
 * handler is built lazily on the first request and reused while the instance
 * stays warm. Configuration errors are returned as a 500 that names the
 * missing/invalid variables (never their values) instead of crashing.
 */

import { sendJson } from "../transport/http.js";
import { parseHostedConfig } from "./config.js";
import { createVercelHandler } from "./handler.js";
import type { NodeHandler } from "./whoop-link.js";

export function createVercelHandlerFromEnv(
  env: Record<string, string | undefined> = process.env
): NodeHandler {
  let ready: Promise<NodeHandler> | undefined;

  return async (req, res) => {
    let handler: NodeHandler;
    try {
      ready ??= createVercelHandler({ config: parseHostedConfig(env) });
      handler = await ready;
    } catch (error) {
      ready = undefined;
      const message = error instanceof Error ? error.message : "Unknown configuration error";
      console.error(message);
      sendJson(res, 500, { error: "Server misconfigured", message });
      return;
    }
    await handler(req, res);
  };
}
