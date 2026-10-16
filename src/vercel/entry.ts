/**
 * Vercel entry point: builds the hosted handler from environment variables.
 *
 * `api/index.js` re-exports the result as the serverless function. The
 * handler is built lazily on the first request and reused while the instance
 * stays warm. Configuration errors return a generic 500; the missing or
 * invalid variable names are written to the deployment logs only.
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
      // Details (variable names) go to the deployment logs only.
      console.error(error instanceof Error ? error.message : "Unknown configuration error");
      sendJson(res, 500, {
        error: "Server misconfigured",
        message: "Check the deployment logs for details.",
      });
      return;
    }
    await handler(req, res);
  };
}
