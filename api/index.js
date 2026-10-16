// Vercel serverless function — every route is rewritten here (see vercel.json).
// The TypeScript source lives in src/vercel/; `npm run build` emits dist/.
import { createVercelHandlerFromEnv } from "../dist/vercel/entry.js";

export default createVercelHandlerFromEnv();
