import apiHandler from "./[...path].js";
import caosAiHandler from "./caos-ai.js";

/**
 * Fixed Vercel entrypoint.
 * The rewrite in vercel.json forwards /api/* here and places the original
 * route in __path. Reconstruct the original URL before invoking the shared
 * API handler, so auth cookies, request bodies and query strings are kept.
 */
export default async function handler(req, res) {
  try {
    const incoming = new URL(req.url || "/api/bridge", "https://" + (req.headers?.host || "localhost"));
    const fromQuery = req.query?.__path;
    const original = Array.isArray(fromQuery)
      ? fromQuery.join("/")
      : (fromQuery || incoming.searchParams.get("__path") || "");
    const routePath = String(original).replace(/^\/+/, "");
    if (routePath === "caos-ai") return await caosAiHandler(req, res);
    if (!routePath) {
      res.statusCode = 400;
      res.setHeader("Content-Type", "application/json; charset=utf-8");
      return res.end(JSON.stringify({ error: "Rota da API não informada." }));
    }
    const passthrough = new URLSearchParams(incoming.searchParams);
    passthrough.delete("__path");
    req.url = "/api/" + routePath + (passthrough.toString() ? "?" + passthrough.toString() : "");
    return await apiHandler(req, res);
  } catch (error) {
    console.error("black-zone-estudio API bridge error:", error);
    res.statusCode = 500;
    res.setHeader("Content-Type", "application/json; charset=utf-8");
    res.setHeader("Cache-Control", "no-store");
    return res.end(JSON.stringify({ error: "Falha ao encaminhar a solicitação para a API." }));
  }
}
