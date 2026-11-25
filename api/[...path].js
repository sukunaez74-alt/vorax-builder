export default function handler(req, res) {
  res.setHeader("Cache-Control", "no-store");
  const route = Array.isArray(req.query.path) ? req.query.path.join("/") : String(req.query.path || "");

  if (req.method === "GET" && route === "health") {
    return res.status(200).json({
      ok: true,
      service: "black-zone-estudio",
      deploymentMode: "frontend-published-backend-pending",
      databaseConfigured: false,
      secretsConfigured: {
        gate: false,
        session: false,
        encryption: false,
        discordOAuth: false
      }
    });
  }

  if (req.method === "GET" && route === "me") {
    return res.status(200).json({ gate: false, user: null, setupRequired: true });
  }

  return res.status(503).json({
    error: "O site está publicado, mas o servidor seguro do painel ainda está sendo conectado. Cadastro, login e controle de bots estarão disponíveis após essa configuração."
  });
}
