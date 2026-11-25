import { readFileSync, writeFileSync, unlinkSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { spawnSync } from "node:child_process";

const backends = ["api/[...path].js", "functions/api/[[path]].js"];
const html = "index.html";

function check(file) {
  const result = spawnSync(process.execPath, ["--check", file], { encoding: "utf8" });
  if (result.status !== 0) {
    process.stderr.write(result.stderr || result.stdout || ("Falha ao validar " + file + "\n"));
    process.exit(result.status || 1);
  }
  console.log("OK: sintaxe de " + file);
}

for (const backend of backends) check(backend);
const apiSource = readFileSync(backends[0], "utf8");
const verificationBot = apiSource.match(new RegExp("function verificationBotSource\\\\(\\\\)\\\\s*\\\\{\\\\s*return String\\\\.raw`([\\\\s\\\\S]*?)`;\\\\s*\\\\}"));
if (!verificationBot) throw new Error("Código-fonte do bot de verificação não encontrado");
const botFile = join(tmpdir(), "black-zone-verification-bot.py");
try {
  writeFileSync(botFile, verificationBot[1]);
  const result = spawnSync("python", ["-m", "py_compile", botFile], { encoding: "utf8" });
  if (result.status !== 0) {
    process.stderr.write(result.stderr || result.stdout || "Falha ao validar o bot Python\\n");
    process.exit(result.status || 1);
  }
  console.log("OK: sintaxe do bot Python de verificação");
} finally {
  try { unlinkSync(botFile); } catch {}
  try { unlinkSync(botFile + "c"); } catch {}
}
const source = readFileSync(html, "utf8");
const scripts = [...source.matchAll(/<script([^>]*)>([\s\S]*?)<\/script>/gi)]
  .filter(match => !/\btype\s*=\s*["']application\/ld\+json["']/i.test(match[1]));
if (!scripts.length) throw new Error("Nenhum script encontrado em index.html");
const temp = join(tmpdir(), "black-zone-inline-check.js");
try {
  writeFileSync(temp, scripts.map(match => match[2]).join("\n"));
  check(temp);
  console.log("OK: JavaScript incorporado em index.html");
} finally {
  try { unlinkSync(temp); } catch {}
}
