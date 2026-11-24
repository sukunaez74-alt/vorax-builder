import { readFileSync, writeFileSync, unlinkSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { spawnSync } from "node:child_process";

const backend = "functions/api/[[path]].js";
const html = "index.html";

function check(file) {
  const result = spawnSync(process.execPath, ["--check", file], { encoding: "utf8" });
  if (result.status !== 0) {
    process.stderr.write(result.stderr || result.stdout || `Falha ao validar ${file}\n`);
    process.exit(result.status || 1);
  }
  console.log(`OK: sintaxe de ${file}`);
}

check(backend);
const source = readFileSync(html, "utf8");
const scripts = [...source.matchAll(/<script(?:\\s[^>]*)?>([\\s\\S]*?)<\\/script>/gi)];
if (!scripts.length) throw new Error("Nenhum script encontrado em index.html");
const temp = join(tmpdir(), "black-zone-inline-check.js");
try {
  writeFileSync(temp, scripts.map(match => match[1]).join("\n"));
  check(temp);
  console.log("OK: JavaScript incorporado em index.html");
} finally {
  try { unlinkSync(temp); } catch {}
}
