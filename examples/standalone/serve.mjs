// 极简静态文件服务器，根目录指向仓库根。
// 用途：让零构建演示（importmap + 浏览器原生 ESM）能加载：
//   - /packages/cert-preview/pkg-web/cert_wasm.js 及其 .wasm
//   - /fixtures/... 下的样本证书
// 无需任何打包器。浏览器禁止 file:// 拉取 wasm，所以需要一个 http(s) 服务器。
import http from "node:http";
import { readFile } from "node:fs/promises";
import { extname, join, normalize, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const ROOT = join(here, "..", ".."); // examples/standalone -> repo root
const PORT = Number(process.env.PORT || 4321);

const MIME = {
  ".html": "text/html; charset=utf-8",
  ".js": "text/javascript; charset=utf-8",
  ".mjs": "text/javascript; charset=utf-8",
  ".ts": "text/javascript; charset=utf-8",
  ".wasm": "application/wasm",
  ".json": "application/json; charset=utf-8",
  ".css": "text/css; charset=utf-8",
  ".map": "application/json; charset=utf-8",
  ".pem": "application/x-pem-file; charset=utf-8",
  ".der": "application/octet-stream",
};

const server = http.createServer(async (req, res) => {
  try {
    let urlPath = decodeURIComponent((req.url || "/").split("?")[0]);
    if (urlPath === "/") urlPath = "/examples/standalone/index.html";
    const filePath = normalize(join(ROOT, urlPath));
    if (!filePath.startsWith(ROOT)) {
      res.writeHead(403, { "content-type": "text/plain" });
      res.end("forbidden");
      return;
    }
    const data = await readFile(filePath);
    const mime = MIME[extname(filePath)] || "application/octet-stream";
    res.writeHead(200, { "content-type": mime });
    res.end(data);
  } catch {
    res.writeHead(404, { "content-type": "text/plain" });
    res.end("not found");
  }
});

server.listen(PORT, () => {
  console.log(`cert-preview 零构建演示: http://localhost:${PORT}/`);
  console.log(`（仓库根: ${ROOT}）`);
});
