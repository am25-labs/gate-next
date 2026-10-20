import { readFileSync } from "node:fs";
import { createRequire } from "node:module";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import ts from "typescript";

const require = createRequire(import.meta.url);
const root = fileURLToPath(new URL("../src/", import.meta.url));

export function createLoader(mocks = {}) {
  const cache = new Map();
  function load(file) {
    const path = resolve(root, file);
    if (cache.has(path)) return cache.get(path);
    const compiled = { exports: {} };
    const { outputText } = ts.transpileModule(readFileSync(path, "utf8"), { compilerOptions: { module: ts.ModuleKind.CommonJS, target: ts.ScriptTarget.ES2022, esModuleInterop: true } });
    new Function("require", "module", "exports", outputText)((name) => {
      if (name in mocks) return mocks[name];
      if (name.startsWith(".")) return load(resolve(dirname(path), name.replace(/\.js$/, ".ts")));
      return require(name);
    }, compiled, compiled.exports);
    cache.set(path, compiled.exports);
    return compiled.exports;
  }
  return load;
}
