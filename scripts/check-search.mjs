#!/usr/bin/env node
import { readFile } from "node:fs/promises";
import { resolve } from "node:path";
import { pathToFileURL } from "node:url";

const site = resolve(process.argv[2] || "_site");
const bundle = pathToFileURL(`${site}/pagefind/pagefind.js`);
const nativeFetch = globalThis.fetch;

// Pagefind's browser bundle fetches its metadata, WASM, and fragments relative
// to import.meta.url. Teach Node's fetch how to read those file:// resources so
// CI can exercise the real generated index without launching a web server.
globalThis.fetch = async (input, init) => {
  const raw = typeof input === "string" || input instanceof URL ? input : input.url;
  const url = raw instanceof URL ? raw : new URL(raw, bundle);
  if (url.protocol === "file:") {
    try {
      const body = await readFile(url);
      const type = url.pathname.endsWith(".wasm")
        ? "application/wasm"
        : "application/octet-stream";
      return new Response(body, { status: 200, headers: { "content-type": type } });
    } catch {
      return new Response("not found", { status: 404 });
    }
  }
  return nativeFetch(input, init);
};

let language = "en";
globalThis.document = {
  currentScript: null,
  querySelector(selector) {
    if (selector !== "html") return null;
    return { getAttribute: (name) => (name === "lang" ? language : null) };
  },
};

const pagefind = await import(bundle.href);

async function check(lang, query, expectChinese) {
  language = lang;
  const instance = pagefind.createInstance();
  await instance.init();
  const search = await instance.search(query);
  if (!search.results.length) {
    throw new Error(`Pagefind returned no ${lang} results for ${JSON.stringify(query)}`);
  }
  const results = await Promise.all(search.results.slice(0, 10).map((item) => item.data()));
  const wrongLanguage = results.find(
    (item) => item.url.includes("/zh-CN/") !== expectChinese,
  );
  if (wrongLanguage) {
    throw new Error(`Pagefind ${lang} search crossed locale boundary: ${wrongLanguage.url}`);
  }
  await instance.destroy();
  console.log(`${lang}: ${search.results.length} result(s) for ${JSON.stringify(query)}`);
}

await check("en", "kernel", false);
await check("zh-CN", "内核", true);
