/**
 * Runs the recovery page's own crypto against files the app actually produced.
 *
 * The script does not reimplement anything: it lifts the <script> block out of
 * the HTML and evaluates it, so what is tested is the code that ships. A tool
 * whose correctness was only ever checked against a second implementation of
 * the same guesses would prove nothing.
 *
 *   node verify_recovery_tool.mjs <fixture-dir>
 */
import { readFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import vm from "node:vm";

const here = dirname(fileURLToPath(import.meta.url));
const fixtureDir = process.argv[2];
if (!fixtureDir) {
  console.error("usage: node verify_recovery_tool.mjs <fixture-dir>");
  process.exit(2);
}

const html = readFileSync(join(here, "storely-vault-recovery.html"), "utf8");

// The page must not reach the network. Assert that before trusting anything
// else it says about itself.
const csp = /<meta http-equiv="Content-Security-Policy"[\s\S]*?content="([^"]+)"/.exec(html);
if (!csp) throw new Error("the page has no Content-Security-Policy");
for (const required of ["default-src 'none'", "form-action 'none'"]) {
  if (!csp[1].includes(required)) {
    throw new Error(`CSP is missing ${required}: ${csp[1]}`);
  }
}
if (/https?:\/\//.test(html.replace(/<!--[\s\S]*?-->/g, ""))) {
  throw new Error("the page references an external URL");
}

const script = /<script>\n([\s\S]*?)<\/script>/.exec(html);
if (!script) throw new Error("could not find the page's script block");

// Only the pure part is evaluated; the DOM wiring below it is not under test
// here and would need a browser.
const pure = script[1].split("/* ----------------------------------------------------------- rendering */")[0];
const exportPart = script[1]
  .split("/* ------------------------------------------------------------- export */")[1]
  .split("/* --------------------------------------------------------------- wiring */")[0];

const sandbox = {
  crypto,
  TextEncoder,
  TextDecoder,
  atob,
  console,
  Blob: class {},
  URL: { createObjectURL: () => "", revokeObjectURL: () => {} },
  document: { createElement: () => ({ click() {} }) },
};
vm.createContext(sandbox);
vm.runInContext(
  pure + "\n" + exportPart + "\nglobalThis.__api = { normalizeCode, unsealVaultKey, openContainer, decryptNotes, parseFields, toCsv };",
  sandbox
);

const api = sandbox.__api;

const read = (name) => readFileSync(join(fixtureDir, name), "utf8");
const code = read("code.txt").trim();
const envelope = JSON.parse(read("storely_vault_key.json"));
const container = read("storely_vault_backup.enc");

let failures = 0;
const check = (label, condition, detail) => {
  if (condition) {
    console.log(`  ok    ${label}`);
  } else {
    failures++;
    console.log(`  FAIL  ${label}${detail ? " — " + detail : ""}`);
  }
};

console.log("\nOpening a vault the app sealed:");

const vaultKey = await api.unsealVaultKey(envelope, code);
check("the recovery code unseals the vault key", vaultKey.length === 32,
  `got ${vaultKey.length} bytes`);

const bundle = await api.openContainer(container, vaultKey);
check("the key opens the container", Array.isArray(bundle.notes),
  JSON.stringify(Object.keys(bundle)));

const result = await api.decryptNotes(bundle, vaultKey);
check("every item decrypted", result.notes.every((n) => !n.failed));
check("two items came back", result.notes.length === 2,
  `got ${result.notes.length}`);

const fielded = result.notes.find((n) => n.id === "note-fields");
check("Arabic titles survive the round trip", fielded.title === "حساب البنك",
  fielded.title);
check("structured items are read as fields", fielded.fields?.length === 2,
  JSON.stringify(fielded.fields));
check("field values are exact",
  fielded.fields?.[0].value === "SA0380000000608010167519",
  fielded.fields?.[0].value);
check("the secret flag is carried", fielded.fields?.[1].secret === true);
check("tags decrypt", fielded.tags.join(",") === "مالي,مهم", fielded.tags.join(","));

const freeText = result.notes.find((n) => n.id === "note-text");
check("free text is not mistaken for fields", freeText.fields === null,
  JSON.stringify(freeText.fields));
check("newlines survive", freeText.content === "سطر أول\nسطر ثانٍ",
  JSON.stringify(freeText.content));

console.log("\nRefusing what it should refuse:");

let refused = false;
try {
  await api.unsealVaultKey(envelope, "AAAAA-AAAAA-AAAAA-AAAAA-AAAAA-AAAAA");
} catch (e) {
  refused = /غير صحيح/.test(e.message);
}
check("a wrong code is refused, not half-opened", refused);

refused = false;
try {
  await api.openContainer('{"magic":"NOT_STORELY","payload":"x"}', vaultKey);
} catch (e) {
  refused = /Storely/.test(e.message);
}
check("a foreign file is rejected by its magic", refused);

console.log("\nAccepting the code as people type it:");
const canonical = api.normalizeCode(code);
check("lower case", api.normalizeCode(code.toLowerCase()) === canonical);
check("no dashes", api.normalizeCode(code.replace(/-/g, "")) === canonical);
check("stray spaces", api.normalizeCode(" " + code + " ") === canonical);
check("letters people substitute (O for 0, I/L for 1, U for V)",
  api.normalizeCode("OIL") === "011" && api.normalizeCode("U") === "V");

console.log("\nExport:");
const csv = api.toCsv(result);
check("the CSV opens in Excel as UTF-8", csv.charCodeAt(0) === 0xfeff);
// A header, one row for each of the two fields in the structured item, and one
// for the free-text item. A whole record squeezed into a single cell would show
// up here as two rows instead of three.
check("one row per field, not one cell per record",
  csv.split("\r\n").length === 1 + 2 + 1,
  `${csv.split("\r\n").length} rows`);
check("values reach the CSV", csv.includes("SA0380000000608010167519"));

console.log(failures === 0 ? "\nAll checks passed.\n" : `\n${failures} FAILED\n`);
process.exit(failures === 0 ? 0 : 1);
