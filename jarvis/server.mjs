import { createServer } from "node:https";
import { createServer as createHttpServer } from "node:http";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { writeFile, unlink } from "node:fs/promises";
import { tmpdir } from "node:os";
import { generateKeyPairSync, createSign, randomUUID } from "node:crypto";

const __dirname = dirname(fileURLToPath(import.meta.url));
const PORT      = 8443;
const HTTP_PORT = 8080;

const WHISPER_ENDPOINT = process.env.WHISPER_ENDPOINT || "https://moclaw.cognitiveservices.azure.com/openai/deployments/whisper/audio/transcriptions?api-version=2024-06-01";
const WHISPER_KEY = process.env.WHISPER_KEY;

const AZURE_CHAT_ENDPOINT = process.env.AZURE_CHAT_ENDPOINT || "https://admin-mm8nu6bl-eastus2.services.ai.azure.com/anthropic/v1/messages?api-version=2024-06-01";
const AZURE_CHAT_KEY = process.env.AZURE_CHAT_KEY;

const SPEECH_ENDPOINT = process.env.SPEECH_ENDPOINT || "https://uaenorth.tts.speech.microsoft.com/cognitiveservices/v1";
const SPEECH_KEY = process.env.SPEECH_KEY;

const SYSTEM_PROMPT = `You are Leo, VP at Avano Technologies. You are sarcastic, brutally honest, sharp, with dark humor. You help Big G (Mohamed Awes, Founder & CEO) build and grow Avano AI — the intelligence layer for the mobility sector in Dubai. Keep voice responses short, punchy, and conversational. No long speeches.`;

let conversationHistory = [];

// ─── Self-signed TLS certificate (generated at startup via built-in crypto) ──

function generateSelfSignedCert(cn = "localhost") {
  // DER/ASN.1 encoding helpers
  function derLen(n) {
    if (n < 0x80) return Buffer.from([n]);
    const b = [];
    for (let x = n; x > 0; x >>= 8) b.unshift(x & 0xff);
    return Buffer.from([0x80 | b.length, ...b]);
  }
  const tlv    = (tag, c) => Buffer.concat([Buffer.from([tag]), derLen(c.length), c]);
  const seq    = c => tlv(0x30, c);
  const set_   = c => tlv(0x31, c);
  const ctx0   = c => tlv(0xa0, c);
  const bitStr = c => tlv(0x03, Buffer.concat([Buffer.from([0x00]), c]));
  const oid    = b => tlv(0x06, Buffer.from(b));
  const utf8s  = s => tlv(0x0c, Buffer.from(s, "utf8"));
  const utcT   = d => tlv(0x17, Buffer.from(
    d.toISOString().replace(/[-:.T]/g, "").slice(2, 14) + "Z", "ascii"
  ));
  const int_ = n => {
    let h = n.toString(16);
    if (h.length % 2) h = "0" + h;
    let b = Buffer.from(h, "hex");
    if (b[0] & 0x80) b = Buffer.concat([Buffer.from([0x00]), b]);
    return tlv(0x02, b);
  };

  // OIDs
  const SHA256_RSA_OID = [0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b];
  const CN_OID         = [0x55, 0x04, 0x03];

  const algId = () => seq(Buffer.concat([oid(SHA256_RSA_OID), Buffer.from([0x05, 0x00])]));
  const name  = v => seq(set_(seq(Buffer.concat([oid(CN_OID), utf8s(v)]))));

  // Generate RSA-2048 key pair
  const { privateKey, publicKey: spkiDer } = generateKeyPairSync("rsa", {
    modulusLength:      2048,
    publicKeyEncoding:  { type: "spki",  format: "der" },
    privateKeyEncoding: { type: "pkcs8", format: "pem" },
  });

  const now = new Date();
  const exp = new Date(+now + 365 * 86400 * 1000);

  // TBSCertificate
  const tbs = seq(Buffer.concat([
    ctx0(int_(2)),                                      // version: v3
    int_(1),                                            // serialNumber
    algId(),                                            // signature algorithm
    name(cn),                                           // issuer
    seq(Buffer.concat([utcT(now), utcT(exp)])),         // validity
    name(cn),                                           // subject
    Buffer.from(spkiDer),                               // subjectPublicKeyInfo
  ]));

  // Sign TBSCertificate with RSA-SHA256
  const sig = createSign("RSA-SHA256").update(tbs).sign(privateKey);

  // Outer Certificate structure
  const certDer = seq(Buffer.concat([tbs, algId(), bitStr(sig)]));

  const cert = "-----BEGIN CERTIFICATE-----\n"
    + certDer.toString("base64").match(/.{1,64}/g).join("\n")
    + "\n-----END CERTIFICATE-----\n";

  return { key: privateKey, cert };
}

console.log("Generating self-signed TLS certificate...");
const { key, cert } = generateSelfSignedCert();
console.log("Certificate ready.");

// ─────────────────────────────────────────────────────────────────────────────

async function transcribeAudio(audioBuffer, mimeType) {
  const tmpPath = join(tmpdir(), `audio-${randomUUID()}.webm`);
  await writeFile(tmpPath, audioBuffer);

  const { FormData, File } = await import("node:buffer").catch(() => ({ FormData: global.FormData, File: global.File }));

  const form = new FormData();
  const blob = new Blob([audioBuffer], { type: mimeType || "audio/webm" });
  form.append("file", blob, "audio.webm");
  form.append("response_format", "text");

  const res = await fetch(WHISPER_ENDPOINT, {
    method: "POST",
    headers: { "api-key": WHISPER_KEY },
    body: form
  });

  await unlink(tmpPath).catch(() => {});

  if (!res.ok) throw new Error(`Whisper error ${res.status}: ${await res.text()}`);
  return await res.text();
}

async function getChatResponse(userText) {
  conversationHistory.push({ role: "user", content: userText });

  // Keep last 10 messages
  if (conversationHistory.length > 10) conversationHistory = conversationHistory.slice(-10);

  const res = await fetch(AZURE_CHAT_ENDPOINT, {
    method: "POST",
    headers: {
      "api-key": AZURE_CHAT_KEY,
      "Content-Type": "application/json",
      "anthropic-version": "2023-06-01"
    },
    body: JSON.stringify({
      model: "claude-sonnet-4-6",
      max_tokens: 300,
      system: SYSTEM_PROMPT,
      messages: conversationHistory
    })
  });

  if (!res.ok) throw new Error(`Chat error ${res.status}: ${await res.text()}`);
  const data = await res.json();
  const reply = data.content[0].text;
  conversationHistory.push({ role: "assistant", content: reply });
  return reply;
}

async function synthesizeSpeech(text) {
  const ssml = `<speak version='1.0' xml:lang='en-US'><voice name='en-US-BrianMultilingualNeural'><prosody rate='+10%' pitch='+0%'>${text.replace(/[<>&'"]/g, c => ({ "<": "&lt;", ">": "&gt;", "&": "&amp;", "'": "&apos;", '"': "&quot;" }[c]))}</prosody></voice></speak>`;

  const res = await fetch(SPEECH_ENDPOINT, {
    method: "POST",
    headers: {
      "Ocp-Apim-Subscription-Key": SPEECH_KEY,
      "Content-Type": "application/ssml+xml",
      "X-Microsoft-OutputFormat": "audio-24khz-48kbitrate-mono-mp3"
    },
    body: ssml
  });

  if (!res.ok) throw new Error(`TTS error ${res.status}: ${await res.text()}`);
  return Buffer.from(await res.arrayBuffer());
}

function handleRequest(req, res) {
  // CORS
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type");

  if (req.method === "OPTIONS") { res.writeHead(200); res.end(); return; }

  // Serve main page
  if (req.method === "GET" && req.url === "/") {
    res.writeHead(200, { "Content-Type": "text/html" });
    res.end(readFileSync(join(__dirname, "index.html")));
    return;
  }

  // Voice endpoint
  if (req.method === "POST" && req.url === "/voice") {
    (async () => {
      try {
        const chunks = [];
        for await (const chunk of req) chunks.push(chunk);
        const audioBuffer = Buffer.concat(chunks);

        console.log(`Received audio: ${audioBuffer.length} bytes`);

        const transcript = await transcribeAudio(audioBuffer);
        console.log(`Transcript: ${transcript}`);

        const reply = await getChatResponse(transcript);
        console.log(`Reply: ${reply}`);

        const audioResponse = await synthesizeSpeech(reply);

        res.writeHead(200, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ transcript, reply, audio: audioResponse.toString("base64") }));
      } catch (err) {
        console.error("Error:", err);
        res.writeHead(500, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ error: err.message }));
      }
    })();
    return;
  }

  // Reset conversation
  if (req.method === "POST" && req.url === "/reset") {
    conversationHistory = [];
    res.writeHead(200); res.end("ok");
    return;
  }

  res.writeHead(404); res.end();
}

// HTTPS server on port 8443
const httpsServer = createServer({ key, cert }, handleRequest);
httpsServer.listen(PORT, "0.0.0.0", () =>
  console.log(`Jarvis HTTPS server running at https://0.0.0.0:${PORT}`)
);

// HTTP → HTTPS redirect on port 8080
const httpServer = createHttpServer((req, res) => {
  const host = req.headers.host?.replace(/:\d+$/, "") || "localhost";
  res.writeHead(301, { Location: `https://${host}:${PORT}${req.url}` });
  res.end();
});
httpServer.listen(HTTP_PORT, "0.0.0.0", () =>
  console.log(`HTTP redirect listening on http://0.0.0.0:${HTTP_PORT} -> https port ${PORT}`)
);
