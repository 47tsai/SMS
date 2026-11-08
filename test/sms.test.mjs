// Tests for the Phase 1 (P0) SMS hardening.
// Run with: npm test        (node --test test/)
// These tests run the Worker entry point in Node with a mocked D1 and a
// mocked fetch. They do NOT touch production D1, Discord, or Chi Auth.
import test from "node:test";
import assert from "node:assert/strict";

import handler, {
  validatePayload,
  computeIdempotencyKey,
  splitMessageForDiscord,
  messageFields,
  escapeCsvCell,
  timingSafeEqual,
} from "../src/index.js";

const API_KEY = "test-key";
const WEBHOOK_URL = "https://discord.example/webhook";
const CHI_AUTH_CLIENT_ID = "z2gX_1zn_jmwhnoia2JiVY6FeuTyPcun";

// ---------------------------------------------------------------------------
// Minimal in-memory D1 stand-in. It implements only the statements the
// Worker issues (prepare/bind/run/all/first), with real UNIQUE-index
// behaviour on idempotency_key.
// ---------------------------------------------------------------------------
function utcString(date) {
  return date.toISOString().replace("T", " ").slice(0, 19);
}

function createMockDb() {
  const rows = [];
  let nextId = 1;
  return {
    rows,
    prepare(sql) {
      const normalized = sql.replace(/\s+/g, " ").trim();
      const makeStatement = (params) => ({
        async first() {
          if (normalized.startsWith("SELECT id FROM messages WHERE idempotency_key")) {
            return rows.find((r) => r.idempotency_key === params[0]) || null;
          }
          throw new Error("unsupported first(): " + normalized);
        },
        async all() {
          if (normalized.startsWith("SELECT id, sender, message, received_at FROM messages")) {
            return { results: [...rows].sort((a, b) => b.id - a.id).slice(0, 500) };
          }
          throw new Error("unsupported all(): " + normalized);
        },
        async run() {
          if (normalized.startsWith("INSERT INTO messages")) {
            const [sender, message, received_at, idempotency_key] = params;
            if (rows.some((r) => r.idempotency_key === idempotency_key)) {
              throw new Error("UNIQUE constraint failed: messages.idempotency_key");
            }
            const id = nextId++;
            const now = new Date();
            rows.push({
              id,
              sender,
              message,
              received_at,
              idempotency_key,
              expires_at: utcString(new Date(now.getTime() + 30 * 86400e3)),
              created_at: utcString(now),
            });
            return { meta: { last_row_id: id, changes: 1 } };
          }
          if (normalized.startsWith("DELETE FROM messages WHERE id = ?")) {
            const index = rows.findIndex((r) => r.id === params[0]);
            if (index === -1) return { meta: { changes: 0 } };
            rows.splice(index, 1);
            return { meta: { changes: 1 } };
          }
          if (normalized === "DELETE FROM messages") {
            const changes = rows.length;
            rows.length = 0;
            return { meta: { changes } };
          }
          if (normalized.startsWith("DELETE FROM messages WHERE (expires_at IS NOT NULL")) {
            const now = utcString(new Date());
            const cutoff = utcString(new Date(Date.now() - 30 * 86400e3));
            let changes = 0;
            for (let i = rows.length - 1; i >= 0; i--) {
              const r = rows[i];
              const expired = (r.expires_at && r.expires_at <= now) ||
                (!r.expires_at && r.created_at <= cutoff);
              if (expired) { rows.splice(i, 1); changes++; }
            }
            return { meta: { changes } };
          }
          throw new Error("unsupported run(): " + normalized);
        },
      });
      // D1 allows prepare(sql).run()/all()/first() with no bind() call.
      return { bind: (...params) => makeStatement(params), ...makeStatement([]) };
    },
  };
}

// ---------------------------------------------------------------------------
// fetch stub: Chi Auth userinfo succeeds as chi-owner; everything else is
// treated as the Discord webhook and recorded for assertions.
// ---------------------------------------------------------------------------
const discordCalls = [];
const realFetch = globalThis.fetch;

function installFetchStub() {
  discordCalls.length = 0;
  globalThis.fetch = async (url, options) => {
    const target = String(url);
    if (target.includes("auth.chi.qzz.io")) {
      return { ok: true, status: 200, json: async () => ({ sub: "chi-owner", aud: CHI_AUTH_CLIENT_ID }) };
    }
    discordCalls.push({ url: target, body: JSON.parse(options?.body || "{}") });
    return { ok: true, status: 204, json: async () => ({}) };
  };
}

function makeEnv(db, extra = {}) {
  return {
    SMS_DB: db,
    SMS_FORWARDER_API_KEY: API_KEY,
    DISCORD_WEBHOOK_URL: WEBHOOK_URL,
    ...extra,
  };
}

function postSms(env, body, headers = {}) {
  return handler.fetch(new Request("https://sms.chi.qzz.io/sms", {
    method: "POST",
    headers: { "Content-Type": "application/json", "X-API-Key": API_KEY, ...headers },
    body: typeof body === "string" ? body : JSON.stringify(body),
  }), env);
}

// ---------------------------------------------------------------------------
// Pure-function tests
// ---------------------------------------------------------------------------
test("validatePayload rejects null, arrays and non-objects instead of crashing", () => {
  for (const bad of [null, undefined, "text", 42, [1, 2]]) {
    const result = validatePayload(bad);
    assert.equal(result.ok, false);
  }
});

test("validatePayload rejects mistyped and over-long fields", () => {
  assert.equal(validatePayload({}).ok, false); // missing message
  assert.equal(validatePayload({ message: "" }).ok, false);
  assert.equal(validatePayload({ message: "   " }).ok, false);
  assert.equal(validatePayload({ message: 123 }).ok, false);
  assert.equal(validatePayload({ sender: 5, message: "hi" }).ok, false);
  assert.equal(validatePayload({ sender: "x".repeat(201), message: "hi" }).ok, false);
  assert.equal(validatePayload({ message: "x".repeat(3501) }).ok, false);
  assert.equal(validatePayload({ message: "hi", receivedAt: 123 }).ok, false);
});

test("validatePayload accepts a valid payload and fills defaults", () => {
  const result = validatePayload({ sender: "Bank", message: "code 123456", receivedAt: "2026-11-08 12:00:00" });
  assert.equal(result.ok, true);
  assert.equal(result.value.sender, "Bank");
  assert.equal(result.value.message, "code 123456");
  const defaulted = validatePayload({ message: "hi" });
  assert.equal(defaulted.ok, true);
  assert.equal(typeof defaulted.value.receivedAt, "string");
});

test("splitMessageForDiscord keeps every character and respects the 1024 limit", () => {
  const message = "A".repeat(2500);
  const chunks = splitMessageForDiscord(message);
  assert.deepEqual(chunks.map((c) => c.length), [1024, 1024, 452]);
  assert.equal(chunks.join(""), message);
  assert.deepEqual(messageFields("short"), [{ name: "💬 簡訊內容", value: "short", inline: false }]);
  assert.equal(messageFields(message).length, 3);
  assert.equal(messageFields(message)[0].name, "💬 簡訊內容（1/3）");
});

test("splitMessageForDiscord does not split emoji across fields", () => {
  const message = "😀".repeat(1100);
  const chunks = splitMessageForDiscord(message);
  for (const chunk of chunks) assert.ok([...chunk].length <= 1024);
  assert.equal(chunks.join(""), message);
  // No lone surrogates: every chunk re-encodes to the same code points.
  for (const chunk of chunks) assert.equal([...chunk].join(""), chunk);
});

test("escapeCsvCell neutralises formula injection", () => {
  assert.equal(escapeCsvCell("=1+1"), "\"'=1+1\"");
  assert.equal(escapeCsvCell("+cmd"), "\"'+cmd\"");
  assert.equal(escapeCsvCell("-x"), "\"'-x\"");
  assert.equal(escapeCsvCell("@x"), "\"'@x\"");
  assert.equal(escapeCsvCell("  =x"), "\"'  =x\"");
  assert.equal(escapeCsvCell("hello"), '"hello"');
  assert.equal(escapeCsvCell('say "hi"'), '"say ""hi"""');
});

test("computeIdempotencyKey is deterministic, 64 hex chars, and input-sensitive", async () => {
  const a = await computeIdempotencyKey("Bank", "code 123456", "2026-11-08 12:00:00");
  const b = await computeIdempotencyKey("Bank", "code 123456", "2026-11-08 12:00:00");
  const c = await computeIdempotencyKey("Bank", "code 654321", "2026-11-08 12:00:00");
  assert.equal(a, b);
  assert.match(a, /^[0-9a-f]{64}$/);
  assert.notEqual(a, c);
});

test("timingSafeEqual compares fixed-length digests", () => {
  assert.equal(timingSafeEqual(new Uint8Array([1, 2, 3]), new Uint8Array([1, 2, 3])), true);
  assert.equal(timingSafeEqual(new Uint8Array([1, 2, 3]), new Uint8Array([1, 2, 4])), false);
  assert.equal(timingSafeEqual(new Uint8Array([1, 2]), new Uint8Array([1, 2, 3])), false);
});

// ---------------------------------------------------------------------------
// Handler integration tests (mocked D1 + mocked Discord)
// ---------------------------------------------------------------------------
test("ingest stores the message and reports D1 + Discord separately", async () => {
  installFetchStub();
  const db = createMockDb();
  const response = await postSms(makeEnv(db), { sender: "Bank", message: "code 123456", receivedAt: "2026-11-08 12:00:00" });
  assert.equal(response.status, 200);
  const data = await response.json();
  assert.equal(data.ok, true);
  assert.equal(data.saved, true);
  assert.equal(typeof data.id, "number");
  assert.deepEqual(data.discord, { ok: true, status: 204 });
  assert.equal(db.rows.length, 1);
  assert.equal(db.rows[0].idempotency_key.length, 64);
  assert.equal(discordCalls.length, 1);
});

test("a retried ingest is a duplicate: no second row, no second Discord call", async () => {
  installFetchStub();
  const db = createMockDb();
  const body = { sender: "Bank", message: "code 123456", receivedAt: "2026-11-08 12:00:00" };
  const first = await postSms(makeEnv(db), body);
  assert.equal(first.status, 200);
  const second = await postSms(makeEnv(db), body);
  assert.equal(second.status, 200);
  const data = await second.json();
  assert.equal(data.duplicate, true);
  assert.equal(data.discord.skipped, "duplicate");
  assert.equal(db.rows.length, 1);
  assert.equal(discordCalls.length, 1);
});

test("a long message reaches Discord in full, split across fields", async () => {
  installFetchStub();
  const db = createMockDb();
  const message = "A".repeat(2500);
  const response = await postSms(makeEnv(db), { sender: "Bank", message, receivedAt: "2026-11-08 12:00:00" });
  assert.equal(response.status, 200);
  const data = await response.json();
  assert.equal(data.discord.ok, true);
  const fields = discordCalls[0].body.embeds[0].fields.filter((f) => f.name.startsWith("💬 簡訊內容"));
  assert.equal(fields.length, 3);
  for (const field of fields) assert.ok(field.value.length <= 1024);
  assert.equal(fields.map((f) => f.value).join(""), message);
});

test("null payload returns 400 instead of crashing with 500", async () => {
  installFetchStub();
  const db = createMockDb();
  for (const body of ["null", "{", "[1,2]", JSON.stringify({ message: "" })]) {
    const response = await postSms(makeEnv(db), body);
    assert.equal(response.status, 400, body);
    assert.equal(db.rows.length, 0);
  }
});

test("missing or wrong API key returns 401", async () => {
  installFetchStub();
  const db = createMockDb();
  const noKey = await handler.fetch(new Request("https://sms.chi.qzz.io/sms", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ message: "hi" }),
  }), makeEnv(db));
  assert.equal(noKey.status, 401);
  const wrongKey = await postSms(makeEnv(db), { message: "hi" }, { "X-API-Key": "wrong-key" });
  assert.equal(wrongKey.status, 401);
  assert.equal(db.rows.length, 0);
});

test("oversized body is rejected with 413 (Content-Length path)", async () => {
  installFetchStub();
  const db = createMockDb();
  const response = await postSms(makeEnv(db), { message: "x".repeat(40000) });
  assert.equal(response.status, 413);
  assert.equal(db.rows.length, 0);
});

test("oversized body without Content-Length is rejected with 413 (streaming path)", async () => {
  installFetchStub();
  const db = createMockDb();
  const big = new TextEncoder().encode(JSON.stringify({ message: "x".repeat(40000) }));
  const stream = new ReadableStream({
    start(controller) { controller.enqueue(big); controller.close(); },
  });
  const response = await handler.fetch(new Request("https://sms.chi.qzz.io/sms", {
    method: "POST",
    headers: { "Content-Type": "application/json", "X-API-Key": API_KEY },
    body: stream,
    duplex: "half",
  }), makeEnv(db));
  assert.equal(response.status, 413);
  assert.equal(db.rows.length, 0);
});

test("rate limiter returning failure produces 429", async () => {
  installFetchStub();
  const db = createMockDb();
  const env = makeEnv(db, { SMS_LIMITER: { limit: async () => ({ success: false }) } });
  const response = await postSms(env, { message: "hi" });
  assert.equal(response.status, 429);
  assert.equal(db.rows.length, 0);
});

test("missing rate limiter binding does not block ingest (fail open)", async () => {
  installFetchStub();
  const db = createMockDb();
  const env = makeEnv(db);
  delete env.SMS_LIMITER;
  const response = await postSms(env, { message: "hi" });
  assert.equal(response.status, 200);
});

test("scheduled() deletes only messages older than 30 days", async () => {
  const db = createMockDb();
  const now = Date.now();
  db.rows.push(
    { id: 1, sender: "A", message: "expired by expires_at", received_at: "2026-01-01 00:00:00", idempotency_key: "a", expires_at: utcString(new Date(now - 86400e3)), created_at: utcString(new Date(now - 40 * 86400e3)) },
    { id: 2, sender: "B", message: "legacy row, old created_at", received_at: "2026-01-01 00:00:00", idempotency_key: "b", expires_at: null, created_at: utcString(new Date(now - 31 * 86400e3)) },
    { id: 3, sender: "C", message: "fresh", received_at: "2026-01-01 00:00:00", idempotency_key: "c", expires_at: utcString(new Date(now + 29 * 86400e3)), created_at: utcString(new Date(now)) },
    { id: 4, sender: "D", message: "legacy row, recent created_at", received_at: "2026-01-01 00:00:00", idempotency_key: "d", expires_at: null, created_at: utcString(new Date(now - 5 * 86400e3)) },
  );
  await handler.scheduled({}, makeEnv(db));
  assert.deepEqual(db.rows.map((r) => r.id), [3, 4]);
});

test("health and CORS preflight behave", async () => {
  const db = createMockDb();
  const health = await handler.fetch(new Request("https://sms.chi.qzz.io/health"), makeEnv(db));
  assert.equal(health.status, 200);
  const allowed = await handler.fetch(new Request("https://sms.chi.qzz.io/sms", {
    method: "OPTIONS",
    headers: { Origin: "https://sms.chi.qzz.io" },
  }), makeEnv(db));
  assert.equal(allowed.status, 204);
  const foreign = await handler.fetch(new Request("https://sms.chi.qzz.io/sms", {
    method: "OPTIONS",
    headers: { Origin: "https://evil.example" },
  }), makeEnv(db));
  assert.equal(foreign.status, 403);
});
