// Shared helpers for the Sentinel k6 scenarios.

export const BASE_URL = __ENV.BASE_URL || "http://127.0.0.1:8010";
export const API_KEY = __ENV.API_KEY || "";

export const TREND_STATS = ["avg", "min", "med", "p(90)", "p(95)", "p(99)", "max"];

const ACTIONS = [
  ["auth.login.succeeded", "iam.user"],
  ["auth.login.failed", "iam.user"],
  ["storage.object.read", "storage.object"],
  ["storage.object.deleted", "storage.object"],
  ["edr.process.blocked", "host"],
];

// 85 % INFO, 12 % WARN, 3 % CRITICAL: the same mix as the seeded dataset.
function severity() {
  const roll = Math.random();
  if (roll < 0.03) return "CRITICAL";
  if (roll < 0.15) return "WARN";
  return "INFO";
}

export function makeEvent(index, overrides = {}) {
  const [action, resourceType] = ACTIONS[index % ACTIONS.length];
  return Object.assign(
    {
      action,
      resource_type: resourceType,
      resource_id: `res-${Math.floor(Math.random() * 20000)}`,
      actor_id: `user-${Math.floor(Math.random() * 5000)}`,
      ip_address: `203.0.113.${1 + Math.floor(Math.random() * 254)}`,
      user_agent: "k6-loadtest",
      severity: severity(),
      metadata: { country: "DE", mfa: Math.random() < 0.8, rule_id: `R-${index}` },
      // Unique per request: every event is new, so nothing is reported as duplicate.
      idempotency_key: `k6-${__VU}-${__ITER}-${index}-${Date.now()}`,
    },
    overrides,
  );
}

export function ingestHeaders() {
  return { "Content-Type": "application/json", "X-API-Key": API_KEY };
}
