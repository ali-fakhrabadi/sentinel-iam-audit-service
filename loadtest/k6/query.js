// Query latency over a seeded dataset at a fixed arrival rate (open model): a weighted
// mix of the filters a SOC analyst or SIEM uses, plus deep keyset pagination (five
// cursor hops per walk).
//
//   k6 run -e EMAIL=... -e PASSWORD=... -e RATE=25 -e DURATION=60s query.js

import http from "k6/http";
import { check, group } from "k6";

import { BASE_URL, TREND_STATS } from "./lib.js";

export const options = {
  scenarios: {
    analysts: {
      executor: "constant-arrival-rate",
      rate: Number(__ENV.RATE || 25),
      timeUnit: "1s",
      duration: __ENV.DURATION || "60s",
      preAllocatedVUs: 20,
      maxVUs: 100,
    },
  },
  thresholds: {
    http_req_failed: ["rate<0.01"],
    "http_reqs{name:q_newest}": ["count>0"],
    "http_reqs{name:q_actor}": ["count>0"],
    "http_reqs{name:q_resource}": ["count>0"],
    "http_reqs{name:q_critical}": ["count>0"],
    "http_reqs{name:q_action}": ["count>0"],
    "http_reqs{name:q_metadata}": ["count>0"],
    "http_reqs{name:q_cursor_hop}": ["count>0"],
    "http_req_duration{name:q_newest}": ["p(95)<500"],
    "http_req_duration{name:q_actor}": ["p(95)<500"],
    "http_req_duration{name:q_resource}": ["p(95)<500"],
    "http_req_duration{name:q_critical}": ["p(95)<500"],
    "http_req_duration{name:q_action}": ["p(95)<500"],
    "http_req_duration{name:q_metadata}": ["p(95)<1000"],
    "http_req_duration{name:q_cursor_hop}": ["p(95)<500"],
  },
  summaryTrendStats: TREND_STATS,
};

export function setup() {
  const response = http.post(
    `${BASE_URL}/api/v1/auth/token/`,
    JSON.stringify({ email: __ENV.EMAIL, password: __ENV.PASSWORD }),
    { headers: { "Content-Type": "application/json" } },
  );
  if (response.status !== 200) {
    throw new Error(`login failed with status ${response.status}`);
  }
  return { token: response.json("access") };
}

function get(token, params, name) {
  const query = Object.entries(params)
    .map(([key, value]) => `${encodeURIComponent(key)}=${encodeURIComponent(value)}`)
    .join("&");
  const url = `${BASE_URL}/api/v1/audit/events/${query ? `?${query}` : ""}`;
  const response = http.get(url, {
    headers: { Authorization: `Bearer ${token}` },
    tags: { name },
  });
  check(response, { [`${name} 200`]: (r) => r.status === 200 });
  return response;
}

const random = (max) => Math.floor(Math.random() * max);

export default function (data) {
  const roll = Math.random();
  if (roll < 0.3) {
    get(data.token, {}, "q_newest");
  } else if (roll < 0.5) {
    get(data.token, { actor_id: `user-${String(random(50)).padStart(4, "0")}` }, "q_actor");
  } else if (roll < 0.65) {
    get(data.token, { resource_type: "storage.bucket", resource_id: `bucket-${random(20000)}` }, "q_resource");
  } else if (roll < 0.8) {
    get(data.token, { severity: "CRITICAL" }, "q_critical");
  } else if (roll < 0.9) {
    get(data.token, { action: "auth.login.failed" }, "q_action");
  } else if (roll < 0.95) {
    get(data.token, { metadata_contains: JSON.stringify({ rule_id: `R-${random(5000)}` }) }, "q_metadata");
  } else {
    group("deep pagination", () => {
      let page = get(data.token, { page_size: 100 }, "q_newest");
      for (let hop = 0; hop < 5 && page.status === 200 && page.json("next_cursor"); hop++) {
        page = get(data.token, { page_size: 100, cursor: page.json("next_cursor") }, "q_cursor_hop");
      }
    });
  }
}
