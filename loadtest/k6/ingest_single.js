// Single-event ingestion latency at a fixed arrival rate (open model).
//
//   k6 run -e API_KEY=sntl_... -e RATE=200 -e DURATION=60s ingest_single.js
//
// With -e ACTION=bench.latency.probe -e SEVERITY=CRITICAL it also drives the
// event-to-webhook latency benchmark (see loadtest/README.md).

import http from "k6/http";
import { check } from "k6";

import { BASE_URL, TREND_STATS, ingestHeaders, makeEvent } from "./lib.js";

const overrides = {};
if (__ENV.ACTION) overrides.action = __ENV.ACTION;
if (__ENV.SEVERITY) overrides.severity = __ENV.SEVERITY;

export const options = {
  scenarios: {
    single: {
      executor: "constant-arrival-rate",
      rate: Number(__ENV.RATE || 200),
      timeUnit: "1s",
      duration: __ENV.DURATION || "60s",
      preAllocatedVUs: Number(__ENV.PRE_VUS || 50),
      maxVUs: Number(__ENV.MAX_VUS || 200),
    },
  },
  thresholds: {
    http_req_failed: ["rate<0.01"],
    "http_reqs{name:single_ingest}": ["count>0"],
    "http_req_duration{name:single_ingest}": ["p(95)<500"],
  },
  summaryTrendStats: TREND_STATS,
};

export default function () {
  const response = http.post(
    `${BASE_URL}/api/v1/audit/events/`,
    JSON.stringify(makeEvent(__ITER, overrides)),
    { headers: ingestHeaders(), tags: { name: "single_ingest" } },
  );
  check(response, { "status is 201": (r) => r.status === 201 });
}
