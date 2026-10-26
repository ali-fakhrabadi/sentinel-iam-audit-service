// Bulk ingestion throughput: each iteration posts one batch (default 100 events).
//
//   k6 run -e API_KEY=sntl_... -e VUS=20 -e DURATION=60s -e BATCH=100 ingest_bulk.js

import http from "k6/http";
import { check } from "k6";
import { Counter } from "k6/metrics";

import { BASE_URL, TREND_STATS, ingestHeaders, makeEvent } from "./lib.js";

const BATCH = Number(__ENV.BATCH || 100);
const eventsAccepted = new Counter("events_accepted");

export const options = {
  scenarios: {
    bulk: {
      executor: "constant-vus",
      vus: Number(__ENV.VUS || 20),
      duration: __ENV.DURATION || "60s",
    },
  },
  thresholds: {
    http_req_failed: ["rate<0.01"],
    "http_reqs{name:bulk_ingest}": ["count>0"],
    "http_req_duration{name:bulk_ingest}": ["p(95)<2000"],
  },
  summaryTrendStats: TREND_STATS,
};

export default function () {
  const events = Array.from({ length: BATCH }, (_, index) => makeEvent(index));
  const response = http.post(
    `${BASE_URL}/api/v1/audit/events/bulk/`,
    JSON.stringify({ events }),
    { headers: ingestHeaders(), tags: { name: "bulk_ingest" } },
  );
  const ok = check(response, {
    "status is 200": (r) => r.status === 200,
    "whole batch accepted": (r) => r.status === 200 && r.json("accepted") === BATCH,
  });
  if (ok) {
    eventsAccepted.add(BATCH);
  }
}
