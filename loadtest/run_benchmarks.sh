#!/usr/bin/env bash
# Reproducible benchmark run: query plans, latency at sustainable rates, throughput,
# saturation, and event-to-webhook latency (idle and under ingestion load).
# Writes everything to loadtest/results/.
#
#   bash loadtest/run_benchmarks.sh
#
# Requirements: the stack from docker-compose.yml with a seeded database
# (see loadtest/README.md), Docker, curl, python3 and openssl on the host.
set -euo pipefail
cd "$(dirname "$0")/.."

BASE_URL="${BASE_URL:-http://127.0.0.1:$(grep '^SENTINEL_HTTP_PORT=' .env | cut -d= -f2)}"
DURATION="${DURATION:-60s}"
RESULTS=loadtest/results
COMPOSE=(docker compose -f docker-compose.yml -f loadtest/docker-compose.loadtest.yml)
K6=(docker run --rm --network host -u "$(id -u):$(id -g)"
    -v "$PWD/loadtest/k6:/scripts:ro" -v "$PWD/$RESULTS/raw:/results"
    grafana/k6:2.3.0 run --quiet --summary-mode=compact)
psql() { docker compose exec -T postgres psql -U postgres -d sentinel -tAc "$1"; }

mkdir -p "$RESULTS/raw"
rm -f "$RESULTS"/raw/*.json "$RESULTS"/raw/*.txt

echo "== environment"
{
  echo "date: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "host: $(nproc) vCPU, $(free -g | awk '/Mem:/{print $2}') GiB RAM, $(. /etc/os-release; echo "$PRETTY_NAME")"
  echo "container limits: web 2 vCPU / 768 MiB, postgres 2 vCPU / 1 GiB, worker 1 vCPU / 512 MiB"
  echo "postgres: $(psql 'SHOW server_version'), shared_buffers $(psql 'SHOW shared_buffers')"
  echo "audit events before run: $(psql 'SELECT count(*) FROM audit_logs_auditevent')"
  echo "gunicorn: ${GUNICORN_WORKERS:-3} workers x ${GUNICORN_THREADS:-4} threads; celery concurrency ${CELERY_WORKER_CONCURRENCY:-4}"
} | tee "$RESULTS/environment.txt"

echo "== benchmark stack (rate limits raised, local webhook receiver)"
"${COMPOSE[@]}" up --detach --build --wait --wait-timeout 180 --remove-orphans > /dev/null

echo "== benchmark identities"
BENCH_PASSWORD="$(openssl rand -hex 16)"
API_KEY="$(docker compose exec -T -e BENCH_PASSWORD="$BENCH_PASSWORD" web python manage.py shell -c "
import os
from apps.accounts import services
from apps.accounts.models import ServiceAccount, User
admin, _ = User.objects.get_or_create(email='bench-admin@sentinel.local')
admin.is_active = admin.is_superuser = True
admin.set_password(os.environ['BENCH_PASSWORD'])
admin.save()
account, _ = ServiceAccount.objects.get_or_create(name='bench-loadgen')
account.is_active = True
account.save()
print(services.api_key_issue(actor=admin, service_account=account, name='k6', scopes=['audit:write', 'audit:read']).raw_key)
" | tail -n 1)"
[[ "$API_KEY" == sntl_* ]] || { echo "could not issue the benchmark key" >&2; exit 1; }
docker compose exec -T worker python manage.py shell -c "
from apps.webhooks.crypto import encrypt_secret, generate_signing_secret
from apps.webhooks.models import WebhookEndpoint
WebhookEndpoint.objects.update_or_create(name='bench-receiver', defaults={
    'url': 'http://webhook-receiver:8080/hook', 'min_severity': 'CRITICAL',
    'action_prefixes': ['bench'], 'is_active': True,
    'secret_ciphertext': encrypt_secret(generate_signing_secret())})
" > /dev/null

k6() {  # k6 <result-name> <script> [-e KEY=VALUE ...]
  local name="$1" script="$2"
  shift 2
  "${K6[@]}" -e BASE_URL="$BASE_URL" -e API_KEY="$API_KEY" "$@" \
    --summary-export "/results/${name}.json" "/scripts/${script}" > "$RESULTS/raw/${name}.log" 2>&1 || true
  grep -E "http_req_duration\{name|http_req_failed|events_accepted" "$RESULTS/raw/${name}.log" | head -4
}

webhook_latency() {  # webhook_latency <label> <action> <since>
  local label="$1" action="$2" since="$3"
  for _ in $(seq 1 180); do
    open="$(psql "SELECT count(*) FROM webhooks_webhookdelivery d JOIN audit_logs_auditevent e ON e.id = d.event_id
                  WHERE e.action = '$action' AND e.created_at >= '$since'
                  AND d.status NOT IN ('succeeded', 'failed', 'exhausted')")"
    events="$(psql "SELECT count(*) FROM audit_logs_auditevent WHERE action = '$action' AND created_at >= '$since'")"
    delivered="$(psql "SELECT count(*) FROM webhooks_webhookdelivery d JOIN audit_logs_auditevent e ON e.id = d.event_id
                       WHERE e.action = '$action' AND e.created_at >= '$since'")"
    [[ "$open" == 0 && "$delivered" == "$events" ]] && break
    sleep 1
  done
  psql "SELECT '$label: ' || count(*) || ' events, '
          || count(*) FILTER (WHERE d.status = 'succeeded') || ' delivered; commit -> webhook acknowledged ms: '
          || 'p50=' || round((percentile_cont(0.5) WITHIN GROUP (ORDER BY extract(epoch FROM d.completed_at - e.created_at)))::numeric * 1000)
          || ' p95=' || round((percentile_cont(0.95) WITHIN GROUP (ORDER BY extract(epoch FROM d.completed_at - e.created_at)))::numeric * 1000)
          || ' p99=' || round((percentile_cont(0.99) WITHIN GROUP (ORDER BY extract(epoch FROM d.completed_at - e.created_at)))::numeric * 1000)
          || ' max=' || round((max(extract(epoch FROM d.completed_at - e.created_at)))::numeric * 1000)
        FROM webhooks_webhookdelivery d JOIN audit_logs_auditevent e ON e.id = d.event_id
        WHERE e.action = '$action' AND e.created_at >= '$since'" | tee -a "$RESULTS/webhook_latency.txt"
}
: > "$RESULTS/webhook_latency.txt"

echo "== query plans (1M+ rows)"
docker compose --profile dev run --rm dev python manage.py shell \
  -c "exec(open('loadtest/explain_queries.py').read())" 2>/dev/null > "$RESULTS/explain.txt"
grep -E '^(###|execution|audit table|sequential|dataset)' "$RESULTS/explain.txt"

echo "== webhook latency on an idle system (CRITICAL events at 20/s)"
since="$(psql 'SELECT now()')"
k6 webhook_idle_20rps ingest_single.js -e RATE=20 -e DURATION="$DURATION" -e ACTION=bench.latency.idle -e SEVERITY=CRITICAL
webhook_latency "idle" bench.latency.idle "$since"

echo "== query latency at 25 req/s"
k6 query_25rps query.js -e EMAIL=bench-admin@sentinel.local -e PASSWORD="$BENCH_PASSWORD" -e RATE=25 -e DURATION="$DURATION"

echo "== single-event ingestion latency at 50 req/s"
k6 single_50rps ingest_single.js -e RATE=50 -e DURATION="$DURATION"

echo "== bulk ingestion latency (100 events/request, 2 VUs)"
k6 bulk_2vus ingest_bulk.js -e VUS=2 -e BATCH=100 -e DURATION="$DURATION"

echo "== bulk ingestion throughput (100 events/request, 10 VUs) + webhook probe at 10/s in parallel"
since="$(psql 'SELECT now()')"
( sleep 30; docker stats --no-stream --format '{{.Name}} cpu={{.CPUPerc}} mem={{.MemUsage}}' \
    > "$RESULTS/raw/stats_bulk_10vus.txt" ) &
k6 webhook_loaded_10rps ingest_single.js -e RATE=10 -e DURATION="$DURATION" -e ACTION=bench.latency.loaded -e SEVERITY=CRITICAL &
k6 bulk_10vus ingest_bulk.js -e VUS=10 -e BATCH=100 -e DURATION="$DURATION"
wait
webhook_latency "under bulk load" bench.latency.loaded "$since"

echo "== saturation: single events offered at 200 req/s for 30 s"
k6 single_saturation_200rps ingest_single.js -e RATE=200 -e DURATION=30s -e MAX_VUS=400

echo "== summary"
python3 loadtest/summarize_k6.py "$RESULTS"/raw/*.json | tee "$RESULTS/summary.md"
echo "audit events after run: $(psql 'SELECT count(*) FROM audit_logs_auditevent')" | tee -a "$RESULTS/environment.txt"

echo "== restore the normal stack and deactivate benchmark identities"
docker compose up --detach --wait --wait-timeout 180 --remove-orphans > /dev/null
docker compose exec -T web python manage.py shell -c "
from apps.accounts.models import APIKey, ServiceAccount, User
from apps.webhooks.models import WebhookEndpoint
from django.utils import timezone
WebhookEndpoint.objects.filter(name='bench-receiver').update(is_active=False)
APIKey.objects.filter(service_account__name='bench-loadgen', revoked_at__isnull=True).update(revoked_at=timezone.now())
ServiceAccount.objects.filter(name='bench-loadgen').update(is_active=False)
User.objects.filter(email='bench-admin@sentinel.local').update(is_active=False)
" > /dev/null
echo "done"
