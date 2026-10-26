| Run | Operation | Requests | Throughput | p50 ms | p95 ms | p99 ms | Errors |
|---|---|---|---|---|---|---|---|
| bulk_10vus | bulk_ingest | 1,065 | 17.6 req/s (1,760 events/s) | 602.6 | 917.3 | 1,063.9 | 0.00 % |
| bulk_2vus | bulk_ingest | 719 | 12.0 req/s (1,196 events/s) | 148.7 | 252.9 | 353.2 | 0.00 % |
| query_25rps | q_action | 156 | 2.6 req/s | 31.8 | 68.6 | 121.8 | 0.00 % |
| query_25rps | q_actor | 271 | 4.5 req/s | 34.0 | 118.0 | 162.5 | 0.00 % |
| query_25rps | q_critical | 222 | 3.7 req/s | 32.2 | 84.2 | 136.0 | 0.00 % |
| query_25rps | q_cursor_hop | 320 | 5.3 req/s | 55.3 | 125.9 | 167.4 | 0.00 % |
| query_25rps | q_metadata | 94 | 1.6 req/s | 63.8 | 139.2 | 765.5 | 0.00 % |
| query_25rps | q_newest | 531 | 8.8 req/s | 32.3 | 82.1 | 129.7 | 0.00 % |
| query_25rps | q_resource | 227 | 3.8 req/s | 16.3 | 57.4 | 140.8 | 0.00 % |
| single_50rps | single_ingest | 3,000 | 50.0 req/s | 19.6 | 33.5 | 56.9 | 0.00 % |
| single_saturation_200rps | single_ingest | 4,880 | 148.8 req/s | 2,418.7 | 2,901.6 | 3,013.6 | 0.00 % |
| webhook_idle_20rps | single_ingest | 1,200 | 20.0 req/s | 22.3 | 36.6 | 70.3 | 0.00 % |
| webhook_loaded_10rps | single_ingest | 601 | 10.0 req/s | 120.9 | 532.4 | 639.2 | 0.00 % |
