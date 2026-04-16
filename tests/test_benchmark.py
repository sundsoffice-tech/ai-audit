"""Public performance benchmarks for ai-audit-trail.

These tests measure and report key performance characteristics so that
downstream consumers can evaluate overhead. They are not regression tests
(timings are machine-dependent) but rather documentation of expected
performance envelopes.

Run: ``uv run pytest tests/test_benchmark.py -v -s``
"""

import statistics
import time
from datetime import UTC, datetime

from ai_audit import (
    AuditConfig,
    ReceiptAction,
    ReceiptCollector,
    ReceiptStore,
    get_verify_key_hex,
    init_audit_config,
    reset_signing_key,
    verify_chain,
)


def setup_function() -> None:
    reset_signing_key()
    init_audit_config(AuditConfig(is_production=False))


def _make_receipt(store: ReceiptStore, tenant: str = "bench", idx: int = 0) -> str:
    c = ReceiptCollector(trace_id=f"t{idx}", tenant_id=tenant, session_id=f"s{idx}")
    c.set_input(f"Benchmark query number {idx} with some realistic payload length")
    c.add_check("safety", score=0.05, threshold=0.8, fired=False)
    c.add_check("routing", score=0.9, threshold=0.5, fired=True)
    c.set_output(f"Benchmark answer number {idx} with a medium-length response body for realism")
    c.set_action(ReceiptAction.ALLOW)
    rid = c.emit(store)
    c.cleanup()
    return rid


def test_seal_latency() -> None:
    """Measure seal() latency (hash + sign) per receipt.

    Target: < 100 microseconds per seal on modern hardware.
    """
    store = ReceiptStore()
    warmup = 50
    iterations = 500

    # Warmup
    for i in range(warmup):
        _make_receipt(store, idx=i)

    store2 = ReceiptStore()
    timings: list[float] = []
    for i in range(iterations):
        c = ReceiptCollector(trace_id=f"t{i}", tenant_id="bench")
        c.set_input(f"Query {i}")
        c.add_check("safety", score=0.05, threshold=0.8)
        c.set_output(f"Answer {i}")
        c.set_action(ReceiptAction.ALLOW)

        start = time.perf_counter_ns()
        c.emit(store2)
        elapsed_ns = time.perf_counter_ns() - start
        timings.append(elapsed_ns)
        c.cleanup()

    p50 = statistics.median(timings)
    p99 = sorted(timings)[int(len(timings) * 0.99)]
    mean = statistics.mean(timings)

    print(f"\n--- seal() latency ({iterations} iterations) ---")
    print(f"  mean: {mean / 1000:.1f} µs")
    print(f"  p50:  {p50 / 1000:.1f} µs")
    print(f"  p99:  {p99 / 1000:.1f} µs")

    # Soft assertion — don't fail CI on slow machines, but flag it
    assert p50 < 5_000_000, f"seal() p50 exceeds 5ms: {p50 / 1000:.1f} µs"


def test_verify_chain_throughput() -> None:
    """Measure verify_chain() throughput for chains of various sizes.

    Target: 1000 receipts verified in < 50ms.
    Note: Receipts are given explicit sequential timestamps to avoid
    timestamp collisions that break chain ordering under tight loops.
    """
    from datetime import timedelta

    for chain_size in [100, 500, 1000]:
        store = ReceiptStore()
        base_time = datetime.now(UTC)
        for i in range(chain_size):
            c = ReceiptCollector(trace_id=f"t{i}", tenant_id="bench")
            c.set_input(f"query {i}")
            c.set_output(f"answer {i}")
            c.set_action(ReceiptAction.ALLOW)
            # Force unique timestamps so verify_chain sort matches insertion order
            c._receipt.timestamp = base_time + timedelta(microseconds=i)
            c.emit(store)
            c.cleanup()

        receipts = store.get_by_tenant("bench")
        vk = get_verify_key_hex()

        start = time.perf_counter_ns()
        result = verify_chain(receipts, vk)
        elapsed_ns = time.perf_counter_ns() - start

        assert result.valid, f"Chain broken at {result.first_failure_idx}: {result.error}"
        elapsed_ms = elapsed_ns / 1_000_000

        print(f"\n--- verify_chain({chain_size} receipts) ---")
        print(f"  time:       {elapsed_ms:.1f} ms")
        print(f"  per-receipt: {elapsed_ns / chain_size / 1000:.1f} µs")

    # Soft assertion for 1000-receipt chain
    assert elapsed_ms < 5000, f"verify_chain(1000) exceeds 5s: {elapsed_ms:.1f} ms"


def test_memory_footprint() -> None:
    """Measure in-memory footprint of ReceiptStore.

    Reports approximate bytes per receipt for capacity planning.
    """
    import sys

    store = ReceiptStore()
    base_size = sys.getsizeof(store._receipts)

    count = 1000
    for i in range(count):
        _make_receipt(store, idx=i)

    loaded_size = sys.getsizeof(store._receipts)
    # Approximate per-receipt overhead (dict entry + receipt object)
    receipts = list(store._receipts.values())
    sample_sizes = [sys.getsizeof(r) for r in receipts[:10]]
    avg_receipt_size = statistics.mean(sample_sizes)

    print(f"\n--- Memory footprint ({count} receipts) ---")
    print(f"  OrderedDict overhead: {loaded_size - base_size:,} bytes")
    print(f"  Avg receipt (shallow): {avg_receipt_size:.0f} bytes")
    print(f"  Store count: {store.count}")

    assert store.count == count
