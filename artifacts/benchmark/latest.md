# PRism Benchmark Report

**Benchmark Version:** 1.0.0  
**Dataset Version:** 1.0.0  
**Execution Timestamp:** `2026-10-08T09:49:24.567829+00:00`  
**Python Version:** `3.12.12`  
**Model Mode:** `mock`  
**Random Seed:** `42`  

## Summary Metrics

- **Dataset:** 25 scenarios
- **Passed Scenarios:** 25 / 25 (100.0%)
- **Risk Accuracy:** 100.0%
- **Risk Macro F1:** 100.0%
- **HIGH+ Recall:** 100.0%
- **Human Gate Recall:** 100.0%
- **Human Gate Accuracy:** 100.0%
- **Injection Detection Recall:** 100.0%
- **Injection Detection Accuracy:** 100.0%
- **Finding F1:** 100.0%
- **Finding Precision:** 100.0%
- **Finding Recall:** 100.0%
- **Policy Accuracy:** 100.0%
- **Mean Local Latency:** 6.35 ms
- **P95 Local Latency:** 8.84 ms

## Risk Confusion Matrix

| Actual \ Predicted | Low | Medium | High | Critical |
| :--- | :---: | :---: | :---: | :---: |
| **LOW** | 5 | 0 | 0 | 0 |
| **MEDIUM** | 0 | 5 | 0 | 0 |
| **HIGH** | 0 | 0 | 10 | 0 |
| **CRITICAL** | 0 | 0 | 0 | 5 |

## Per-category Results

| Category | Count | Correct | Accuracy |
| :--- | :---: | :---: | :---: |
| **Benign** | 5 | 5 | 100.0% |
| **Code Quality** | 5 | 5 | 100.0% |
| **Security** | 5 | 5 | 100.0% |
| **Critical** | 5 | 5 | 100.0% |
| **Adversarial** | 5 | 5 | 100.0% |

## Finding Metrics By Category

| Finding Category | Precision | Recall | F1 | Support |
| :--- | :---: | :---: | :---: | :---: |
| **bug** | 100.0% | 100.0% | 100.0% | 4.0 |
| **security** | 100.0% | 100.0% | 100.0% | 8.0 |
| **secret_leak** | 100.0% | 100.0% | 100.0% | 4.0 |
| **test_gap** | 100.0% | 100.0% | 100.0% | 1.0 |
| **injection** | 100.0% | 100.0% | 100.0% | 5.0 |

## Execution Latency Profile

- **Note:** These measurements reflect local deterministic execution duration, not production network latency.
- **Mean Latency:** 6.35 ms
- **Median Latency:** 6.17 ms
- **P95 Latency:** 8.84 ms
- **Min Latency:** 5.98 ms
- **Max Latency:** 9.8 ms

## Failure Analysis

No benchmark mismatches detected.
