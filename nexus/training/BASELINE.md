# Baseline — Qwen3-4B Q4_K_M on CPU

Date: 2026-07-23

Host: Intel i5-4570T, 4 threads, 15.5 GiB RAM, no CUDA.

- llama.cpp server memory while idle: about 2.5 GiB
- observed generation: about 4 tokens/s
- single answers: roughly 20–80 seconds depending on prompt/context
- RAG retrieval recall@1: 5/5
- routing smoke cases: username and CVE/banner cases passed
- CSP case: chooses the correct `headers` module after the RAG correction,
  but may assign an unsupported default severity (“moyen à élevé”)

This is the pre-training reference. The CSP severity error is intentionally
kept as a failing evaluation criterion. The GPU-trained adapter must improve
tool-name accuracy and calibrated claims without regressing the passing cases.
