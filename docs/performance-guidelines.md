# Performance Guidelines — OwlEyeEngine

Best practices for maintaining fast execution and lightweight runtime overhead:

1. **Asset & Memory Hygiene**: Prune unused modules, avoid circular references, and leverage stream-based processing where suitable.
2. **Deterministic Builds**: Lock dependency versions and ensure repeatable builds across environments.
3. **Execution Latency**: Keep latency-critical paths free of synchronous blocking operations.
