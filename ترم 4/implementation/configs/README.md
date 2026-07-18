# Experiment Configuration

The typed public configuration schema lives in `crates/experiment-config`.

Runnable TOML configurations are deferred until the transition-policy and CLI tasks. Every valid configuration must provide exactly one Delta form, use relative output paths, and keep workload reproducibility data separate from secret key-generation entropy.
