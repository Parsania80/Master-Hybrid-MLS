# Experiment Configuration

The typed public configuration schema lives in `crates/experiment-config`.

Task 62 adds the checked-in real comparison triplet: `task62-baseline.toml`, `task62-mkyber.toml`, and `task62-adaptive.toml`. The strict comparison CLI requires all three files, validates that their group/transition/execution controls match, and executes all three real fixed-round-robin update-only workload clients. The 128-member, three-update shape is intentional: it is the smallest already-proven schedule that has a real adaptive transition plus a post-transition update.

The earlier `task57-*` files remain historical baseline-only inputs and are not suitable for the Task 62 real-client runner.

Every valid configuration must provide exactly one Delta form, use relative output paths, and keep workload reproducibility data separate from secret key-generation entropy.
