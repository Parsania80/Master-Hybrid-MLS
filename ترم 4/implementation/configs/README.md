# Experiment Configuration

The typed public configuration schema lives in `crates/experiment-config`.

Task 57 adds the checked-in public comparison triplet: `task57-baseline.toml`, `task57-mkyber.toml`, and `task57-adaptive.toml`. The strict comparison CLI requires all three files, validates that their group/transition/execution controls match, and derives only public workload-scheduling seeds. The maintained runner executes baseline repetitions only; the two experimental selected modes remain explicitly unavailable until an OpenMLS fork injects their authenticated behavior.

Every valid configuration must provide exactly one Delta form, use relative output paths, and keep workload reproducibility data separate from secret key-generation entropy.
