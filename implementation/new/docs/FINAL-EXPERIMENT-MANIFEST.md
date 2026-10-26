# Final Clean-Checkout Experiment Manifest

## Freeze boundary

This manifest records one clean-checkout reproduction of the supported thesis
workflow. SHA-256 is the integrity rule: every listed input and output must
match its digest before it is reused as final evidence. A digest mismatch means
the record is no longer the frozen result.

The clean checkout was a detached local Git worktree at repository revision
`603159be358934c92bf47617de4ca039138b9ad4`, created before any Task 70
command ran. Its Rust workspace path was `ترم 4/implementation`; it had no
tracked modifications. The workspace used the repository-pinned Rust `1.93.1`
toolchain and the committed lockfile below. All Cargo commands used `--locked
--offline`.

## Reproduction contract

The byte and state comparison is exact: the three emitted-Commit totals,
adaptive transition bytes, adaptive post-transition update count, Task 67 row
count, and availability/provenance validation must match. Lifecycle elapsed
time and peak RSS have no numeric equality tolerance because they are explicitly
environment-dependent local observations, not CPU or network benchmarks. They
are recorded and hashed, but must not be compared as a performance regression.

The 128-member comparison controls are public and fixed: three update-only
operations, zero warmup, one repetition, two regions, and the Task 62
fixed-round-robin configuration. The public workload seed is `62`; it selects
the schedule and is not cryptographic entropy.

Task 65 needs the completed Task 61 public summary. Re-running Task 61's
separate 128-member adaptive workload is outside this clean reproduction, so
the summary is an explicitly hashed external public input. No private state,
ciphertext body, key, secret, or raw entropy was imported.

## Exact command sequence

```text
git worktree add --detach <clean-worktree> 603159be358934c92bf47617de4ca039138b9ad4
cd <clean-worktree>/ترم 4/implementation

cargo fmt --all --check
cargo test -p adaptive-hybrid-mls -p adaptive-tree -p arity-state -p experiment-config -p experimental-mls-adapter -p hybrid-path-secret -p metrics -p mkyber -p mls-adapter -p report -p simulation -p transition-auth -p transition-tree -p transition-policy --all-targets --locked --offline
cargo test --doc -p adaptive-hybrid-mls -p adaptive-tree -p arity-state -p experiment-config -p experimental-mls-adapter -p hybrid-path-secret -p metrics -p mkyber -p mls-adapter -p report -p simulation -p transition-auth -p transition-tree -p transition-policy --locked --offline
cargo build -p adaptive-hybrid-mls -p adaptive-tree -p arity-state -p experiment-config -p experimental-mls-adapter -p hybrid-path-secret -p metrics -p mkyber -p mls-adapter -p report -p simulation -p transition-auth -p transition-tree -p transition-policy --release --locked --offline

cargo run -p report --bin compare_modes --release --locked --offline -- --baseline-config configs/task62-baseline.toml --mkyber-config configs/task62-mkyber.toml --adaptive-config configs/task62-adaptive.toml --initial-members 128 --maximum-members 128 --operations 3 --regions 2 --output output/task70-clean-core-128 --report report/task70-clean-core-128
cargo run -p report --bin plot_mode_comparison --release --locked --offline -- --comparison-csv output/task70-clean-core-128/mode_comparison.csv --output output/task70-clean-core-128 --report report/task70-clean-core-128
cargo run -p report --bin collect_environment --release --locked --offline -- --output output/task70-clean-environment-128 --label task70-clean-128 --repetitions 1 -- target/release/compare_modes --baseline-config configs/task62-baseline.toml --mkyber-config configs/task62-mkyber.toml --adaptive-config configs/task62-adaptive.toml --initial-members 128 --maximum-members 128 --operations 3 --regions 2 --output output/task70-clean-rss-128 --report report/task70-clean-rss-128
cargo run -p report --bin generate_normal_operations --release --locked --offline -- --repetitions 1 --output output/task70-clean-normal-operations --report report/task70-clean-normal-operations
cargo run -p report --bin generate_transition_tables --release --locked --offline -- --task61-summary <public-task61-summary.json> --output output/task70-clean-transition-maturity --report report/task70-clean-transition-maturity
cargo run -p report --bin generate_model_errors --release --locked --offline -- --environment-json output/task70-clean-environment-128/environment.json --normal-operations-csv output/task70-clean-normal-operations/normal_operations.csv --transition-maturity-json output/task70-clean-transition-maturity/transition_maturity.json --output output/task70-clean-model-errors --report report/task70-clean-model-errors --timing-samples 25
cargo run -p report --bin generate_thesis_tables --release --locked --offline -- --comparison-csv output/task70-clean-core-128/mode_comparison.csv --environment-json output/task70-clean-environment-128/environment.json --normal-operations-csv output/task70-clean-normal-operations/normal_operations.csv --transition-maturity-json output/task70-clean-transition-maturity/transition_maturity.json --model-errors-json output/task70-clean-model-errors/model_errors.json --output output/task70-clean-thesis-tables --report report/task70-clean-thesis-tables
```

## Exact reproduced facts

| Fact | Reproduced value | State |
|---|---:|---|
| Baseline emitted Commit bytes | 33,068 | Observed local run |
| Binary-with-mKyber emitted Commit bytes | 87,012 | Observed local run |
| Adaptive emitted Commit bytes | 109,144 | Observed local run; includes transition |
| Adaptive matched-window saving | +7,256 bytes | Observed local run |
| Adaptive amortized-preflight saving | -18,366 bytes | Observed local run; not break-even |
| Adaptive actual transition bytes | 25,622 | Observed local run |
| Adaptive post-transition updates | 1 | Observed local run |
| Final thesis-table rows | 208 | Availability/provenance-checked |
| Direct-child peak RSS | 147,600 KiB | Observed local environment only |

TreeCover retirement remains `UnsupportedNoAuthenticatedRetirementCommit`.
Educational arity-4/8 and 4-to-8 values remain educational-only. No result in
this manifest upgrades the experimental fork to RFC interoperability, a
security proof, or a production claim.

## SHA-256 inputs

| Path | SHA-256 |
|---|---|
| `Cargo.lock` | `775caec3e9fb0dca4c655b5ce5b6b89c63ce3e5e3c9c4cd9bf53e97e2c803dbb` |
| `rust-toolchain.toml` | `162713004a236937311e636866219dc019297684304d082e2fc31eb23c91ebcf` |
| `configs/task62-baseline.toml` | `100d519b0cd92074f52e7c93d4d6e4a14cf2d750150e85104d96f2c1be590151` |
| `configs/task62-mkyber.toml` | `5f3f55e77dfee032f70ec31e457e8ecbab2b6abc6161f6bd932a503040119923` |
| `configs/task62-adaptive.toml` | `309b2efe4b165c157a565ee01a95f5f30923cc1f2f3096bf33ae82a561d7f7fc` |
| `output/task61-adaptive-128-matched-per-commit/summary.json` | `dbfa9b2ff3a40e9f712beb8f1b9c448275fed4293802f806499141297b5affcf` |

## SHA-256 outputs

| Path | SHA-256 |
|---|---|
| `output/task70-clean-core-128/mode_comparison.csv` | `b41c5a8b95eed3021253ae8b25303318d193bdb1b4a2e91e5a1d6a075c20e4b5` |
| `output/task70-clean-core-128/mode_comparison.json` | `2fc905f499a63d81cab0fe472eea7d7484141d3318822caeacecef7031b8d649` |
| `output/task70-clean-core-128/mode_comparison_plot_data.csv` | `549794c5bba9e182180eb2a686f4de1fd13c16633380cc59e49e168e8c279eb3` |
| `report/task70-clean-core-128/mode_comparison.md` | `56ed79041b7ba31b429c19a2aa7488d9bf2138906d051781d023ed16572b962f` |
| `report/task70-clean-core-128/mode_comparison_bytes.svg` | `05e801c5ad0cd6268e3cd7f9b56f3361a385a399d3ad5534f2f11868f42bef0a` |
| `report/task70-clean-core-128/mode_comparison_hybrid_counts.svg` | `374b1c631f30acec084f629ce7d2a8f37ab2997547d28bc657e5a14026361ec8` |
| `report/task70-clean-core-128/mode_comparison_lifecycle.svg` | `b267e5a5096263c4994dedc9b4d961b9aaca6b724feaed2ac8cba9b1e5a70c90` |
| `report/task70-clean-core-128/mode_comparison_transition.svg` | `7397b03ce56dc71ece81a77dad6806f6ca4908652567f5576eca430deed39893` |
| `output/task70-clean-rss-128/mode_comparison.csv` | `31495b007840db1aeb4490bdad07b47e0246cd939f7058934a268c08fcc755c7` |
| `output/task70-clean-rss-128/mode_comparison.json` | `3f011608ae16cc4db87089af8766c3615cda367733d29376879ff1d414261531` |
| `report/task70-clean-rss-128/mode_comparison.md` | `80986f314a0dc4730e36f41ab44b7f3bf2de746259f85356a9ddb4e606cd1a70` |
| `output/task70-clean-environment-128/environment.csv` | `8c67bd8d67fb22bf1625d567670a518507af7bc6ca2562310f3abb177362f7c0` |
| `output/task70-clean-environment-128/environment.json` | `3096fc9d5980dde92f893d4bde205baf81c9b02c88a7d1ccbe6cede134a3c651` |
| `output/task70-clean-environment-128/peak_rss.csv` | `f1b767a621b5d7232d2a665033affc85885175323d9bd39c513e50dc7fe10b33` |
| `output/task70-clean-normal-operations/normal_operations.csv` | `724fc4eb1417d042c807b9ee2ff68cddbf98f002cd889cf212dea6a3d72ecc2c` |
| `output/task70-clean-normal-operations/normal_operations.json` | `9ea6a12a4e8248afd91b53c6c6df752fed843a35b4ce5cd8a6689e704ec6b13a` |
| `report/task70-clean-normal-operations/normal_operations.md` | `dce579bef1d81e77b696f2ba0df6d95568df6492f3addbc280f309fb7e83ccf7` |
| `output/task70-clean-transition-maturity/transition_maturity.csv` | `19d123a44567640f552116f2b981bf8730aef74922c3ef9fa44bb32f336f6eee` |
| `output/task70-clean-transition-maturity/transition_maturity.json` | `77b07689036d0323030bc9177bf64f76becc04826158755d4661815f934ee2a7` |
| `report/task70-clean-transition-maturity/transition_maturity.md` | `475ad1cbd8292a6600900e0c6b6c2a914f280d6ea726b47405a79e32947dd9b7` |
| `output/task70-clean-model-errors/model_errors.csv` | `22bfd1bb73ddd08c363f4d6b0b2d743c5241f442fc5969c83d084222acc6b530` |
| `output/task70-clean-model-errors/model_errors.json` | `068faab7fb8faaab1a14ab23a602364ba1e614ce95a4b63226d433d8ad63afc3` |
| `report/task70-clean-model-errors/model_errors.md` | `6b5c7a66815e18ec1a71c9244984953a94e4a768060ce30540198d8e9d734e69` |
| `output/task70-clean-thesis-tables/thesis_tables.csv` | `8f92560077636ee7921f624085b6d6e48453c330645be5b67bab3b542734afce` |
| `output/task70-clean-thesis-tables/thesis_tables.json` | `41b1cfda5be3b160cc22b0c04d6c1c1417717436741184f9435b021af921379b` |
| `report/task70-clean-thesis-tables/thesis_tables.md` | `335d542069c3ca7b81007116f14d716aafc7d92f95d9880436105ff3abfb5bf0` |

## Final verification

The clean worktree passed the maintained package test/doc-test/release-build
boundary before artifact generation. The generated public Task 70 directories
passed a secret-marker scan for `private_key`, `shared_secret`, `path_secret`,
`aead_key`, and `raw_entropy`. The final CSV has exactly 208 data rows and its
validator preserves availability reason, provenance, source artifact, and
observed numeric zero. The copied public artifact directories above are the
local frozen evidence referenced by this manifest.
