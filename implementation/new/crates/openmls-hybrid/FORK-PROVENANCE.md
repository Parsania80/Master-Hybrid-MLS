# OpenMLS Hybrid Fork Provenance

This directory is a local thesis fork imported from the OpenMLS source at
commit `47dbedecad0c1fd8eb5368d582250ebfcc1e1ce6`, the `openmls-v0.8.1` tag.

The upstream source, `LICENSE`, notices, and sibling crates are retained here.
The fork package is named `openmls-hybrid` and exposes an opt-in
`experimental-hybrid` feature. The parent workspace continues to depend on
the unmodified crates.io `openmls = 0.8.1` for the RFC 9420 baseline.

No hybrid UpdatePath, authenticated ArityState, or adaptive TreeKEM behavior
has been implemented merely by importing this source. Those changes must stay
behind the opt-in feature, be reviewed against this upstream base, and retain
the research-only limitations in `SECURITY.md` and ADR 0001.
