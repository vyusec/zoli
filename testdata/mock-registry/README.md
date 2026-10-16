# Mock registry

A minimal npm registry for the Phase 2 Docker gate: packuments and tarballs for a direct dependency and a transitive dependency, with one version flagged by a synthetic signed feed. Real npm installs through Zoli against this registry must block both, and leave the rest of npm's output unchanged.

Synthetic data only. Never publish these packages or this feed. Empty until Phase 2.
