# Results
Collection of results from evaluation of BSim

## SQLite - *C*

**Methodology:** 
1. Compile SQLite CLI interface using *clang* optimization levels `-O0`, `-O1`, `-O2`, and `-O3`.
2. Create a BSim database and store the features from `-O0`
3. Compare all other optimization levels against the `-O0` signatures
4. Evaluate match rate, similarity and it's distribution, confidence and it's distribution, and compare similarity v. confidence

**Artifacts:**
- Matched functions from BSim queries
- Graphs from data analysis

## Bat - *Rust*

**Methodology**
1. Compile (bat)[] via *cargo* with optimization levels `O0`, `O1`, `O2`, and `O3`. Configure this in `cargo.toml` as separate profiles
2. Crate a BSim database and store the features from `O0`
3. Compare all other optmization levels against the `O0` signatures
4. Filter out all results that do not include the top-level `bat` namespace. Rust statically links it's standard library and dependencies, so much more is included in the binary. 
5. Evaluate match rate, similarity and it's distribution, confidence and it's distribution, and compare similarity v. confidence

**Artifacts:**
- matched functions (only `bat` namespace) from BSim queries
- graphs from data analysis
