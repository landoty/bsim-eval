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
1. Compile [bat](https://github.com/sharkdp/bat) via *cargo* with optimization levels `O0`, `O1`, `O2`, and `O3`. Configure this in `cargo.toml` as separate profiles
2. Crate a BSim database and store the features from `O0`
3. Compare all other optmization levels against the `O0` signatures
4. Filter out all results that do not include the top-level `bat` namespace. Rust statically links it's standard library and dependencies, so much more is included in the binary. 
5. Evaluate match rate, similarity and it's distribution, confidence and it's distribution, and compare similarity v. confidence

**Artifacts:**
- matched functions (only `bat` namespace) from BSim queries
- graphs from data analysis

## Bat + Stdlib - *Rust*

**Methodology**
1. Create a BSim database and store the features from the static `Rust standard
   lirbary`. Currently version 1.80
2. Using the various optimization-level-compiled versions of `bat`, compare
   against `rust-stdlib-v1.80`
3. Evaluate match rate, similarity and it's distribution, confidence and it's distribution, and compare similarity v. confidence

**Artifacts:**
- matched functions (only `stdlib`) from BSim queries
- graphs from data analysis

## Hyper - *Rust*

**Motivation**

The results from *Bat* were less than ideal in terms of query match accuracy. To confirm if this behavior from BSim was unique to the Bat application or actually affected by differens in source-level language and semantics, we need to collect more data.

Hyper is a HTTP library written in Rust, providing interfaces for both HTTP servers and clients. We build the `Hello World` example from their documentation and generate signatures/perform queries on the included Hyper libraries.

**Methodology**
1. Build and compile the Hello World HTTP server [from the Hyper Libray guide](https://hyper.rs/guides/1/server/hello-world/) at optimization levels O0 - O4
2. 

## Correlation

**Methodology**
1. Combine all results from SQLite, Bat, and Bat + Stdlib
2. Collect correct and incorrect matches
3. Use a box plot to distinguish which metric (similarity v. confidence) is a
   better indicator for function similarity

**Artifacts**
- box plots correlating confidence and similarity with match counts
- normalized version to show overlap of incorrectly matched confidence scores
  across range of possible values
