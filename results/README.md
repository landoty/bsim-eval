# Results
Collection of results from evaluation of BSim

## SQLite

**Methodology:** 
1. Compile SQLite CLI interface using *clang* optimization levels `-O0`, `-O1`, '-O2`, and `-O3`.
2. Create a BSim database and store the features from `-O0`
3. Compare all other optimization levels against the `-O0` signatures
4. Evaluate match rate, similarity and it's distribution, confidence and it's distribution, and compare similarity v. confidence

**Artifacts:**
- Matched functions from BSim queries
- Graphs from data analysis
