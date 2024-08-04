# Evaluating Ghidra's BSIM
Collection of helper scripts and results in evaluating the accuracy, efficiency, and overall performance of Ghidra's BSim utility. BSim uses LSH-based fuzzy hashing to measure similarity of binaries given a database of known feature vectors. Features include dataflow and control flow information that model the *behavioral* characteristics - hence, BSim or *Behavioral* Similarity - of a program.

BSim provides two metrics when performing similarity comparison - *similarity* and *confidence*. Similarity is a direct measure of how many features are matched between the database's function and the target binary's function. *Confidence*, however, is a measure of the uniqueness, strength, and/or degree of the match. Confidence is proportional with the number of features matched and improves when these features are *less common* across the database. 

## Running Tools

1. Create a project for the database binary
```sh
$ analyzeHeadless <project_location> <project_name> -import <file_to_get_features> 
```

2. Generate Signatures
```sh
$ bsim generatesigs ghidra:<project_location> --bsim file:<output_path_of_database>
```

3. Create new project for target binary
```
$ analyzeHeadless <project_location_2> <project_name_2> -import <file_to_analyze>
```

4. Compare similarity to database functions 
```
$ analyzeHeadless <project_location_2> <project_name_2> -process -scriptPath ./ghidra_scripts -postScript QueryAllFunctions.java file:<output_path_of_database> 
```
## Results

Current collection of results stored [here](./results)
