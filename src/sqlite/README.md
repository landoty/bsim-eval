To reproduce the experimental binaries, download the [SQLite Amalgamation source](https://www.sqlite.org/2024/sqlite-amalgamation-3460100.zip) and unzip in a local directory. Build using `clang` as follows: 

```bash
clang -c -O[0,1,2,3] sqlite3.c -o sqlite3-O[1,2,3].o
```
