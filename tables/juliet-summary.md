| tool | cwe_set | cwes | files | flaw_lines | findings | in_bad | in_good | precision_all_% | cwe_matched_bad | cwe_matched_good | precision_cwe_% | flaw_lines_hit | flaw_hit_% |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| aurora-lint | all-covered | 17 | 30484 | 41580 | 16585 | 13652 | 2933 | 82.3 | 13652 | 2933 | 82.3 | 10328 | 24.8 |
| aurora-lint | common | 17 | 30484 | 41580 | 16585 | 13652 | 2933 | 82.3 | 13652 | 2933 | 82.3 | 10328 | 24.8 |
| aurora-lint-full | all-covered | 17 | 30484 | 41580 | 324930 | 131891 | 193039 | 40.6 | 13652 | 2933 | 82.3 | 10328 | 24.8 |
| aurora-lint-full | common | 17 | 30484 | 41580 | 324930 | 131891 | 193039 | 40.6 | 13652 | 2933 | 82.3 | 10328 | 24.8 |
| clang-tidy | all-covered | 17 | 30484 | 41580 | 71000 | 28384 | 42616 | 40.0 | 864 | 349 | 71.2 | 480 | 1.2 |
| clang-tidy | common | 17 | 30484 | 41580 | 71000 | 28384 | 42616 | 40.0 | 864 | 349 | 71.2 | 480 | 1.2 |
| cppcheck | all-covered | 17 | 30484 | 41580 | 102995 | 37544 | 65451 | 36.5 | 1049 | 364 | 74.2 | 510 | 1.2 |
| cppcheck | common | 17 | 30484 | 41580 | 102995 | 37544 | 65451 | 36.5 | 1049 | 364 | 74.2 | 510 | 1.2 |

_tool_comparison_benchmarks 8fa3afa36d0c; aurora-lint 92eae76c2326_  
_tools: aurora-lint 0.5.2; aurora-lint-full 0.5.2; clang-tidy 21.1.8; cppcheck 2.13.0_  
_corpus pins: 1e02f4f86bc7 (benchmark_repos.json at aurora-lint 92eae76c2326); juliet f88433e34436_  
_labels: benchmark_adjudication d5a09bca4f53_  
_mapping: clang-tidy.json 40a814df673e; cppcheck.json e03cd9b06282; aurora-lint:data/rule_cwe_map.json ee91690bfe4d_  
_environment: 12th Gen Intel(R) Core(TM) i5-12400, Ubuntu 24.04.5 LTS, glibc 2.39, dev-packages 91d70318a047_  
_common CWE set: CWE121, CWE122, CWE124, CWE126, CWE127, CWE190, CWE191, CWE197, CWE369, CWE401, CWE415, CWE416, CWE457, CWE476, CWE680, CWE690, CWE761_  
