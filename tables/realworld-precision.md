| project | tool | in_scope_keys | TP | FP | uncertain | unlabeled | precision_% | label_coverage_% | known_TP_in_labels | label_lookup |
|---|---|---|---|---|---|---|---|---|---|---|
| libcrc | aurora-lint | 266 | 12 | 252 | 0 | 2 | 4.5 | 99.2 | 16 | direct |
| libcrc | clang-tidy | 2 | 1 | 0 | 0 | 1 | 100.0 | 50.0 | 16 | via mapping |
| libcrc | cppcheck | 19 | 0 | 0 | 0 | 19 |  | 0.0 | 16 | via mapping |
| lua | aurora-lint | 3582 | 1432 | 2149 | 0 | 1 | 40.0 | 100.0 | 1449 | direct |
| lua | clang-tidy | 106 | 5 | 10 | 0 | 91 | 33.3 | 14.2 | 1449 | via mapping |
| lua | cppcheck | 161 | 0 | 5 | 0 | 156 | 0.0 | 3.1 | 1449 | via mapping |

_tool_comparison_benchmarks 8fa3afa36d0c; aurora-lint 92eae76c2326_  
_tools: aurora-lint 0.5.2; clang-tidy 21.1.8; cppcheck 2.13.0_  
_corpus pins: 1e02f4f86bc7 (benchmark_repos.json at aurora-lint 92eae76c2326); juliet f88433e34436_  
_labels: benchmark_adjudication d5a09bca4f53_  
_mapping: clang-tidy.json 40a814df673e; cppcheck.json e03cd9b06282; aurora-lint:data/rule_cwe_map.json ee91690bfe4d_  
_environment: 12th Gen Intel(R) Core(TM) i5-12400, Ubuntu 24.04.5 LTS, glibc 2.39, dev-packages 91d70318a047_  
