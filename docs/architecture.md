# Architecture

_This document will describe the architecture of the elastic-lolbin-detection-pack._ 

## Sigma Rule Conversion

Sigma rules in `rules/` are converted to Elasticsearch Query DSL using `sigmac` (version 0.12.2). Converted rules are stored in `rules/es/` for use in automated detection and testing. 