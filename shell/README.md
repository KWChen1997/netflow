# Netflow
## Part 1: filter.awk
- Extract information from conntrack raw data
## Part 2: netflow
- Use filter.awk to extract information and sort the output
## Output
- The top 5 ip address with the most packet exchange numbers(both directions)
## How to use
```sh=
./netflow [options]
```
- the option is same as conntrack
- `-z` option will reset the counter
- No need to set -L option since it's already in use
