# How to run dextool

This requires `bear` to be installed and `$DEXTOOL_INSTALL` to be set to where
dextool is installed.

```
./autogen.sh
LDFLAGS="-L$DEXTOOL_INSTALL/lib -Wl,--whole-archive -ldextool_coverage_runtime -ldextool_schema_runtime -Wl,--no-whole-archive" ./configure

bear -- make check

dextool mutate analyze
dextool mutate test
```

# Background

I saw a comment about [secp256k1 on hackernews regarding mutation
testing](https://news.ycombinator.com/item?id=26024915) and got curious if it
would be possible to run dextool.

```
nullc 3 months ago [–]

I've deployed mutation testing extensively in libsecp256k1 for the past five
years or so, to good ends.

Though it's turned up some testing inadequacies here and there and a
substantial performance improvement (https://twitter.com/pwuille/status/1348835954396516353 ),
I don't believe it's yet caught a bug there, but I do feel a lot more confident
in the tests as a result.

I've also deployed it to a lesser degree in the Bitcoin codebase and turned up
some minor bugs as a result of the tests being improved to pass mutation
testing.

The biggest challenge I've seen for most parties to use mutation testing is
that to begin with you must have 100% branch coverage of the code you might
mutate, and very few ordinary pieces of software reach that level of coverage.

The next issue is that in C/C++ there really aren't any great tools that I'm
aware of-- so every effort needs to be homebrewed.

My process is to have some a harness script that:

1. makes a modification (e.g. a python script that does small search and
   replacements one at a time line by line, or just doing it by hand).
2. attempts to compile the code (if it fails, move on to the next change)
3. Compares the hash of the optimized binary to a collection of already tested
   hashes and moves onto the next if it's already been seen.
4. Runs the tests and if the tests pass save off the diff.
5. Goto 1.

Then I go back trough the diffs and toss ones that are obviously no meaningful
effect, and lob the remaining diffs over to other contributors to figure out if
they're false positives or to improve the tests.
```
