# About

This is a demonstration of using [dextool mutate](https://github.com/joakim-brannstrom/dextool/tree/master/plugin/mutate) on open source projects.

The intention is to demonstrate that the tool is usable on a wide range of open
source projects in practise and to serve as example of how to use it to others.
I hope it will help you, as a reader, to get started.

## [GoogleTest](https://github.com/joakim-brannstrom/dextool_mutate_demo/tree/googletest)

Googletest is a nice candidate to show the tool because of the extensive test
suite together with the tools builtin googletest test case parser. The parser
mean that when a mutant is killed it is assigned to one or more test cases.
This tracking thus allow the tool to score the tests, find those that kill zero
mutants, *know* when mutants need to be re-tested because tests have changed
etc.

Unfortantly, as with all mutation testing, it can take a while to run the tool.
Googletest exhibit the classic C++ tendencies of a long compilation time for a
minor change to a header. If you want a quick overview I recommend running with
the flag `--schema-only`.
