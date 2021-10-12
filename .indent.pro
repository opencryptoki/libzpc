// *** libzpc indent options ***
//
// To use the indent tool with the specified options, copy this file to your
// home directory or set the INDENT_PROFILE environment variable's value to
// name this file e.g., do
//
//     export INDENT_PROFILE=`pwd`/.indent.pro
//
// from the root of the source tree.
//
// See indent(1).


// *** INVOKIND INDENT ***

//--standard-output
//--ignore-profile


// *** COMMON STYLES ***

// We use none of them.
//--gnu-style
//--k-and-r-style
//--original
//--linux


// *** BLANK LINES ***

//--blank-lines-after-declarations
--no-blank-lines-after-declarations

--blank-lines-after-procedures
//--no-blank-lines-after-procedures

// Puts blank line before header.
//--blank-lines-before-block-comments
--no-blank-lines-before-block-comments

--swallow-optional-blank-lines
//--leave-optional-blank-lines


// *** COMMENTS ***

// Set in BLANK LINES section.
//--blank-lines-before-block-comments
//--no-blank-lines-before-block-comments

--format-all-comments
//--dont-format-comments

// Puts a trailing space after /*
//--format-first-column-comments
--dont-format-first-column-comments

--comment-line-length80

//--fix-nested-comments

--line-comments-indentation0

--comment-indentation0

--declaration-comment-column0

--else-endif-column0

--left-justify-declarations
//--dont-left-justify-declarations

//--dont-tab-align-comments

//--comment-delimiters-on-blank-lines
--no-comment-delimiters-on-blank-lines

--start-left-side-of-comments
//--dont-star-comments


// *** STATEMENTS ***

--braces-on-if-line
//--braces-after-if-line

//--brace-indent0

--cuddle-else
//--dont-cuddle-else

--cuddle-do-while
//--dont-cuddle-do-while

//--single-line-conditionals

--case-indentation0

--case-brace-indentation0

//--space-special-semicolon
--dont-space-special-semicolon

//--space-after-procedure-calls
--no-space-after-function-call-names

//--space-after-cast
--no-space-after-casts

//--blank-before-sizeof

--space-after-for
//--no-space-after-for

--space-after-if
//--no-space-after-if

--space-after-while
//--no-space-after-while

//--space-after-parentheses
--no-space-after-parentheses

--struct-brace-indentation0


// *** DECLARATIONS ***

--declaration-indentation0

//--blank-lines-after-commas
--no-blank-lines-after-commas

//--break-function-decl-args
--dont-break-function-decl-args

//--break-function-decl-args-end
--dont-break-function-decl-args-end

--procnames-start-lines
//--dont-break-procedure-type

--braces-on-struct-decl-line
//--braces-after-struct-decl-line

//--braces-on-func-def-line
--braces-after-func-def-line

//--spaces-around-initializers


// *** IDENTATION ***

--use-tabs
//--no-tabs

--indent-level8

--continuation-indentation4

//--continue-at-parentheses
--dont-line-up-parentheses

--paren-indentation0

--tab-size8

--align-with-spaces

--parameter-indentation4
//--no-parameter-indentation

// Overridden by --preprocessor-indentationn.
//--leave-preprocessor-space
//-nps

--preprocessor-indentation1

--indent-label0


// *** BREAKING LONG LINES ***

--line-length80

--break-before-boolean-operator
//--break-after-boolean-operator

//--honour-newlines
--ignore-newlines

//--gettext-strings
--no-gettext-strings


// *** MISCELLANEOUS OPTIONS ***

//--verbose
--no-verbosity

//--preserve-mtime
