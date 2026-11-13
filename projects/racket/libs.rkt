#lang racket/base
;; Libraries that fuzzed programs may `require`, besides `racket/base`.
;; They are preloaded by "safe-eval.rkt" and embedded by
;; "embed-modules.rkt".

(provide fuzz-libs
         fuzz-lazy-libs)

(define fuzz-libs
  '(racket/list racket/string racket/math racket/vector racket/match
    racket/set racket/hash racket/function racket/bool racket/format
    racket/flonum racket/fixnum racket/extflonum racket/stream
    racket/sequence racket/generator racket/port racket/symbol
    racket/keyword racket/fasl racket/contract/base))

;; Modules that those libraries load lazily, which an embedding process
;; would not find as dependencies
(define fuzz-lazy-libs
  '(racket/match/gen-match racket/match/parse racket/match/patterns
    racket/runtime-config))
