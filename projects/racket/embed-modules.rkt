#lang racket/base
;; Writes the compiled code of "safe-eval.rkt" and of the libraries
;; that fuzzed programs may use, as one module bundle that the driver
;; loads with `racket_embedded_load_bytes`, so that a fuzz target needs
;; no files at run time.
;;
;;   racket embed-modules.rkt <dest>
;;
;; Run it with the Racket CS that the fuzz targets link against, so
;; that the machine code matches.

(require racket/cmdline
         racket/runtime-path
         compiler/embed)

(define-runtime-path safe-eval "safe-eval.rkt")
(require "libs.rkt")

(define dest
  (command-line #:args (dest) dest))

(call-with-output-file dest
  #:exists 'truncate
  (lambda (o)
    (parameterize ([current-output-port o])
      (write-module-bundle
       ;; the prefix makes "safe-eval.rkt" available as 'fuzz:safe-eval
       #:modules (append (list (list 'fuzz: (list 'file (path->string safe-eval)))
                               ;; libraries stay reachable through their
                               ;; collection paths; a #f prefix would
                               ;; instead declare `racket/base` as 'base
                               (list #t 'racket/base))
                         (for/list ([l (in-list (append fuzz-libs fuzz-lazy-libs))])
                           (list #t l)))))))
