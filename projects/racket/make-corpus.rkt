#lang racket/base
;; Builds seed corpora from the core test suite.
;;
;;   racket make-corpus.rkt <tests-dir> <out-dir>
;;
;; <tests-dir> is "pkgs/racket-test-core/tests/racket". Writes
;; <out-dir>/{eval,read,number,regexp,fasl}/, one input per file.

(require racket/cmdline
         racket/file
         racket/list
         racket/path
         racket/fasl
         file/sha1)

(define-values (tests-dir out-dir)
  (command-line #:args (tests-dir out-dir) (values tests-dir out-dir)))

(define max-form-bytes 4096)

(define (write-input! kind bstr)
  (define dir (build-path out-dir kind))
  (make-directory* dir)
  (call-with-output-file (build-path dir (sha1 (open-input-bytes bstr)))
    (lambda (o) (write-bytes bstr o))
    #:exists 'truncate))

(define (form->bytes v)
  (define o (open-output-bytes))
  (parameterize ([print-graph #t]) (write v o))
  (get-output-bytes o))

;; Forms that touch files or the test harness's own state are not
;; useful seeds: the evaluator refuses them.
(define (useful-form? v)
  (not (and (pair? v)
            (memq (car v) '(load load-relative require module report-errs
                            test-errs SECTION Section)))))

(define (walk v proc)
  (proc v)
  (cond
    [(pair? v) (walk (car v) proc) (walk (cdr v) proc)]
    [(vector? v) (for ([x (in-vector v)]) (walk x proc))]
    [(box? v) (walk (unbox v) proc)]
    [else (void)]))

(define files
  (for/list ([f (in-directory tests-dir)]
             #:when (member (path-get-extension f) '(#".rktl" #".rkt")))
    f))

(define counts (make-hash))
(define (count! k) (hash-update! counts k add1 0))

(for ([f (in-list files)])
  (with-handlers ([exn:fail? void])
    (define forms
      (parameterize ([read-accept-reader #t]
                     [read-accept-lang #t]
                     [read-accept-compiled #f])
        (call-with-input-file f
          (lambda (in)
            (port-count-lines! in)
            (let loop ([acc '()])
              (define v (with-handlers ([exn:fail? (lambda (e) eof)]) (read in)))
              (if (eof-object? v) (reverse acc) (loop (cons v acc))))))))
    (for ([v (in-list forms)])
      (define bstr (form->bytes v))
      (when (<= (bytes-length bstr) max-form-bytes)
        (write-input! "read" bstr) (count! "read")
        (with-handlers ([exn:fail? void])
          (write-input! "fasl" (s-exp->fasl v)) (count! "fasl"))
        (when (useful-form? v)
          (write-input! "eval" bstr) (count! "eval")))
      (walk v (lambda (x)
                (cond
                  [(number? x)
                   (write-input! "number" (string->bytes/utf-8 (number->string x)))
                   (count! "number")]
                  [(or (regexp? x) (byte-regexp? x))
                   (write-input! "regexp" (if (regexp? x)
                                              (string->bytes/utf-8 (object-name x))
                                              (object-name x)))
                   (count! "regexp")]
                  [else (void)]))))))

(for ([(k n) (in-hash counts)])
  (printf "~a: ~a inputs (before dedup)\n" k n))
