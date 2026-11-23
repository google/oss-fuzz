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
         racket/string
         racket/fasl
         racket/flonum
         racket/fixnum
         file/sha1)

(define-values (tests-dir out-dir)
  (command-line #:args (tests-dir out-dir) (values tests-dir out-dir)))

(define max-form-bytes 4096)

(define counts (make-hash))

(define (write-input! kind bstr)
  (when (<= (bytes-length bstr) max-form-bytes)
    (define dir (build-path out-dir kind))
    (make-directory* dir)
    (hash-update! counts kind add1 0)
    (call-with-output-file (build-path dir (sha1 (open-input-bytes bstr)))
      (lambda (o) (write-bytes bstr o))
      #:exists 'truncate)))

(define (form->bytes v)
  (define o (open-output-bytes))
  (parameterize ([print-graph #t]) (write v o))
  (get-output-bytes o))

(define (forms->bytes vs)
  (apply bytes-append (add-between (map form->bytes vs) #"\n")))

;; Forms that touch files or the test harness's own state are not
;; useful seeds: the evaluator refuses them.
(define (useful-form? v)
  (not (and (pair? v)
            (memq (car v) '(load load-relative require module report-errs
                            test-errs SECTION Section)))))

;; The tests are mostly calls to helpers from "testing.rktl", such as
;; `(test expected proc arg ...)`, which are not defined when a seed
;; runs, so the call fails before doing anything. Replace each one
;; with the expression that it tests.
(define (unwrap-test v)
  (define (unquote-stx e)
    (if (and (pair? e) (memq (car e) '(quote quote-syntax syntax)) (pair? (cdr e)))
        (cadr e)
        e))
  (let loop ([v v])
    (cond
      [(not (list? v)) v]
      [(null? v) v]
      [(memq (car v) '(quote quote-syntax syntax)) v]
      [else
       (define args (map loop (cdr v)))
       (case (car v)
         [(test ctest rtest)
          (cond
            [(= (length args) 2) (cadr args)]
            [(> (length args) 2) (cdr args)]
            [else v])]
         [(err/rt-test err/rt-test/once err/rt-chk-test)
          (if (pair? args) (car args) v)]
         [(syntax-test error-test)
          (if (pair? args) (unquote-stx (car args)) v)]
         [(test-comp)
          (if (>= (length args) 2)
              `(begin ,(unquote-stx (car args)) ,(unquote-stx (cadr args)))
              v)]
         [(arity-test)
          (if (pair? args) `(procedure-arity ,(car args)) v)]
         [(test-values)
          (if (= (length args) 2) `(,(cadr args)) v)]
         [(test-regexp test-regexp-x)
          (if (= (length args) 3) `(regexp-match ,(cadr args) ,(caddr args)) v)]
         [else (cons (car v) args)])])))

(define (walk v proc)
  (proc v)
  (cond
    [(pair? v) (walk (car v) proc) (walk (cdr v) proc)]
    [(vector? v) (for ([x (in-vector v)]) (walk x proc))]
    [(box? v) (walk (unbox v) proc)]
    [else (void)]))

(define (->bytes s) (if (string? s) (string->bytes/utf-8 s) s))

(define regexp-ops
  '(regexp-match regexp-match* regexp-match-positions regexp-match-positions*
    regexp-match? regexp-match-exact? regexp-split regexp-replace regexp-replace*
    regexp-match-peek regexp-match-peek-positions regexp-try-match
    test-regexp test-regexp-x))

;; A pattern, a NUL and a subject, as "fuzz-regexp" expects
(define (regexp-input! pat subject)
  (define p (cond
              [(regexp? pat) (->bytes (object-name pat))]
              [(byte-regexp? pat) (object-name pat)]
              [(or (string? pat) (bytes? pat)) (->bytes pat)]
              [else #f]))
  (when p
    (write-input! "regexp" (if subject (bytes-append p #"\0" (->bytes subject)) p))))

(define (string-or-bytes? v) (or (string? v) (bytes? v)))

(define (seeds-from-datum! v)
  (walk v (lambda (x)
            (cond
              [(number? x)
               (write-input! "number" (string->bytes/utf-8 (number->string x)))]
              [(or (regexp? x) (byte-regexp? x))
               (regexp-input! x #f)]
              [(string? x)
               ;; strings that are numbers, as in "numstrs.rktl"
               (when (and (< (string-length x) 200)
                          (with-handlers ([void (lambda (e) #f)]) (string->number x)))
                 (write-input! "number" (string->bytes/utf-8 x)))]
              [(and (list? x) (pair? x) (memq (car x) regexp-ops))
               ;; a pattern and the first string or bytes after it
               (define args (if (memq (car x) '(test-regexp test-regexp-x)) (cddr x) (cdr x)))
               (define pat (and (pair? args) (car args)))
               (define pat* (cond
                              [(and (pair? pat) (memq (car pat) '(regexp byte-regexp pregexp byte-pregexp))
                                    (pair? (cdr pat)) (string-or-bytes? (cadr pat)))
                               (cadr pat)]
                              [else pat]))
               (define subject (for/first ([a (in-list (if (pair? args) (cdr args) '()))]
                                           #:when (string-or-bytes? a))
                                 a))
               (when (or (regexp? pat*) (byte-regexp? pat*) (string-or-bytes? pat*))
                 (regexp-input! pat* subject))]
              [else (void)]))))

;; Each top-level form of a file, as a datum and the text it was read
;; from, so that "read" seeds keep the original syntax (comments, quote
;; abbreviations, here strings, ...) instead of what `write` prints. For
;; a `#lang` module, the forms are those of its body.
(define (read-file-forms f)
  (define text (file->bytes f))
  (define (source-text s)
    (define pos (syntax-position s))
    (and pos (syntax-span s)
         (subbytes text (sub1 pos) (min (bytes-length text) (+ (sub1 pos) (syntax-span s))))))
  (define (module-body stx)
    (define l (syntax->list stx))
    (define body (and l (= (length l) 4) (syntax->list (list-ref l 3))))
    (if body (cdr body) '()))
  (define in (open-input-bytes text))
  (port-count-lines! in)
  (define stxs
    (parameterize ([read-accept-reader #t]
                   [read-accept-lang #t]
                   [read-accept-compiled #f])
      (let loop ()
        (define stx (with-handlers ([exn:fail? (lambda (e) eof)]) (read-syntax f in)))
        (if (eof-object? stx) '() (cons stx (loop))))))
  (for*/list ([stx (in-list stxs)]
              [s (in-list (if (regexp-match? #rx#"^#lang" text) (module-body stx) (list stx)))])
    (cons (syntax->datum s) (source-text s))))

(define files
  (for/list ([f (in-directory tests-dir)]
             #:when (member (path-get-extension f) '(#".rktl" #".rkt")))
    f))

(for ([f (in-list files)])
  (with-handlers ([exn:fail? void])
    (define forms (read-file-forms f))
    (for ([p (in-list forms)])
      (define v (car p))
      (define text (cdr p))
      (write-input! "read" (form->bytes v))
      (when text (write-input! "read" text))
      (with-handlers ([exn:fail? void])
        (write-input! "fasl" (s-exp->fasl v)))
      (seeds-from-datum! v))
    ;; eval seeds: each form, and runs of consecutive forms, so that
    ;; uses come with the definitions before them
    (define evals (for/list ([p (in-list forms)]
                             #:when (useful-form? (car p)))
                    (unwrap-test (car p))))
    (for ([v (in-list evals)])
      (write-input! "eval" (form->bytes v)))
    (let loop ([vs evals])
      (unless (null? vs)
        (define chunk
          (let grow ([n 2])
            (if (and (<= n (length vs))
                     (<= (bytes-length (forms->bytes (take vs n))) max-form-bytes))
                (grow (add1 n))
                (take vs (min (length vs) (sub1 n))))))
        (when (> (length chunk) 1)
          (write-input! "eval" (forms->bytes chunk)))
        (loop (drop vs (max 1 (length chunk))))))))

;; Values that the tests rarely spell as literals, for the fasl target
(for ([v (in-list
          (list (make-hash '((a . 1) (2 . "b")))
                (make-hasheqv '((1 . 2)))
                (make-weak-hash)
                (hash 'a 1 "b" #"c")
                (hasheq 'x '(1 . 2))
                (hashalw 1.0 2)
                #s(point 1 2)
                (box 1) (box-immutable 'x)
                (vector 1 2.5 'a) (vector-immutable 1)
                (make-flvector 3 1.5) (make-fxvector 3 7)
                (string->path "a/b") (bytes->path #"/x" 'unix) (bytes->path #"c:\\x" 'windows)
                (srcloc "f.rkt" 1 2 3 4)
                #rx"a|b" #px"\\d+" #rx#"x*" #px#"[[:alpha:]]"
                (string->uninterned-symbol "u") (string->unreadable-symbol "r")
                '#:kw #\u3BB (void) eof +inf.0 -nan.0 1/3 1+2i 1.5+2.5i (expt 2 100)
                (mcons 1 2) (string-copy "mutable") (bytes-copy #"mutable")
                (let ([p (list 1 2)]) (list p p))))])
  (with-handlers ([exn:fail? void])
    (write-input! "fasl" (s-exp->fasl v #:keep-mutable? #t))
    (write-input! "fasl" (s-exp->fasl v))))

(for ([(k n) (in-hash counts)])
  (printf "~a: ~a inputs (before dedup)\n" k n))
