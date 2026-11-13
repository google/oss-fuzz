#lang racket/base
;; Fuzz entry points for Racket CS.
;;
;; Each `fuzz-*` function takes the fuzzer's input as a byte string
;; and returns 0 for every expected outcome, or for a bug either 1 or
;; a string that describes it (see `bug-signature`). It never
;; raises: the C driver calls it through `racket_apply`, which has no
;; exception handling.
;;
;; Untrusted code runs only inside `run-limited`, which gives it:
;;  - a fresh namespace and a weak code inspector, so protected modules
;;    (`#%unsafe`, `#%foreign`, `#%linklet`, `ffi/unsafe/vm`, ...) and
;;    `(#%declare #:unsafe)` are unavailable;
;;  - a security guard that permits only reading installed libraries;
;;  - a custodian with a memory limit;
;;  - a fuel limit counted in scheduler quanta, so every run halts
;;    without depending on the clock;
;;  - bounded output and no exit.

(require setup/dirs
         "libs.rkt"
         racket/string
         racket/fasl
         racket/extflonum
         (only-in ffi/unsafe/vm vm-eval))

(provide fuzz-read
         fuzz-eval
         fuzz-print-roundtrip
         fuzz-number
         fuzz-regexp
         fuzz-fasl
         fuzz-heap-eval
         run-limited
         bug-exn?
         fuzz-debug-port)

;; ----------------------------------------
;; Limits

(define memory-limit (* 64 1024 1024))
(define fuel-quanta 400)       ; scheduler quanta for untrusted code
(define output-limit (* 64 1024))
(define max-forms 256)

;; ----------------------------------------
;; Oracles

;; An entry point returns 0 when every property holds, and otherwise
;; the number of the property that failed; "driver.c" has a check for
;; each number, so keep the two in sync
(define failed-print-roundtrip 1)
(define failed-exact-number-roundtrip 2)
(define failed-inexact-number-roundtrip 3)
(define failed-regexp-match-positions 4)
(define failed-fasl-roundtrip 5)
(define failed-fasl-raise 6)
(define failed-heap-check 7)

;; When a port, every exception caught from untrusted code is written
;; there; used to check the harness by hand, never while fuzzing.
;; Setting PLT_FUZZ_DEBUG turns it on for the current error port.
(define fuzz-debug-port
  (make-parameter (and (getenv "PLT_FUZZ_DEBUG") (current-error-port))))

(define (note-exn e)
  (define p (fuzz-debug-port))
  (when p
    (fprintf p "  caught: ~a\n" (if (exn? e) (exn-message e) e))))

;; Chez reports a fault inside Scheme code as this exception, so a
;; memory-safety bug can look like an ordinary error.
(define (bug-exn? e)
  (and (exn? e)
       (let ([msg (exn-message e)])
         (or (string-contains? msg "invalid memory reference")
             (string-prefix? msg "internal error")))))

;; A bug's message goes to the original error port, whatever untrusted
;; code did to its own, so that a crash report says what went wrong;
;; for a memory fault, Chez may say where.
(define bug-port (current-error-port))

(define (report-bug e)
  (define ctx (continuation-mark-set->context (exn-continuation-marks e)))
  (fprintf bug-port "fuzz bug: ~a\n" (exn-message e))
  (for ([c (in-list ctx)]
        [i (in-range 20)])
    (fprintf bug-port "  ~a~a\n"
             (or (car c) "???")
             (if (cdr c)
                 (format " at ~a:~a" (srcloc-source (cdr c)) (srcloc-line (cdr c)))
                 "")))
  (flush-output bug-port)
  (bug-signature e ctx))

;; A short description of a bug that is the same for every input that
;; triggers it, which the driver reports as a failed assertion, so
;; that a fuzzing service, which groups crashes by the assertion
;; message and the stack, can tell bugs apart even though they all
;; end in the same C function. It names the kind of error and the
;; innermost few procedures of Racket and Chez Scheme where it
;; happened, leaving out the fuzzed program's own procedures and
;; anything that can vary between runs, such as addresses.
(define (bug-signature e ctx)
  (define msg (exn-message e))
  (define kind
    (if (string-contains? msg "invalid memory reference")
        "invalid memory reference"
        (let* ([s (car (string-split (string-append msg "\n") "\n" #:trim? #f))]
               [s (regexp-replace* #rx"0x[0-9a-fA-F]+|[0-9]+" s "N")])
          (if (> (string-length s) 80) (substring s 0 80) s))))
  (define names
    (for/list ([c (in-list ctx)]
               #:when (car c)
               #:unless (and (cdr c) (eq? (srcloc-source (cdr c)) 'fuzz)))
      (symbol->string (car c))))
  (define where
    (let loop ([names names] [n 3])
      (if (or (null? names) (zero? n))
          '()
          (cons (car names) (loop (cdr names) (sub1 n))))))
  (if (null? where)
      kind
      (string-append kind " in " (string-join where " < "))))

;; ----------------------------------------
;; Security guard: read-only access to installed libraries

(define allowed-roots
  (for/list ([d (in-list (append (list (find-collects-dir)
                                       (find-pkgs-dir)
                                       (find-share-dir)
                                       (find-lib-dir)
                                       (find-config-dir)
                                       (find-system-path 'addon-dir))
                                 (get-collects-search-dirs)))]
             #:when d)
    (path->string (simplify-path (path->complete-path d) #f))))

;; `simplify-path` without filesystem access, so the guard does not
;; call itself.
(define (allowed-path? p)
  (define s (path->string (simplify-path (path->complete-path p) #f)))
  (for/or ([r (in-list allowed-roots)])
    (string-prefix? s r)))

(define (deny who what)
  (raise (exn:fail (format "~a: ~a denied in fuzz evaluator" who what)
                   (current-continuation-marks))))

(define fuzz-guard
  (make-security-guard
   (current-security-guard)
   (lambda (who path modes)
     ;; Existence checks are harmless and the module name resolver
     ;; makes them everywhere; reading is limited to the libraries.
     (when path
       (unless (or (equal? modes '(exists))
                   (and (null? (remq* '(read exists) modes))
                        (allowed-path? path)))
         (deny who "file access"))))
   (lambda (who host port mode) (deny who "network access"))
   (lambda (who path target) (deny who "link creation"))))

;; ----------------------------------------
;; Output that keeps at most `output-limit` bytes and drops the rest

(define (make-bounded-output-port)
  (define count 0)
  (make-output-port
   'fuzz-output
   always-evt
   (lambda (bstr start end non-block? breakable?)
     (set! count (min output-limit (+ count (- end start))))
     (- end start))
   void))

;; ----------------------------------------
;; Namespaces

(define-namespace-anchor anchor)
(define harness-ns (namespace-anchor->namespace anchor))
(define orig-code-inspector (current-code-inspector))

;; The libraries in `fuzz-libs` are loaded once, here, with the
;; original inspector. Each fuzz namespace gets their declarations,
;; but makes its own instances, so no state is shared between runs.
(define attached-libs (append fuzz-libs fuzz-lazy-libs))
(define preloaded-libs (cons 'racket/base attached-libs))
;; Names that the module name resolver produced while preloading;
;; see `make-fuzz-namespace`.
(define preload-resolved-names (make-hash))
(parameterize ([current-namespace harness-ns]
               [current-module-name-resolver
                (let ([orig (current-module-name-resolver)])
                  (case-lambda
                    [(r ns) (orig r ns)]
                    [(name rel-to stx load?)
                     (define r (orig name rel-to stx load?))
                     (hash-set! preload-resolved-names r #t)
                     r]))])
  (for ([l (in-list attached-libs)])
    (dynamic-require l (void))))
(define preloaded-names
  (parameterize ([current-namespace harness-ns])
    (for/hash ([l (in-list preloaded-libs)])
      (values l ((current-module-name-resolver) l #f #f #f)))))

;; Must be called with the weak code inspector installed, so that the
;; new namespace (and code compiled in it) is under that inspector.
(define (make-fuzz-namespace)
  (define ns (make-empty-namespace))
  (namespace-attach-module harness-ns 'racket/base ns)
  (for ([l (in-list attached-libs)])
    (namespace-attach-module-declaration harness-ns l ns))
  (parameterize ([current-namespace ns])
    ;; In a target with embedded modules, the resolver knows how to
    ;; resolve relative paths from an embedded module only in a
    ;; registry that it has been told about, and attaching tells it
    ;; about only some modules, not including the submodules that
    ;; `lazy-require` creates; then a relative path from one of those
    ;; resolves against the current directory. So tell it about every
    ;; module that the harness resolved.
    (for ([r (in-hash-keys preload-resolved-names)])
      ((current-module-name-resolver) r harness-ns))
    (namespace-require 'racket/base)
    ;; A major collection can take most of a second in a sanitized
    ;; build, and fuel does not count time spent in the collector, so
    ;; `collect-garbage` at the top level only requests a minor one
    (namespace-set-variable-value! 'collect-garbage
                                   (lambda ([request 'major])
                                     (collect-garbage 'minor))
                                   #t))
  ns)

;; A preloaded library resolves to the name it has in the harness. That
;; matters in a fuzz target with embedded modules, where only the
;; harness's registry knows the embedded names. Other module paths,
;; such as a module that the fuzzed program declares, are resolved as
;; usual.
(define (make-fuzz-resolver orig-resolver)
  (case-lambda
    [(r ns) (orig-resolver r ns)]
    [(name rel-to stx load?)
     (define r (hash-ref preloaded-names name #f))
     ;; a namespace that the program makes, such as with
     ;; `make-base-namespace`, may not have the declaration
     (if (and r (module-declared? r #f))
         r
         (orig-resolver name rel-to stx load?))]))

;; Installed libraries are loaded with the original inspector, as
;; `racket/sandbox` does; nothing else may be loaded as compiled code.
(define (make-load/use-compiled orig-handler)
  (lambda (path modname)
    (if (allowed-path? path)
        (parameterize ([current-code-inspector orig-code-inspector]
                       [current-security-guard (current-security-guard)])
          (orig-handler path modname))
        (deny 'load "loading code"))))

;; ----------------------------------------
;; Running untrusted work

;; Runs `thunk` (a procedure of no arguments that returns 0 or 1) under
;; the limits described at the top. Returns what `thunk` returns, or
;; a bug's description.
(define (run-limited thunk)
  (define cust (make-custodian))
  (custodian-limit-memory cust memory-limit cust)
  (define result 0)
  (define out (make-bounded-output-port))
  (define th
    (parameterize ([current-custodian cust]
                   [current-code-inspector (make-inspector orig-code-inspector)]
                   [current-inspector (make-inspector (current-inspector))]
                   [current-security-guard fuzz-guard]
                   [current-load/use-compiled
                    (make-load/use-compiled (current-load/use-compiled))]
                   [current-module-name-resolver
                    (make-fuzz-resolver (current-module-name-resolver))]
                   [current-environment-variables (make-environment-variables)]
                   [current-command-line-arguments (vector)]
                   ;; the initial generator is seeded from the clock
                   [current-pseudo-random-generator
                    (vector->pseudo-random-generator '#(1 2 3 4 5 6))]
                   [current-input-port (open-input-bytes #"")]
                   [current-output-port out]
                   [current-error-port out]
                   [read-accept-reader #f]
                   [read-accept-lang #f]
                   [read-accept-compiled #f])
      (parameterize ([current-namespace (make-fuzz-namespace)])
        (thread
         (lambda ()
           (let/ec esc
             (parameterize ([exit-handler (lambda (v) (esc (void)))])
               (with-handlers ([(lambda (e) #t)
                                (lambda (e)
                                  (note-exn e)
                                  (when (bug-exn? e)
                                    (set! result (report-bug e))))])
                 (set! result (thunk))))))))))
  ;; Watchdog: each `(sleep 0)` lets the other threads run for up to
  ;; one quantum, so this loop bounds the work they can do. It also
  ;; checks total memory use, which is cheap, since the custodian's
  ;; limit is enforced only at a major collection, and allocation is
  ;; fast enough to reach the fuzzer's RSS limit before then.
  (define base-memory (current-memory-use))
  (let loop ([n 0])
    (cond
      [(thread-dead? th) (void)]
      [(>= n fuel-quanta) (note-exn "out of fuel")]
      [(> (- (current-memory-use) base-memory) memory-limit)
       (note-exn "out of memory")]
      [else (sleep 0) (loop (add1 n))]))
  (custodian-shutdown-all cust)
  result)

;; Wraps an entry point so that nothing escapes to C.
(define-syntax-rule (define-entry (name bstr) body ...)
  (define (name bstr)
    (with-handlers ([(lambda (e) #t)
                     (lambda (e)
                       (cond
                         [(bug-exn? e) (report-bug e)]
                         [else 0]))])
      body ...)))

;; ----------------------------------------
;; Reading forms

(define (read-forms in)
  (port-count-lines! in)
  (let loop ([acc '()] [n 0])
    (define v (read-syntax 'fuzz in))
    (if (or (eof-object? v) (= n max-forms))
        (reverse acc)
        (loop (cons v acc) (add1 n)))))

;; ----------------------------------------
;; Targets

;; Reader only.
(define-entry (fuzz-read bstr)
  (run-limited
   (lambda ()
     (read-forms (open-input-bytes bstr))
     0)))

;; Expand, compile and run each top-level form.
(define-entry (fuzz-eval bstr)
  (run-limited
   (lambda ()
     (for ([form (in-list (read-forms (open-input-bytes bstr)))])
       (with-handlers ([(lambda (e) (not (bug-exn? e))) note-exn])
         (eval (namespace-syntax-introduce form))))
     0)))

;; Like `fuzz-eval`, then has Chez Scheme check the whole heap for
;; consistency during a collection, which catches corruption that does
;; not happen to cause a fault. It is a separate target because of the
;; cost of the check.
(define enable-check-heap (vm-eval '($primitive $enable-check-heap)))
(define check-heap-errors (vm-eval '($primitive $check-heap-errors)))

;; A heap check takes up to a second, so check after the first input,
;; which is the only one when a crash is reproduced, and then after
;; every `heap-check-interval`th input
(define heap-check-interval 32)
(define heap-eval-count 0)

(define-entry (fuzz-heap-eval bstr)
  (define r (fuzz-eval bstr))
  (set! heap-eval-count (add1 heap-eval-count))
  (cond
    [(and (eqv? r 0)
          (eqv? 1 (modulo heap-eval-count heap-check-interval)))
     (define before (check-heap-errors))
     (enable-check-heap #t)
     (collect-garbage 'minor)
     (enable-check-heap #f)
     (define n (- (check-heap-errors) before))
     (if (zero? n)
         0
         (begin
           (fprintf bug-port "fuzz bug: heap check found ~a errors\n" n)
           (flush-output bug-port)
           failed-heap-check))]
    [else r]))

;; Readable data must read back as itself after `write`.
(define-entry (fuzz-print-roundtrip bstr)
  (run-limited
   (lambda ()
     (for/fold ([r 0]) ([stx (in-list (read-forms (open-input-bytes bstr)))])
       (define v (syntax->datum stx))
       (define s (let ([o (open-output-bytes)]) (write v o) (get-output-bytes o)))
       ;; `read-syntax`, like the first read, so strings are immutable
       ;; on both sides (`read` makes mutable strings, which
       ;; `equal-always?` hash tables compare by identity).
       (define v2 (syntax->datum (read-syntax 'fuzz (open-input-bytes s))))
       (if (or (equal? v v2) (has-unreadable? v))
           r
           failed-print-roundtrip)))))

;; Values whose printed form is not expected to read back as `equal?`.
(define (has-unreadable? v)
  (let loop ([v v])
    (cond
      [(pair? v) (or (loop (car v)) (loop (cdr v)))]
      [(vector? v) (for/or ([x (in-vector v)]) (loop x))]
      [(box? v) (loop (unbox v))]
      [(hash? v) (or (and (not (hash-equal? v))
                          (for/or ([k (in-hash-keys v)]) (not (eq-preserved? k))))
                     (for/or ([(k x) (in-hash v)]) (or (loop k) (loop x))))]
      [(prefab-struct-key v) (for/or ([x (in-vector (struct->vector v))]) (loop x))]
      [(symbol? v) (not (symbol-interned? v))]
      ;; +nan.0 is not `equal?` to itself in every representation
      [(and (flonum? v) (not (= v v))) #t]
      ;; Racket CS has no extflonum arithmetic; extflonums read back
      ;; as fresh, non-`equal?` values
      [(extflonum? v) #t]
      [else #f])))

;; Values that read back as themselves by `eq?`; other keys of an `eq?`,
;; `eqv?` or `equal-always?` table read back as fresh, different keys
(define (eq-preserved? v)
  (or (fixnum? v) (char? v) (boolean? v) (null? v) (void? v) (eof-object? v)
      (keyword? v) (and (symbol? v) (symbol-interned? v))))

;; A numeric literal must survive number->string and string->number.
(define-entry (fuzz-number bstr)
  (run-limited
   (lambda ()
     (define s (bytes->string/utf-8 bstr #\?))
     (define n (string->number s 10 'number-or-false 'decimal-as-exact))
     (cond
       [(and n (exact? n))
        (define s2 (number->string n))
        (if (equal? (string->number s2) n) 0 failed-exact-number-roundtrip)]
       [(and n (real? n) (= n n))
        (define s2 (number->string n))
        (if (eqv? (string->number s2) n) 0 failed-inexact-number-roundtrip)]
       [else 0]))))

;; The input is a pattern and a subject separated by the first NUL byte.
(define-entry (fuzz-regexp bstr)
  (run-limited
   (lambda ()
     (define parts (regexp-split #rx#"\0" bstr))
     (define pat (car parts))
     (define subject (if (null? (cdr parts)) #"" (cadr parts)))
     (define rx (with-handlers ([bug-exn? raise]
                                [exn:fail? (lambda (e) #f)])
                  (byte-pregexp pat)))
     (cond
       [rx
        (define m (regexp-match rx subject))
        (define p (regexp-match-positions rx subject))
        ;; The two must agree on whether, and where, there is a match.
        (cond
          [(and (not m) (not p)) 0]
          [(and m p
                (= (length m) (length p))
                (for/and ([s (in-list m)] [pos (in-list p)])
                  (if s
                      (and pos (equal? s (subbytes subject (car pos) (cdr pos))))
                      (not pos))))
           0]
          [else failed-regexp-match-positions])]
       [else 0]))))

;; `racket/fasl` is implemented in Racket; decoding must not fail
;; except with `exn:fail`, and a decoded value must re-encode to an
;; equal value.
(define bad-raise (string->uninterned-symbol "bad-raise"))

(define-entry (fuzz-fasl bstr)
  (run-limited
   (lambda ()
     (define v (with-handlers ([bug-exn? raise]
                               [exn:fail? (lambda (e) (void))]
                               [(lambda (e) #t) (lambda (e) (note-exn e) bad-raise)])
                 (fasl->s-exp bstr #:datum-intern? #f)))
     (cond
       [(void? v) 0]
       [(eq? v bad-raise) failed-fasl-raise]
       [else
        ;; mutable values stay mutable, since a mutable hash table is
        ;; not `equal?` to an immutable one
        (define v2 (fasl->s-exp (s-exp->fasl v #:keep-mutable? #t) #:datum-intern? #f))
        (if (or (equal? v v2) (has-unreadable? v)) 0 failed-fasl-roundtrip)]))))
