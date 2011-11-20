#lang racket/base
(require (for-syntax racket/base)
         racket/list
         racket/class
         (only-in openssl/sha1 bytes->hex-string))

(provide sendp
         recvp
         recv+
         recv++
         recv/assert
         recv/in
         recv/pkt/in
         ->bytes
         ->sbytes
         build-ssh-bytes
         build-ssh-bool
         ->int32 
         ->sshb
         read-ssh-uint32
         read-ssh-string
         read-ssh-bool
         random-bytes
         bytes-join
         parse
         parse/bs
         unparse
         hex-bytes->bytes
         bytes->hex-string)

(define (say x) (printf "~a~n" x) x)

(define (sendp io type . others)
;  (printf "DATAOUT~a\n" (bytes->hex-string (apply bytes-append (bytes type) (map ->sbytes others))))
  (send io send-packet (apply bytes-append
    (bytes type)
    (map ->sbytes others))))

(define (assert/equal? a b)
  (unless (equal? a b) 
    (displayln (bytes->hex-string a))
    (displayln (bytes->hex-string b))
    (error 'assert/equal? "X~aX doesn't match X~aX" a b)))

(define (recv/assert io type . others)
  (define pkt (send io recv-packet))
  (define in (open-input-bytes pkt))
  (assert/equal? type (read-byte in))
  (for ([x others])
    (cond [(string? x)  (assert/equal? (->bytes x) (read-ssh-string in))]
          [(bytes? x)   (assert/equal? x (read-ssh-string in))]
          [(integer? x) (assert/equal? x (read-ssh-uint32 in))]
          [(boolean? x) (assert/equal? x (read-ssh-bool in))])))

(define (parse in pat . lst)
  (apply values (append (for/list ([x (in-string pat)])
    (cond
     [(equal? x #\b) (read-byte in)]
     [(equal? x #\s) (read-ssh-string in)]
     [(equal? x #\X) (read-ssh-string-raw in)]
     [(equal? x #\i) (read-ssh-uint32 in)]
     [(equal? x #\B) (read-ssh-bool in)]
     [else (say x)])) lst)))

(define (unparse pat . lst)
  (define out (open-output-bytes))
  (for/list ([x (in-string pat)]
             [y  lst])
    (cond
     [(equal? x #\b) (write-byte y out)]
     [(equal? x #\X) (write-bytes y out)]
     [(equal? x #\s) (write-bytes (->sshbytes y) out)]
     [(equal? x #\i) (write-bytes (->sshbytes y) out)]
     [(equal? x #\B) (write-bytes (->sshbytes y) out)]
     [else (say x)]))
  (get-output-bytes out))

(define (parse/bs str pat) (parse (open-input-bytes str) pat))

(define (recv io pat)
  (define in (open-input-bytes (send io recv-packet)))
  (parse in pat))

(define (recv/in io pat)
  (define in (open-input-bytes (send io recv-packet)))
  (parse in pat in))

(define (recv/pkt/in io type pat)
  (define pkt (send io recv-packet))
  (define in (open-input-bytes pkt))
  (assert/equal? type (read-byte in))
  (parse in pat pkt in))

(define (recvp io type pat)
  (define in (open-input-bytes (send io recv-packet)))
  (assert/equal? type (read-byte in))
  (parse in pat))

(define (recv+ io type pat)
  (define in (open-input-bytes (send io recv-packet)))
  (assert/equal? type (read-byte in))
  (parse in pat in))

(define (recv++ io type pat)
  (define pkt (send io recv-packet))
  (define in (open-input-bytes pkt))
  (assert/equal? type (read-byte in))
  (parse in pat pkt in))

(define (->bytes x)
  (cond [(string? x) (string->bytes/locale x)]
        [(bytes? x) x]
        [(integer? x) (integer->integer-bytes x 4 #f #t)]
        [(boolean? x) (if x (bytes 1) (bytes 0))]
        [else (error 'bytes "~a" x)]))

(define (->sbytes x)
  (cond [(string? x) (build-ssh-bytes (string->bytes/locale x))]
        [else (->bytes x)]))

(define (->sshbytes x)
  (cond [(bytes? x) (build-ssh-bytes x)]
        [else (->sbytes x)]))

(define (->sshb . lst)
  (for/fold ([r #""]) ([x lst])
    (bytes-append r 
      (->sshbytes x))))

(define (build-ssh-bytes data)
  (define byte-data (->bytes data))
  (bytes-append (->bytes (bytes-length byte-data)) byte-data))
(define (build-ssh-bool b) (if b (bytes 1) (bytes 0)))

(define (->int32 x) (integer-bytes->integer x #f #t))

(define (read-ssh-uint32 in) (->int32 (read-bytes 4 in)))
(define (read-ssh-string in) (read-bytes (read-ssh-uint32 in) in))
(define (read-ssh-string-raw in) 
  (define out (open-output-bytes))
  (define lenbytes (read-bytes 4 in))
  (define len (->int32 lenbytes))
  (write-bytes lenbytes out)
  (write-bytes (read-bytes len in) out)
  (get-output-bytes out))

(define (read-ssh-bool in) (if (= 0 (read-byte in)) #f #t))
(define (random-bytes cnt) (apply bytes (for/list ([x (in-range cnt)]) (random 256))))

(define (bytes-join strs sep)
  (cond [(not (and (list? strs) (andmap bytes? strs)))
         (raise-type-error 'bytes-join "list-of-byte-strings" strs)]
        [(not (bytes? sep))
         (raise-type-error 'bytes-join "bytes" sep)]
        [(null? strs) #""]
        [(null? (cdr strs)) (car strs)]
        [else (apply bytes-append (add-between strs sep))]))

(define (hex-bytes->bytes bstr)
  (let* ([len (bytes-length bstr)]
         [bstr2l (/ len 2)]
         [bstr2 (make-bytes bstr2l)]
         [digit
          (lambda (v)
            (if (v . <= . (char->integer #\9))
                (- v (char->integer #\0))
            (if (v . <= . (char->integer #\F))
                (+ (- v (char->integer #\A)) 10)
                (+ (- v (char->integer #\a)) 10))))])
    (for ([i (in-range bstr2l)])
      (let ([c1 (bytes-ref bstr (* 2 i))]
            [c2 (bytes-ref bstr (+ (* 2 i) 1))])
        ;(printf "~a ~a ~a ~a\n" c1 c2 (digit c1) (digit c2))
        (bytes-set! bstr2 i (bitwise-ior (arithmetic-shift (digit c1) 4)
                                         (digit c2)))))
    bstr2))

