#lang racket/base
(require (for-syntax racket/base)
         racket/list
         racket/class
         (only-in openssl/sha1 bytes->hex-string))

(provide sendp
         recvp
         recv/assert
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
         parse)

(define (say x) (printf "~a~n" x) x)

(define (sendp io type . others)
  (send io send-packet (apply bytes-append
    (bytes type)
    (map ->sbytes others))))

(define (recv/assert io type . others)
  (define (assert/equal? a b)
    (unless (equal? a b) (error 'assert/equal? "X~aX doesn't match X~aX" a b)))
  (define pkt (send io recv-packet))
  (define in (open-input-bytes pkt))
  (assert/equal? type (read-byte in))
  (for ([x others])
    (cond [(string? x)  (assert/equal? (->bytes x) (read-ssh-string in))]
          [(bytes? x)   (assert/equal? x (read-ssh-string in))]
          [(integer? x) (assert/equal? x (read-ssh-uint32 in))]
          [(boolean? x) (assert/equal? x (read-ssh-bool in))])))

(define (parse in pat)
  (apply values (for/list ([x (in-string pat)])
    (cond
     [(equal? x #\b) (read-byte in)]
     [(equal? x #\s) (read-ssh-string in)]
     [(equal? x #\i) (read-ssh-uint32 in)]
     [(equal? x #\B) (read-ssh-bool in)]
     [else (say x)]))))

(define (recvp io pat)
  (define in (open-input-bytes (send io recv-packet)))
  (parse io pat))

(define (->bytes x)
  (cond [(string? x) (string->bytes/locale x)]
        [(bytes? x) x]
        [(integer? x) (integer->integer-bytes x 4 #f #t)]
        [(boolean? x) (if x (bytes 1) (bytes 0))]
        [else (error 'bytes "~a" x)]))

(define (->sbytes x)
  (cond [(string? x) (build-ssh-bytes (string->bytes/locale x))]
        [else (->bytes x)]))

(define (->sshb . lst)
  (for/fold ([r #""]) ([x lst])
    (bytes-append r 
      (cond [(bytes? x) (build-ssh-bytes x)]
            [else (->sbytes x)]))))

(define (build-ssh-bytes data)
  (define byte-data (->bytes data))
  (bytes-append (->bytes (bytes-length byte-data)) byte-data))
(define (build-ssh-bool b) (if b (bytes 1) (bytes 0)))

(define (->int32 x) (integer-bytes->integer x #f #t))

(define (read-ssh-uint32 in) (->int32 (read-bytes 4 in)))
(define (read-ssh-string in) (read-bytes (read-ssh-uint32 in) in))
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

