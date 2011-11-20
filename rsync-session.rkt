#lang racket/base
(require racket/class
         "utils.rkt"
         "constants.rkt"
         "session.rkt"
         (for-syntax racket/base)
         racket/date)

(provide rsync-session%)

(define XMIT_TOP_DIR             (arithmetic-shift 1 0))
(define XMIT_SAME_MODE           (arithmetic-shift 1 1))
(define XMIT_EXTENDED_FLAGS      (arithmetic-shift 1 2))
(define XMIT_SAME_UID            (arithmetic-shift 1 3))
(define XMIT_SAME_GID            (arithmetic-shift 1 4))
(define XMIT_SAME_NAME           (arithmetic-shift 1 5))
(define XMIT_LONG_NAME           (arithmetic-shift 1 6))
(define XMIT_SAME_TIME           (arithmetic-shift 1 7))
(define XMIT_SAME_RDEV_MAJOR     (arithmetic-shift 1 8))
(define XMIT_HAS_IDEV_DATA       (arithmetic-shift 1 9))
(define XMIT_SAME_DEV            (arithmetic-shift 1 10))
(define XMIT_RDEV_MINOR_IS_SMALL (arithmetic-shift 1 11))
(define PRESERVE_LINKS           (arithmetic-shift 1 0))
(define XMIT_MOD_NSEC            (arithmetic-shift 1 13))

(define (islink? mode)
  (bitwise-and #x1 mode))

(define (vax->uint32 x) (integer-bytes->integer x #f #f))
(define (read-uint32 in) (vax->uint32 (read-bytes 4 in)))
(define (uint32->vax x) (integer->integer-bytes x 4 #f #f))
(define (write-uint32 x out) (write-bytes (uint32->vax x) out))
(define MAXPATHLEN 255)

(define-syntax-rule (let/ccc k body ...)
  (call-with-composable-continuation (lambda (k) body ...)))

(define-syntax (define-flag-pred stx)
  (syntax-case stx ()
    [(_ flag)
    (with-syntax ([name (string->symbol (string-append "is-" (symbol->string (syntax->datum #'flag)) "?"))])
      #'(define (name f) (not (= 0 (bitwise-and f flag)))))]))

(define rsync-session%
  (class session%
  (init-field [upgrade-session #f])
  (field [server #f])
  (field [k (box #f)])
  (field [k2 #f])
  (field [_s #f]
         [_o #f]
         [_i #f]
         [_e #f])
  (inherit-field in)
  (inherit-field io)
  (inherit-field out)
  (define-values (pi po) (make-pipe))
  ;(inherit send-data)

  (define (buffer-has-n n)
    ((pipe-content-length pi) . >= . n))

  (define/public (send-data2 data) 
    (printf "DATAOUT:~a\n" (bytes->hex-string data))
    (sendp io SSH_MSG_CHANNEL_DATA (->sshb out) (->sshb data)))

  (define (do-rsync die)
    (when upgrade-session
      (define-values (_io _in _out _iws _mps) (send upgrade-session get-params))
      (set! io  _io) 
      (set! in  _in)
      (set! out _out)
      (set! server #t))

    (define (is-XMIT_EXTENDED_FLAGS? flags) (not (= 0 (bitwise-and flags XMIT_EXTENDED_FLAGS))))
    (define (is-XMIT_SAME_NAME? flags) (not (= 0 (bitwise-and flags XMIT_SAME_NAME))))
    (define (is-XMIT_LONG_NAME? flags) (not (= 0 (bitwise-and flags XMIT_LONG_NAME))))
    (define (is-XMIT_MOD_NSEC? flags) (not (= 0 (bitwise-and flags XMIT_MOD_NSEC))))
    (define (is-XMIT_SAME_MODE? flags) (not (= 0 (bitwise-and flags XMIT_SAME_MODE))))
    (define-flag-pred XMIT_SAME_UID)
    (define-flag-pred XMIT_SAME_GID)

    (define (read-byte-int) (bytes-ref (read-s-byte) 0))
    (define (read-30varuint32) (read-uint32))
    (define (read-varint) (read-uint32))

    (define (read-flags)
      (define flag1 (bytes-ref (read-s-byte) 0))
      (cond
        [(is-XMIT_EXTENDED_FLAGS? flag1) 
         (bitwise-ior flag1
                     (arithmetic-shift (read-byte-int) 8))]
        [else flag1]))

    (define (print-flags flags)
      (printf "XMIT_TOP_DIR        ~a\n" (bitwise-and flags XMIT_TOP_DIR))
      (printf "XMIT_SAME_MODE      ~a\n" (bitwise-and flags XMIT_SAME_MODE))   
      (printf "XMIT_EXTENDED_FLAGS ~a\n" (bitwise-and flags XMIT_EXTENDED_FLAGS)) 
      (printf "XMIT_SAME_UID       ~a\n" (bitwise-and flags XMIT_SAME_UID))
      (printf "XMIT_SAME_GID       ~a\n" (bitwise-and flags XMIT_SAME_GID))
      (printf "XMIT_SAME_NAME      ~a\n" (bitwise-and flags XMIT_SAME_NAME))
      (printf "XMIT_LONG_NAME      ~a\n" (bitwise-and flags XMIT_LONG_NAME))
      (printf "XMIT_SAME_TIME      ~a\n" (bitwise-and flags XMIT_SAME_TIME))
      (printf "XMIT_SAME_RDEV_MAJOR~a\n" (bitwise-and flags XMIT_SAME_RDEV_MAJOR))
      (printf "XMIT_HAS_IDEV_DATA  ~a\n" (bitwise-and flags XMIT_HAS_IDEV_DATA))
      (printf "XMIT_SAME_DEV       ~a\n" (bitwise-and flags XMIT_SAME_DEV))
      (printf "XMIT_RDEV_MINOR_IS_SMALL ~a\n"(bitwise-and flags XMIT_RDEV_MINOR_IS_SMALL))
      (printf "XMIT_MOD_NSEC            ~a\n"(bitwise-and flags XMIT_MOD_NSEC)))



    (define (read-file-metadata flags lastname)
      (define l1 (if (is-XMIT_SAME_NAME? flags) (read-byte-int) 0))
      (define l2 (if (is-XMIT_LONG_NAME? flags) (read-byte-int) (read-byte-int)))
      (define file-name 
        (let ([postfix (read-s-bytes l2)])
          (cond
            [(not (zero? l1))
                  (bytes-append (subbytes lastname 0 l1) postfix)]
            [else postfix])))
      (define file-size (read-30varuint32))
      (define mod-seconds (read-30varuint32))
      (printf "nseconds ~a\n" (is-XMIT_MOD_NSEC? flags))
      (define mod-nseconds (if (is-XMIT_MOD_NSEC? flags) (read-varint) 0))
      (define file-mode (if (not (is-XMIT_SAME_MODE? flags)) (read-varint) 0))
      (read-varint)

      (printf "FILENAME ~a ~a ~a\n" file-name file-size (date->string (seconds->date mod-seconds) #t))
      (list file-name file-size mod-seconds file-mode))


    
    (printf "Sending version ~a\n" server)
    (send-data2 (uint32->vax 28))  ;version
    (cond [server (send-data2 (bytes-append (bytes #x00) (bytes #x46 #xe5 #x59 #x98)))]
          [else (read-s-bytes 4)
                ;(read-s-byte)
                (define checksum (read-s-bytes 4))
                ;(send-data2 (uint32->vax (inexact->exact (round (/ (current-inexact-milliseconds) 1000)))))])
                (send-data2 (uint32->vax 0))
                (read-s-bytes 3)
                (let loop ([flags (read-flags)]
                           [lastname #""])
                  (print-flags flags)
                  (when (not (zero? flags))
                    (define fi (read-file-metadata flags lastname))
                    (loop (read-flags) (list-ref fi 0))))
                (send-data2 (uint32->vax 0))
                (send-data2 (uint32->vax 0))
                (send-data2 (uint32->vax 0))
                (send-data2 (uint32->vax 0))
                ])
  )

  (define/public (read-s-bytes n)
    (let loop ()
      (cond
        [(buffer-has-n n)
         (define d (read-bytes n pi))
         (printf "rsync reads ~a ~a\n" (bytes->hex-string d) n)
         d]
        [else
          (printf "Buffer has ~a needs ~a\n" (pipe-content-length pi) n)
          (call/cc (lambda (kt)
            (set-box! k kt)
            (k2)))
          (loop)])))

  (define/public (read-s-byte)
    (read-s-bytes 1))

  (define/public (read-long-int)
    (define f (read-uint32))
    (cond [(not (= f #xffffffff)) f]
          [else (+ (read-int) (* (read-int) 65536 64436))]))

  (define/public (read-int) (read-uint32))
  (define/public (read-uint32)
    (define b (read-s-bytes 4))
    ;(printf "RECV: ~a ~a\n" (bytes->hex-string b) (vax->uint32 b))
    (vax->uint32 b))

  (define/override (setup id _io)
    (super setup id _io)
    (sendp io SSH_MSG_CHANNEL_OPEN "session" in 32768 32768))

  (define/override (channel/success sc _iws _mps)
    (super channel/success sc _iws _mps)
    (sendp io SSH_MSG_CHANNEL_REQUEST out "exec" #f "rsync --server --sender -e.Lsf . /home/tewk/WardCampFlyer.svg /home/tewk/WardCamp2011.pdf")
    (define-values (s o i e) (subprocess #f #f #f "/usr/bin/rsync" "--server" "-e.Lsf" "." "/home/tewk/WardCampFlyer.svg" "/home/tewk/WardCamp2011.pdf"))
    (set! _s s)
    (set! _o o)
    (set! _i i)
    (set! _e e))

                                        

  (define/override (stderr type data)               (printf "~a\n" (bytes->hex-string data)) (flush-output))
  (define/override (stdout data)
    (printf "DATAIN: ~a\n" (bytes->hex-string data))
    (for ([x (bytes->string/latin-1 data)])
      (cond [(or (char-alphabetic? x) (char-numeric? x) (char-symbolic? x)) (printf "~a" x)]
            [else (printf  ".")]))
    (newline)
    (flush-output)

    (write-bytes data _i)
    (flush-output _i)
    (sleep 1)

    (define b (make-bytes 4096 0))
    (let loop ()
      (define bl (read-bytes-avail!* b _o))

      (when (not (zero? bl))
        (printf "DATAOUT1: ~a\n" (bytes->hex-string (subbytes b 0 bl)))
        (for ([x (bytes->string/latin-1 (subbytes b 0 bl))])
          (cond [(or (char-alphabetic? x) (char-numeric? x) (char-symbolic? x)) (printf "~a" x)]
                [else (printf  ".")]))
        (newline)
        (flush-output)
        (send-data2 (subbytes b 0 bl))
        (loop))))

#|
    (write-bytes data po)
    (flush-output po)
    (cond
      [(unbox k) ((unbox k) 'dddd)]
      [else
        (call/cc (lambda (die)
          (call/cc (lambda (kk)
            (set! k2 kk)
            (do-rsync die )))
            ))
        ]))
|#

  (define/public (read/file-list config-flags)
    (let loop ([flags1 (read-s-byte)]
                  [prev-name #f]
                  [prev-mod-time #f]
                  [prev-mode #f]
                  [prev-uid #f]
                  [prev-gid #f]
                  [prev-dev-major #f]
                  [prev-dev-minor #f]
                  [prev-link-len 0]
                  [prev-link-name #f]
                  [entries null])
    (define flags
      (cond
        [(and (version . > . 28) (bitwise-and XMIT_EXTENDED_FLAGS flags1))
          (bitwise-ior (arithmetic-shift (read-s-byte) 8) flags1)]
        [else flags1]))
    (define l1 (cond [(bitwise-and XMIT_SAME_NAME flags) (read-s-byte)] [else 0]))
    (define l2 (cond [(bitwise-and XMIT_LONG_NAME flags) (read-int)] [else (read-s-byte)]))
    (when (l2 . >= . (- MAXPATHLEN l2))
      (raise  "overflow: flags=0x~a l1=~a l2=~a, lastname=~a\n" flags l1 l2 prev-name))

    (define file-name (bytes-append (substring prev-name 0 (add1 l1)) (read-s-bytes l2)))
    (define file-length (read-long-int))
    (define file-mod-time (cond [(not (bitwise-and XMIT_SAME_TIME flags)) (read-int)] [else prev-mod-time]))
    (define file-mode (cond [(not (bitwise-and XMIT_SAME_MODE flags)) (read-int)] [else prev-mode]))
    (define file-uid (cond [(not (bitwise-and XMIT_SAME_UID flags)) (read-int)] [else prev-uid]))
    (define file-gid (cond [(not (bitwise-and XMIT_SAME_GID flags)) (read-int)] [else prev-gid]))
    (define file-dev-major (cond [(not (bitwise-and XMIT_SAME_RDEV_MAJOR flags)) (read-int)] [else prev-dev-major]))
    (define file-dev-minor (cond [(bitwise-and XMIT_RDEV_MINOR_IS_SMALL flags) (read-s-byte)] [else (read-int)]))
    (define file-link-len
      (cond [(and (bitwise-and PRESERVE_LINKS config-flags)
                  (islink? file-mode))
             (read-int)]
            [else #f]))
    (define file-link-name (cond [file-link-len (read-s-bytes file-link-len)] [else ""]))
    (loop (read-s-byte)
          file-name
          file-mod-time
          file-mode
          file-uid
          file-gid
          file-dev-major
          file-dev-minor
          file-link-len
          prev-link-name
          (cons (list file-name file-mod-time file-mode file-uid file-gid file-dev-major file-dev-minor file-link-len prev-link-name)
                entries))))

  (super-new)))
