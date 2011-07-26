#lang racket/base
(require racket/class
         "utils.rkt"
         "constants.rkt"
         "session.rkt")

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

(define (islink? mode)
  (bitwise-and #x1 mode))

(define (vax->uint32 x) (integer-bytes->integer x #f #f))
(define (read-uint32 in) (vax->uint32 (read-bytes 4 in)))
(define (uint32->vax x) (integer->integer-bytes x 4 #f #f))
(define (write-uint32 x out) (write-bytes (uint32->vax x) out))
(define MAXPATHLEN 255)

(define-syntax-rule (let/ccc k body ...)
  (call-with-composable-continuation (lambda (k) body ...)))

(define rsync-session%
  (class session%
  (init-field [upgrade-session #f])
  (field [server #f])
  (field [k #f])
  (field [k2 #f])
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
    
    (printf "Sending version\n")
    (send-data2 (uint32->vax 30))  ;version
    (cond [server (send-data2 (bytes-append (bytes #x00) (bytes #x46 #xe5 #x59 #x98)))]
          [else (read-s-byte) (read-s-bytes 4)])
  )

  (define/public (read-s-bytes n)
    (let loop ()
      (cond
        [(buffer-has-n n) (read-bytes n pi)]
        [else
          (call/cc (lambda (kt)
            (set! k kt)
            (k2))
          (loop))])))

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
    (sendp io SSH_MSG_CHANNEL_REQUEST out "exec" #f "rsync --server -e.Lsf . /home/tewk/Hamlet2.vob"))

  (define/override (stderr type data)               (printf "~a\n" (bytes->hex-string data)) (flush-output))
  (define/override (stdout data)
    (printf "DATAIN: ~a\n" (bytes->hex-string data))
    (for ([x (bytes->string/latin-1 data)])
      (cond [(or (char-alphabetic? x) (char-numeric? x) (char-symbolic? x)) (printf "~a" x)]
            [else (printf  ".")]))
    (newline)
    (flush-output)
    (write-bytes data po)
    (cond
      [k (k)]
      [else
        (call/cc (lambda (die)
          (call/cc (lambda (kk)
            (set! k2 kk)
            (do-rsync die )))
            (set! k die)))
        ]))

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
