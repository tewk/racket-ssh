#lang racket/base
(require racket/class
         "constants.rkt"
         "session.rkt"
         "utils.rkt")

(provide connection%)

(define-syntax-rule (mk-generic func clss method args ...)
  (begin
    (define g (generic clss method))
    (define (func obj args ...)
      (send-generic obj g args ...))))

(define-syntax-rule (define/class/generics class (func method args ...) ...)
  (begin
    (mk-generic func class method args ...) ...))

(define-syntax-rule (define/class/generics/provide class (func method args ...) ...)
  (begin
    (begin
      (mk-generic func class method args ...)
      (provide func)) ...))


(define cmd-session%
  (class session%
    (init-field [_in #f]
                [_io #f]
                [cmd #f])

  (inherit-field in)
  (inherit-field io)
  (inherit-field out)

  (super-new [in _in] [io _io])

  (sendp io SSH_MSG_CHANNEL_OPEN "session" in 32768 32768)

  (define/override (channel/success sc _iws _mps)
    (super channel/success sc _iws _mps)
    (sendp io SSH_MSG_CHANNEL_REQUEST out "exec" #f cmd))))


(define/class/generics/provide session%
  (session/setup setup chid io)
  (session/success channel/success sc _iws _mps)
  (session/failure channel/failure rc descr lang-tag)
  (session/eof eof)
  (session/stderr stderr type data)
  (session/stdout stdout data)
  (session/close close)
  (session/close-ch close-ch)
  (session/window-adjust window-adjust s)
  (session/signal signal)
  (session/exit exit ec)
  (session/exit-signal exit-signal str bool str2 str3)
  (session/window-change window-change wc hr wp hp))

(define connection%
  (class object%
    (init-field [io null])
    (field [channelcnt 0])
    (field [sessions (make-hash)])

    (define (nextchid)
      (set! channelcnt (add1 channelcnt))
      channelcnt)

    (define/public (new-custon-session s)
      (define chid (nextchid))
      (session/setup s chid io)
      (hash-set! sessions chid s))

    (define/public (new-cmd-session cmd)
      (define chid (nextchid))
      (hash-set! sessions chid (new cmd-session% [_in chid] [_io io] [cmd cmd])))

    (define/public (new-shell-session handlers)
      (define chid (nextchid))
      (sendp io SSH_MSG_CHANNEL_OPEN "session" chid 3 4096)
      (sendp io SSH_MSG_CHANNEL_REQUEST chid "shell" #f)
      (hash-set! sessions chid (new session% [in chid] [io io])))

    (define/public (event-loop)
      (let loop ()
      (define ps (open-input-bytes (send io recv-packet)))
      (define pktid (read-byte ps))
      (cond
        [(= pktid SSH_MSG_DISCONNECT)
         (exit 1)]
        [(= pktid SSH_MSG_GLOBAL_REQUEST)
          (define type (read-ssh-string ps))
          (define resp (read-ssh-bool ps))
          (printf "SSH_MSG_GLOBAL_REQUEST ~a ~a\n" type resp)]
        [(= pktid SSH_MSG_CHANNEL_OPEN_CONFIRMATION)
          (define-values (rc sc iws mps) (parse ps "iiii"))
          (session/success (hash-ref sessions rc) sc iws mps)]
        [(= pktid SSH_MSG_CHANNEL_OPEN_FAILURE)
          (define-values (rc reason-code descr lang-tag) (parse ps "iiss"))
          (session/failure (hash-ref sessions rc) reason-code descr lang-tag)]
        [(= pktid SSH_MSG_REQUEST_SUCCESS) (printf "SSH_MSG_REQUEST_SUCCESS\n")]
        [(= pktid SSH_MSG_REQUEST_FAILURE) (printf "SSH_MSG_REQUEST_FAILURE\n")]
        [else
          (define chid (read-ssh-uint32 ps))
          (define s (hash-ref sessions chid))
          (cond
            [(= pktid SSH_MSG_CHANNEL_EXTENDED_DATA) (session/stderr s (read-ssh-uint32 ps) (read-ssh-string ps))]
            [(= pktid SSH_MSG_CHANNEL_DATA)     (session/stdout s (read-ssh-string ps))]
            [(= pktid SSH_MSG_CHANNEL_EOF)      (session/close s)]
            [(= pktid SSH_MSG_CHANNEL_CLOSE)    (session/close-ch s)]
            [(= pktid SSH_MSG_CHANNEL_WINDOW_ADJUST) (session/window-adjust s (read-ssh-uint32 ps))]
            [(= pktid SSH_MSG_CHANNEL_REQUEST)
              (define type (read-ssh-string ps))
              (define resp (read-ssh-bool ps))
              (cond
                [(equal? type #"signal")             (session/signal s (read-ssh-string ps))]
                [(equal? type #"exit-status")        (session/exit s (read-ssh-uint32 ps))]  
                [(equal? type #"exit-signal")        (session/exit-signal s (read-ssh-string ps) 
                                                             (read-ssh-bool ps)
                                                             (read-ssh-string ps)
                                                             (read-ssh-string ps))]
                [(equal? type #"window-change")
                  (define-values (wc hr wp hp) (parse ps "iiii"))
                  (session/window-change s wc hr wp hp)]
                [else
                  (printf "CRE: ~a ~a\n" type resp)])])])
       (loop)
      ))

    (define/public (server-event-loop)
      (let loop ()
      (define ps (open-input-bytes (send io recv-packet)))
      (define pktid (read-byte ps))
      (cond
        [(= pktid SSH_MSG_DISCONNECT)
         (exit 1)]
        [(= pktid SSH_MSG_CHANNEL_OPEN)
          (define-values (type out iws mps) (parse ps "siii"))
          (define chid (nextchid))
          (cond
            [(equal? type #"session")
              (define s (new session% [in chid] [io io]))
              (hash-set! sessions chid s)
              (send s server-setup out 3 4096)]
            [else 
              (printf "SSH_MSG_CHANNEL_OPEN ~a ~a ~a ~a\n" type out iws mps)])]
        [(= pktid SSH_MSG_GLOBAL_REQUEST)
          (define type (read-ssh-string ps))
          (define resp (read-ssh-bool ps))
          (cond
            [(equal? type #"keepalive@openssh.com")
              (sendp io SSH_MSG_GLOBAL_REQUEST "keepalive@openssh.com" #f)]
            [else
              (printf "SSH_MSG_GLOBAL_REQUEST ~a ~a\n" type resp)])]

        [(= pktid SSH_MSG_CHANNEL_OPEN_CONFIRMATION)
          (define-values (rc sc iws mps) (parse ps "iiii"))
          (session/success (hash-ref sessions rc) sc iws mps)]
        [(= pktid SSH_MSG_CHANNEL_OPEN_FAILURE)
          (define-values (rc reason-code descr lang-tag) (parse ps "iiss"))
          (session/failure (hash-ref sessions rc) reason-code descr lang-tag)]
        [(= pktid SSH_MSG_REQUEST_SUCCESS) (printf "SSH_MSG_REQUEST_SUCCESS\n")]
        [(= pktid SSH_MSG_REQUEST_FAILURE) (printf "SSH_MSG_REQUEST_FAILURE\n")]
        [else
          (define chid (read-ssh-uint32 ps))
          (define s (hash-ref sessions chid))
          (cond
            [(= pktid SSH_MSG_CHANNEL_EXTENDED_DATA) (session/stderr s (read-ssh-uint32 ps) (read-ssh-string ps))]
            [(= pktid SSH_MSG_CHANNEL_DATA)     (session/stdout s (read-ssh-string ps))]
            [(= pktid SSH_MSG_CHANNEL_EOF)      (session/close s)]
            [(= pktid SSH_MSG_CHANNEL_CLOSE)    (session/close-ch s)]
            [(= pktid SSH_MSG_CHANNEL_WINDOW_ADJUST) (session/window-adjust s (read-ssh-uint32 ps))]
            [(= pktid SSH_MSG_CHANNEL_REQUEST)
              (define type (read-ssh-string ps))
              (define resp (read-ssh-bool ps))
              (cond
                [(equal? type #"signal")             (session/signal s (read-ssh-string ps))]
                [(equal? type #"exit-status")        (session/exit s (read-ssh-uint32 ps))]  
                [(equal? type #"exit-signal")        (session/exit-signal s (read-ssh-string ps) 
                                                             (read-ssh-bool ps)
                                                             (read-ssh-string ps)
                                                             (read-ssh-string ps))]
                [(equal? type #"window-change")
                  (define-values (wc hr wp hp) (parse ps "iiii"))
                  (session/window-change s wc hr wp hp)]
                [(equal? type #"exec") (printf "CMD: ~a\n" (parse ps "s"))]
                [(equal? type #"shell") (void)]
                [else
                  (printf "CRE: ~a ~a\n" type resp)])])])
       (loop)
      ))
  (super-new)
))
