#lang racket/base
(require racket/class
         "constants.rkt"
         "utils.rkt")

(provide session%)

(define session%
  (class object%
    (init-field [in #f]
                [io #f])
    (field [out #f]
           [iws #f]
           [mps #f])

  (define/public (channel/success sc _iws _mps)
    (set! out sc)
    (set! iws _iws)
    (set! mps _mps))
    
  (define/public (channel/failure reason-code descr lang-tag)
    (error "DIE DIE DIE"))
  (define/public (send-data data)
    (sendp io SSH_MSG_CHANNEL_DATA (->sshb out) (->sshb data)))

  (define/public (setup chid _io)
    (set! in chid)
    (set! io _io))

  (define/public (server-setup _out _iws _mps)
    (set! out _out)
    (set! iws _iws)
    (set! mps _mps)
    (sendp io SSH_MSG_CHANNEL_OPEN_CONFIRMATION (->sshb out) (->sshb in) (->sshb iws) (->sshb mps)))

  (define/public (eof)                            (printf "EOF\n"))
  (define/public (stderr type data)               (printf "~a" data) (flush-output))
  (define/public (stdout data)                    (printf "~a\n~a\n" data (bytes->hex-string data)) (flush-output))
  (define/public (close)                          (printf "close\n"))
  (define/public (close-ch)                       (printf "close-ch\n"))
  (define/public (window-adjust x)                (void)#;(printf "window-adjust ~a\n" x))
  (define/public (signal)                         (printf "signal\n"))
  (define/public (exit ec)                        (printf "exit ~a\n" ec))
  (define/public (exit-signal str bool str2 str3) (printf "exit-signal\n"))
  (define/public (window-change wc hr wp hp)      (printf "windowchange ~a ~a ~a ~a\n" wc hr wp hp))
  (super-new)
))


