#lang racket
(require "ssh-openssl.rkt")
(require "utils.rkt")
(require "constants.rkt")
(require "userauth.rkt")
(require "dh.rkt")
(require racket/pretty)

(define b->hs bytes->hex-string)
 
(define ssh-stream
  (class object%
    (init-field (s null))
    (init-field (dir 0))
    (field (on #f))
    (field (cipher (make-cipher)))
    (field (hmac (make-hmac)))
    (field (hmaclen 0))
    (field (cipher-block-size 0))
    (field (min-pad 8))
    (field (ivlen 0))
    (field (keylen 0))
    (field (IV null))
    (field (pktcnt 0))

    (define/public (init cname hname iv KEY INTEG)
      (define-values (crc bs kl ivl) (cipher-init cipher cname KEY iv (if (eq? dir 'out) 1 0)))
      (define-values (hrc hs hbs) (hmac-init hmac hname INTEG))
      ;(printf "~a ~a ~a ~a\n" crc bs kl ivl)
      ;(printf "~a ~a ~a\n" hrc hs hbs)
      (set! IV iv)
      (set! cipher-block-size bs)
      (set! min-pad (max 8 bs))
      (set! keylen kl)
      (set! ivlen ivl)
      (set! hmaclen hs)
      (set! on #t))
    
    (define/public (sendraw lst)
      (for ([x lst]) (write-bytes x s))
      (flush-output s))

    (define/public (readline)
      (read-line s))

    (define (incrpktcnt) 
      (set! pktcnt (+ pktcnt 1)))

    (define (updateIV new)
      (let* ([b (bytes-append IV new)]
             [bl (bytes-length b)])
        (set! IV (subbytes b (- bl ivlen) bl))))

    (define (calc-hmac pkt)
      (subbytes (hmacit hmac (bytes-append (->bytes pktcnt) pkt)) 0 hmaclen))

    (define (build-packet buffer)
      (define buf (->bytes buffer))
      (define blen (bytes-length buf))
      (define initial-total-len (+ 4 1 blen))
      (define ipadding-len (- min-pad (modulo initial-total-len min-pad)))
      (define padding-len (if (ipadding-len . < . 4) (+ ipadding-len min-pad) ipadding-len))
      (define packet-length (+ 1 blen padding-len))
      ;Smaller than 16 byte packet case not implemented 
      (define type (bytes-ref buffer 0))
      (eprintf "SENT PKT: type ~a ~a pktlen: ~a padding ~a datalen ~a\n" type (pkt-id->name type) packet-length padding-len blen)
      ;(eprintf "~a\n" (bytes->hex-string buf))
      (bytes-append
        (->bytes packet-length)
        (bytes padding-len)
        buf
        (random-bytes padding-len)))

    (define/public (parse-packet buffer)
      (define in (open-input-bytes buffer))
      (define packet-len (read-ssh-uint32 in))
      (define padding-len (read-byte in))
      (define data-len (- packet-len 1 padding-len))
      (define data (read-bytes data-len in))
      (define padding (read-bytes padding-len in))
      (define type (bytes-ref data 0))
      (eprintf "RECV PKT: type ~a ~a pktlen: ~a padding ~a datalen ~a\n" type (pkt-id->name type) packet-len padding-len data-len)
      ;(eprintf "~a\n" (b->hs data))
      (when (= type 1)
        (define in (open-input-bytes data))
        (define type (read-byte in))
        (define ec (read-ssh-uint32 in))
        (define s1 (read-ssh-string in))
        (define s2 (read-ssh-string in))
        (printf "SSH_CLOSE_CONNECTION ~a desc: ~a langtag: ~a\n" ec s1 s2))
      data)

    (define/public (recv-parse-packet) (parse-packet (recv-packet)))
    (define/public (recv-packet)
      (unless (eq? dir 'in) (error "Attempting INPUT on OUTPUT stream"))
      (begin0
        (if on
          (let ()
            (define prefix-size (max 4 cipher-block-size))
            (define enc-prefix (read-bytes prefix-size s))  
            (define prefix (decrypt-begin cipher enc-prefix IV))
            (define packet-len (->int32 (subbytes prefix 0 4)))
            (when (packet-len . > . 1024) (error "PACKET TO LONG" packet-len))
            (define bytes-left (+ (- packet-len prefix-size) 4))
            (define-values (enc-rest rest)
              (if (bytes-left . > . 0)
                (let ()
                  (define enc-rest (read-bytes (+ (- packet-len prefix-size) 4) s))
                  (define rest (decrypt-rest cipher enc-rest))
                  (values enc-rest rest))
                (values #"" #"")))
            (define hmacin (read-bytes hmaclen s))
            (define pkt (bytes-append prefix rest))
            (updateIV (bytes-append enc-prefix enc-rest))
            (define myhmac (calc-hmac pkt))
            (unless (bytes=? hmacin myhmac) (error 'recv-packet "HMACS dont match ~a ~a ~a ~a" (b->hs hmacin) (b->hs myhmac) (bytes-length hmacin) (bytes-length myhmac)))
            pkt)
          (let* ([prefix-size 4]
                 [prefix (read-bytes prefix-size s)]
                 [packet-len (->int32 prefix)]
                 [rest (read-bytes packet-len s)]
                 [pkt (bytes-append prefix rest)])
            pkt))
        (incrpktcnt)))

    (define/public (send-build-packet buffer) (send-packet (build-packet buffer)))
    (define/public (send-packet pkt)
      (unless (eq? dir 'out) (error "Attempting OUTPUT on INPUT stream"))
      (if on
        (let ()
          (define enc-data (encrypt-all cipher pkt IV))
          (write-bytes enc-data s)
          (write-bytes (calc-hmac pkt) s)
          (updateIV enc-data))
        (write-bytes pkt s))
      (flush-output s)
      (incrpktcnt))

    (super-new)))

(define ssh-transport
  (class object%
    (init (in null)
          (out null))
    (init-field (role null))
    (field (ins (new ssh-stream  [s in] [dir 'in])))
    (field (outs (new ssh-stream [s out] [dir 'out])))
    (field (session-id null))
  
    (define/public (send-raw . x) (send outs sendraw x))
    (define/public (read-line)  (send ins readline))
    (define/public (send-packet x) (send outs send-build-packet x))
    (define/public (recv-packet) (send ins recv-parse-packet))
    (define/public (get-CS-SC) (if (eq? role 'server) (values ins outs) (values outs ins)))
    (define/public (get-session-id exch-hash)
      (when (eq? null session-id) (set! session-id exch-hash))
      session-id)

    (super-new)))

(define (curry-io io)
  (values (lambda (x) (send io send-packet x)) (lambda () (send io recv-packet))))

(define (server? x) (eq? x 'server))
(define (do-handshake io role)
  (define RACKET-SSH-VERSION #"SSH-2.0-RacketSSH_0.1p0 Racket5.0")
  (send io send-raw RACKET-SSH-VERSION #"\r\n")
  (define PEER-VERSION (send io read-line))

  (define-values (SERVER_VERSION CLIENT_VERSION)
    (if (server? role) 
      (values RACKET-SSH-VERSION PEER-VERSION)
      (values PEER-VERSION RACKET-SSH-VERSION)))
  (printf "SERVER: ~a\n" SERVER_VERSION)
  (printf "CLIENT: ~a\n" CLIENT_VERSION)
  (list CLIENT_VERSION SERVER_VERSION))


(define ssh
  (class object%
    (field (io null))
    (define/public (connect host port)
      (define role 'client)
      (define-values (in out) (tcp-connect host port))
      (set! io (new ssh-transport (in in) (out out)))

      (define handshake (do-handshake io role))
      (define algs (algorithm-negotiation io role))
      (define exchange-hash (do-key-exchange io handshake algs role))
      (do-client-user-auth io exchange-hash))

    (super-new)))

(define sshd
  (class object%
    (init-field (host "localhost"))
    (init-field (port 2222))
    (field (io null))
    (field (role 'server))
    (define/public (listen)
      (define-values (in out) (tcp-accept (tcp-listen port 4 #t)))
      (set! io (new ssh-transport (in in) (out out) (role role)))

      (define handshake (do-handshake io role))
      (define algs (algorithm-negotiation io role))
      (define exchange-hash (do-key-exchange io handshake algs role))

      (do-server-user-auth io exchange-hash))

    (define (gp)
      (define-values (send-pkt recv-pkt) (curry-io io))
      (define ppp (recv-pkt))
      (printf "A~a\n" (bytes->hex-string ppp)))

    (super-new)))


(match (current-command-line-arguments)
  [(vector) (send (new ssh) connect "localhost" 2222)]
  [(vector "s") (send (new sshd (host "localhost") (port 2222)) listen)]
  [(vector "l") (send (new ssh) connect "localhost" 22)])
