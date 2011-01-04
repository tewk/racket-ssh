#lang racket
(require "ssh_openssl.rkt")
(require "ssh-utils.rkt")
(require "ssh-msg-ids.rkt")
(require "userauth.rkt")
(require racket/pretty)

(define b->hs bytes->hex-string)
 
(define (build-kexinit)
  (define algorithms (list 
    (list #"diffie-hellman-group-exchange-sha256" #"diffie-hellman-group-exchange-sha1")
    (list #"ssh-rsa")
    (list #"aes128-cbc")
    (list #"aes128-cbc")
    (list #"hmac-md5" #"hmac-sha1")
    (list #"hmac-md5" #"hmac-sha1")
    (list #"none")
    (list #"none")))
  (define pkt (bytes-append
  (bytes SSH_MSG_KEXINIT) 
  (random-bytes 16)
;  (build-ssh-bytes #"diffie-hellman-group-exchange-sha256,diffie-hellman-group-exchange-sha1,diffie-hellman-group14-sha1,diffie-hellman-group1-sha1")
;  (build-ssh-bytes #"diffie-hellman-group1-sha1")
;  (build-ssh-bytes #"ssh-rsa,ssh-dss")
;  (build-ssh-bytes #"aes128-ctr,aes192-ctr,aes256-ctr,arcfour256,arcfour128,aes128-cbc,3des-cbc,blowfish-cbc,cast128-cbc,aes192-cbc,aes256-cbc,arcfour,rijndael-cbc@lysator.liu.se")
;  (build-ssh-bytes #"aes128-ctr,aes192-ctr,aes256-ctr,arcfour256,arcfour128,aes128-cbc,3des-cbc,blowfish-cbc,cast128-cbc,aes192-cbc,aes256-cbc,arcfour,rijndael-cbc@lysator.liu.se")
;  (build-ssh-bytes #"hmac-md5,hmac-sha1,umac-64@openssh.com,hmac-ripemd160,hmac-ripemd160@openssh.com,hmac-sha1-96,hmac-md5-96")
;  (build-ssh-bytes #"hmac-md5,hmac-sha1,umac-64@openssh.com,hmac-ripemd160,hmac-ripemd160@openssh.com,hmac-sha1-96,hmac-md5-96")
;  (build-ssh-bytes #"none,zlib@openssh.com,zlib")
;  (build-ssh-bytes #"none,zlib@openssh.com,zlib")
  (for/fold ([accum #""]) ([x algorithms])
    (bytes-append accum (build-ssh-bytes (bytes-join x #","))))
#|
  (build-ssh-bytes #"diffie-hellman-group-exchange-sha1")
  (build-ssh-bytes #"ssh-rsa")
  (build-ssh-bytes #"aes128-cbc")
  (build-ssh-bytes #"aes128-cbc")
  (build-ssh-bytes #"hmac-md5")
  (build-ssh-bytes #"hmac-md5")
  (build-ssh-bytes #"none")
  (build-ssh-bytes #"none")
|#
  (build-ssh-bytes #"")
  (build-ssh-bytes #"")
  (bytes 0)
  (->bytes 0)))
  (values pkt algorithms))

(define (parse-kexinit bytes)
  (define in (open-input-bytes bytes))
  (define type (read-byte in))
  (define cookie (read-bytes 16 in))
  (define lines (for/list ([x (in-range 10)]) (read-ssh-string in)))
  (define first-kex-pkt (read-ssh-bool in))
  (define future-use (read-ssh-uint32 in))
  (for/list ([x lines]) 
    (eprintf "~a~n" x)
    (regexp-split #rx"," x)))
;      byte         SSH_MSG_KEXINIT
;      byte[16]     cookie (random bytes)
;      name-list    kex_algorithms
;      name-list    server_host_key_algorithms
;      name-list    encryption_algorithms_client_to_server
;      name-list    encryption_algorithms_server_to_client
;      name-list    mac_algorithms_client_to_server
;      name-list    mac_algorithms_server_to_client
;      name-list    compression_algorithms_client_to_server
;      name-list    compression_algorithms_server_to_client
;      name-list    languages_client_to_server
;      name-list    languages_server_to_client
;      boolean      first_kex_packet_follows
;      uint32       0 (reserved for future extension)

(define (parse-dh-reply bytes)
  (define in (open-input-bytes bytes))
  (define type (read-byte in))
  (define s1 (read-ssh-string in))
  (define s2 (read-ssh-string in))
  (define s3 (read-ssh-string in))
  (printf "~a\n~a\n~a\n" s1 s2 s3))

(define (parse-dh-group-exch-req bytes)
  (define in (open-input-bytes bytes))
  (define type (read-byte in))
  (values (read-ssh-uint32 in)
          (read-ssh-uint32 in)
          (read-ssh-uint32 in)))

(define (parse-dh-group-exch-reply bytes)
  (define in (open-input-bytes bytes))
  (define type (read-byte in))
  (values (read-ssh-string in)
          (read-ssh-string in)))

(define (parse-dh-group-exch-init bytes)
  (define in (open-input-bytes bytes))
  (define type (read-byte in))
  (read-ssh-string in))

(define (parse-dh-group-exch-gex-reply bytes)
  (define in (open-input-bytes bytes))
  (define type (read-byte in))
  (define host-key- (read-ssh-string in))
  (define in2 (open-input-bytes host-key-))
  (define host-key (read-ssh-string in2))
  (define host-key-cert (read-ssh-string in2))
  (define server-pub (read-ssh-string in))
  (define sigbuf (read-ssh-string in))
  (define in3 (open-input-bytes sigbuf))
  (define sig-type (read-ssh-string in3))
  (define sig (read-ssh-string in3))
  (values host-key host-key-cert server-pub sig-type sig))

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
      (eprintf "SENT PKT: type ~a pktlen: ~a padding ~a datalen ~a\n" type packet-length padding-len blen)
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
      (eprintf "RECV PKT: type ~a pktlen: ~a padding ~a datalen ~a\n" type packet-len padding-len data-len)
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
            (when (packet-len . > . 1024) (error "PACKET TO LONG ~a" packet-len))
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
  
    (define/public (send-raw . x) (send outs sendraw x))
    (define/public (read-line)  (send ins readline))
    (define/public (send-packet x) (send outs send-build-packet x))
    (define/public (recv-packet) (send ins recv-parse-packet))
    (define/public (get-CS-SC) (if (eq? role 'server) (values ins outs) (values outs ins)))
    (super-new)))

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

(define (curry-io io)
  (values (lambda (x) (send io send-packet x)) (lambda () (send io recv-packet))))

(define (diffie-hellman-group-exchange-hash io handshake algorithms hasher->bin bmin bm bmax sshp sshg cpub spub ssh-shared-secret public-host-key-blob)
  (match-define (list client-version server-version) handshake)
  (match-define (list client-kex-payload server-kex-payload kex-alg pub-priv-alg client-sym server-sym client-hmac server-hmac client-comp server-comp) algorithms)
  (define (chomprn x) (regexp-replace "\r$" (regexp-replace "\n$" (regexp-replace "\r\n$" x "") "") ""))
  (hasher->bin
    (build-ssh-bytes (chomprn client-version))
    (build-ssh-bytes (chomprn server-version))
    (build-ssh-bytes client-kex-payload)
    (build-ssh-bytes server-kex-payload)
    (build-ssh-bytes public-host-key-blob)
    (->bytes bmin) (->bytes bm) (->bytes bmax) 
    sshp 
    sshg 
    (build-ssh-bytes cpub)
    spub
    ssh-shared-secret))

(define (client-diffie-hellman-group-exchange io handshake algorithms hasher->bin role)
  (define-values (send-pkt recv-pkt) (curry-io io))
  (sendp io KEXDH_GEX_REQUEST (->bytes 1024) (->bytes 1024) (->bytes 8192))
  (define-values (pid1 sshp sshg) (recvp io "bss"))
  (define-values (dh cpub) (DiffieHellman-get-public-key sshp sshg 20))
  (sendp io bytes KEXDH_GEX_INIT cpub)
  (define-values (s-host-key spub sigtype sig) (parse-dh-group-exch-gex-reply (recv-pkt)))
  (define-values (shared-secret) (DiffieHellman-get-shared-secret dh spub))
  (define ssh-shared-secret (build-ssh-bin shared-secret))
  (define exchange-hash (diffie-hellman-group-exchange-hash io handshake algorithms hasher->bin 1024 1024 8192 sshp sshg cpub spub ssh-shared-secret s-host-key))
  (unless (sha1-rsa-verify/bin s-host-key exchange-hash) (error "a"))
  (values exchange-hash ssh-shared-secret))


(define (server-diffie-hellman-group-exchange io handshake algorithms hasher->bin role)
  (define-values (send-pkt recv-pkt) (curry-io io))
  (define p (hex-bytes->bytes (bytes-append
#"00FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
#"29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
#"EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
#"E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
#"EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"
#"C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"
#"83655D23DCA3AD961C62F356208552BB9ED529077096966D"
#"670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
#"E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9"
#"DE2BCBF6955817183995497CEA956AE515D2261898FA0510"
#"15728E5A8AACAA68FFFFFFFFFFFFFFFF")))
  (define g (bytes 2))
  (define sshp (build-ssh-bytes p))
  (define sshg (build-ssh-bytes g))
  (define-values (bmin bm bmax) (parse-dh-group-exch-req (recv-pkt))) ;  S <- C
  (sendp io KEXDH_GEX_GROUP sshp sshg)                                 ;  S -> C
  (define-values (cpub) (parse-dh-group-exch-init (recv-pkt)))        ;  S <- C
  (define-values (dh spub shared-secret) (DiffieHellmanGroup14-get-shared-secret cpub))
  (define ssh-shared-secret (build-ssh-bin shared-secret))
  (define public-host-key-blob (ssh-host-public-file->blob "/home/tewk/.ssh/rktsshhost.pub"))
  (define exchange-hash (diffie-hellman-group-exchange-hash io handshake algorithms hasher->bin bmin bm bmax sshp sshg cpub spub ssh-shared-secret public-host-key-blob))
  (define signature (sha1-rsa-signature/fn "/home/tewk/.ssh/rktsshhost" exchange-hash))
  (sendp io KEXDH_GEX_REPLY
    (build-ssh-bytes public-host-key-blob)
    spub
    (build-ssh-bytes (bytes-append (build-ssh-bytes #"ssh-rsa") (build-ssh-bytes signature))))
  (values exchange-hash ssh-shared-secret))

(define (diffie-hellman-group-exchange io handshake algorithms hasher->bin role)
  (define-values (exchange-hash ssh-shared-secret)
    ((if (server? role) server-diffie-hellman-group-exchange client-diffie-hellman-group-exchange)
     io handshake algorithms hasher->bin role))

    (sendp io SSH_MSG_NEWKEYS)
    (unless (recv/assert io SSH_MSG_NEWKEYS) (error "Expected SSH_MSG_NEWKEYS"))

    (define session_id exchange-hash)

    (define (setup-encrypted-streams ccipher chmac scipher shmac ssh-shared-secret exchange-hash session_id hasher->bin s/c)
      (define (gen k) (hasher->bin ssh-shared-secret exchange-hash k session_id))
      (define-values (C->S S->C) (send io get-CS-SC))
      (send C->S init ccipher chmac (gen #"A") (gen #"C") (gen #"E"))
      (send S->C init scipher shmac (gen #"B") (gen #"D") (gen #"F")))

    (match-define (list client-kex-payload server-kex-payload kex-alg pub-priv-alg client-sym server-sym client-hmac server-hmac client-comp server-comp) algorithms)
    (setup-encrypted-streams client-sym client-hmac server-sym server-hmac ssh-shared-secret exchange-hash session_id hasher->bin role)
    exchange-hash)

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

(define (algorithm-negotiation io role)
  (define-values (send-pkt recv-pkt) (curry-io io))
  (define-values (OUR_KEX_PAYLOAD OUR_ALGORITHMS) (build-kexinit))
  (send-pkt OUR_KEX_PAYLOAD)
  (define PEER_KEX_PAYLOAD (recv-pkt))
  (define PEER_ALGORITHMS  (parse-kexinit PEER_KEX_PAYLOAD))
  (define-values (SERVER_KEX_PAYLOAD SERVER_ALGORITHMS CLIENT_KEX_PAYLOAD CLIENT_ALGORITHMS)
    (if (server? role) 
      (values OUR_KEX_PAYLOAD OUR_ALGORITHMS PEER_KEX_PAYLOAD PEER_ALGORITHMS)
      (values PEER_KEX_PAYLOAD PEER_ALGORITHMS OUR_KEX_PAYLOAD OUR_ALGORITHMS)))
  (cons CLIENT_KEX_PAYLOAD (cons SERVER_KEX_PAYLOAD (negotiate SERVER_ALGORITHMS CLIENT_ALGORITHMS))))

(define (list->hash-keys lst val)
  (make-hash (map (lambda (x) (cons x x)) lst)))

(define (negotiate sa ca)
  (for/list ([cs ca]
             [ss sa])
    (define nv (for/or ([c cs]) (if (member c ss) c #f)))
    (unless nv (error 'negotiate "failed algorithm negotiation ~a ~a" cs ss))
    nv))

(define (do-key-exchange io handshake algorithms role)
  (define kexalg (third algorithms))
  (define (e) (error (format "key exchange algorithm ~a not supported" kexalg)))
  (cond
    [(bytes=? kexalg #"diffie-hellman-group-exchange-sha256") (diffie-hellman-group-exchange io handshake algorithms sha256->bin role)]
    [(bytes=? kexalg #"diffie-hellman-group-exchange-sha1") (diffie-hellman-group-exchange io handshake algorithms sha1->bin role)]
    [(bytes=? kexalg #"diffie-hellman-group14-sha1") (e)]
    [(bytes=? kexalg #"diffie-hellman-group1-sha1") (e)]
    [else (e)]))

(define ssh
  (class object%
    (field (io null))
    (define/public (connect host port)
      (define role 'server)
      (define-values (in out) (tcp-connect "localhost" 2224))
      (set! io (new ssh-transport (in in) (out out)))

      (define handshake (do-handshake io role))
      (define algs (algorithm-negotiation io role))
      (do-key-exchange io handshake algs role)
      (do-client-user-auth io))

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
  [(vector) (send (new ssh (host "localhost") (port 22)) connect "localhost" 2224)]
  [(vector "s") (send (new sshd (host "localhost") (port 2222)) listen)])
