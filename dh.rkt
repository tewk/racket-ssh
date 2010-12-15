#lang racket/base
(require ffi/unsafe
         racket/runtime-path
         (for-syntax racket/base))
(require openssl/sha1)

(provide MD5-it
         DiffieHellmanGroup1-get-public-key
         DiffieHellman-get-public-key
         DiffieHellman-get-shared-secret
         DiffieHellmanGroup14-get-shared-secret
         sha256->hex
         build-ssh-bn)

(define-runtime-path libcrypto-so
  (case (system-type)
    [(windows) '(so "libeay32")]
    [else '(so "libcrypto")]))

(define libcrypto
  (with-handlers ([exn:fail? (lambda (exn) 
                               (log-warning (format "warning: couldn't load OpenSSL library: ~a"
                                                    (if (exn? exn)
                                                        (exn-message exn)
                                                        exn)))
                               #f)])
    (ffi-lib libcrypto-so '("" "0.9.8b" "0.9.8" "0.9.7"))))

(define-syntax-rule (define-crypto-func name func-signature)
  (define name (and libcrypto (get-ffi-obj (quote name) libcrypto func-signature (lambda () #f)))))

(define-cstruct _BN ([j1 _long] [top _int] [dmax _int] [neg _int] [flags _int]))
(define-cstruct _DH ([pad _int] [version _int] [p _BN-pointer][g _BN-pointer] [length _long] [pub_key _BN-pointer] [priv_key _BN-pointer]))

(define _MD5_CTX-pointer _pointer)
(define _SHA1_CTX-pointer _pointer)
(define _SHA256_CTX-pointer _pointer)


(define-crypto-func DH_new          (_fun                                -> _DH-pointer))
(define-crypto-func DH_generate_key (_fun _DH-pointer                    -> _int))
(define-crypto-func DH_compute_key  (_fun _bytes _BN-pointer _DH-pointer -> _int))
(define-crypto-func DH_size         (_fun _DH-pointer                    -> _int))
(define-crypto-func DH_free         (_fun _DH-pointer                    -> _int))

(define-crypto-func BN_new          (_fun                                -> _BN-pointer))
(define-crypto-func BN_free         (_fun _BN-pointer                    -> _int))
(define-crypto-func BN_bin2bn       (_fun _bytes _int _BN-pointer        -> _BN-pointer))
(define-crypto-func BN_hex2bn       (_fun (_ptr i _BN-pointer) _bytes    -> _int))
(define-crypto-func BN_dec2bn       (_fun (_ptr i _BN-pointer) _bytes    -> _int))
(define-crypto-func BN_num_bits     (_fun _BN-pointer                    -> _int))
(define-crypto-func BN_bn2bin       (_fun _BN-pointer _bytes             -> _int))
(define-crypto-func BN_print_fp     (_fun _pointer _BN-pointer           -> _int))
(define-crypto-func BN_rand         (_fun _BN-pointer _int  _int _int    -> _int))
(define-crypto-func BN_cmp          (_fun _BN-pointer _BN-pointer        -> _int))
(define-crypto-func BN_is_bit_set   (_fun _BN-pointer _int               -> _int))
(define-crypto-func BN_value_one    (_fun                                -> _BN-pointer))
(define-crypto-func BN_sub          (_fun _BN-pointer _BN-pointer _BN-pointer -> _int))
(define-crypto-func BN_clear_free   (_fun _BN-pointer                    -> _int))

(define-crypto-func MD5_Init        (_fun _MD5_CTX-pointer                 -> _int))
(define-crypto-func MD5_Update      (_fun _MD5_CTX-pointer _bytes _long    -> _int))
(define-crypto-func MD5_Final       (_fun (_ptr i _bytes) _MD5_CTX-pointer -> _int))
(define-crypto-func MD5             (_fun _bytes _long (_ptr i _bytes)     -> _int))
(define-crypto-func MD5_Transform   (_fun _MD5_CTX-pointer _bytes          -> _void))
(define-crypto-func SHA1_Init        (_fun _SHA1_CTX-pointer                 -> _int))
(define-crypto-func SHA1_Update      (_fun _SHA1_CTX-pointer _bytes _long    -> _int))
(define-crypto-func SHA1_Final       (_fun (_ptr i _bytes) _SHA1_CTX-pointer -> _int))
(define-crypto-func SHA1             (_fun _bytes _long (_ptr i _bytes)     -> _int))
(define-crypto-func SHA1_Transform   (_fun _SHA1_CTX-pointer _bytes          -> _void))
(define-crypto-func SHA256_Init        (_fun _SHA256_CTX-pointer                 -> _int))
(define-crypto-func SHA256_Update      (_fun _SHA256_CTX-pointer _bytes _long    -> _int))
(define-crypto-func SHA256_Final       (_fun (_ptr i _bytes) _SHA256_CTX-pointer -> _int))
(define-crypto-func SHA256             (_fun _bytes _long (_ptr i _bytes)     -> _int))
(define-crypto-func SHA256_Transform   (_fun _SHA256_CTX-pointer _bytes          -> _void))

(define (sha1->hex . lst)
  (bytes->hex-string (apply sha1->bin lst)))
(define (sha1->bin . lst)
  (let ([ctx (malloc 256)]
        [tmp (make-bytes 4096)]
        [result (make-bytes 20)])
    (SHA1_Init ctx)
    (for ([x lst]) (SHA1_Update ctx x (bytes-length x)))
    (SHA1_Final result ctx)
    result))

(define (sha256->hex . lst)
  (bytes->hex-string (apply sha256->bin lst)))
(define (sha256->bin . lst)
  (let ([ctx (malloc 256)]
        [tmp (make-bytes 4096)]
        [result (make-bytes 20)])
    (SHA256_Init ctx)
    (for ([x lst]) (SHA256_Update ctx x (bytes-length x)))
    (SHA256_Final result ctx)
    result))


(define (->bytes x)
  (cond [(string? x) (string->bytes/locale x)]
        [(bytes? x) x]
        [(number? x) (integer->integer-bytes x 4 #f #t)]))
(define (BN_num_bytes bn)
  (ceiling (/ (+ (BN_num_bits bn) 7) 8)))

(define (build-ssh-bn bn)
  (define b (make-bytes (BN_num_bytes bn) 0))
  ;(printf "~a~n" (BN_num_bytes bn))
  (define bl (BN_bn2bin bn b))
  (let ([bs
    (if (not (= 0 (bitwise-and #x80 (bytes-ref b 0))))
      (bytes-append (->bytes (+ bl 1)) (bytes 0) (subbytes b 0 bl))
      (bytes-append (->bytes bl) (subbytes b 0 bl)))])
    ;(printf "B& ~a ~a\n~a\n~a\n" (bytes->hex-string (bytes (bytes-ref b 0))) (bitwise-and #x80 (bytes-ref b 0))
    ;                         (bytes->hex-string b)
   ;                          (bytes->hex-string bs))
    bs))
(define (BNp bn)
  (define bits-set (for/sum ([i (in-range (BN_num_bits bn))]) (BN_is_bit_set bn i)))
  (define b (make-bytes (BN_num_bytes bn) 0))
  (define bl (BN_bn2bin bn b))
  (printf "~a ~a ~a ~a ~a/~a\n" (BN-top bn) (BN-dmax bn) (BN-neg bn) (BN-flags bn) bits-set (BN_num_bits bn))
  (printf "~a\n" (bytes->hex-string (subbytes b 0 bl))))

(define (DiffieHellmanGroup1-get-public-key)
  (define dh (DH_new))
  (define p_s (bytes-append
  #"FFFFFFFFFFFFFFFFC90FDAA22168C234"
  #"C4C6628B80DC1CD129024E088A67CC74"
  #"020BBEA63B139B22514A08798E3404DD"
  #"EF9519B3CD3A431B302B0A6DF25F1437"
  #"4FE1356D6D51C245E485B576625E7EC6"
  #"F44C42E9A637ED6B0BFF5CB6F406B7ED"
  #"EE386BFB5A899FA5AE9F24117C4B1FE6"
  #"49286651ECE65381FFFFFFFFFFFFFFFF"))
  (define p (BN_new))
  (define g (BN_new))
  (BN_hex2bn p p_s)
  (BN_dec2bn g #"2")

  (set-DH-p! dh p)
  (set-DH-g! dh g)
  (DiffieHellmanGenerateKey dh 20)
  (values dh (build-ssh-bn (DH-pub_key dh))))

(define (DiffieHellman-get-public-key pbs gbs bits-needed)
  (define dh (DH_new))
  (define p (BN_new))
  (define g (BN_new))

  (set-DH-p! dh (BN_bin2bn pbs (bytes-length pbs) p))
  (set-DH-g! dh (BN_bin2bn gbs (bytes-length gbs) g))
  (DiffieHellmanGenerateKey dh (* 16 8))
  (values dh (build-ssh-bn (DH-pub_key dh))))

(define (MD5-it d)
  (define r (make-bytes 16 0))
  (MD5 d (bytes-length d) r)
  r)

(define (DiffieHellman-get-shared-secret dh peer-public-key)
  (define shared-secret (make-bytes (DH_size dh)))
  (DH_compute_key shared-secret peer-public-key dh))

(define (DiffieHellmanGenerateKey dh bits-needed)
  (define pbits (BN_num_bits (DH-p dh)))
  (define bits-needed*2 (* 2 bits-needed))
  (printf "~a ~a ~a\n" bits-needed bits-needed*2 pbits)
  (when (bits-needed . > . (/ 2147483647 2))
    (eprintf "DiffieHellmanGenerateKey group too bi: ~a (2*bits-needed ~a)\n" pbits bits-needed*2))
  (when (bits-needed*2 . >= . pbits)
    (eprintf "DiffieHellmanGenerateKey group too small: (p bits ~a) <= (2*bits-needed ~a) \n" pbits bits-needed*2))

  (let loop ()
    ;(when (not (DH-priv_key dh))
    ;  (BN_clear_free (DH-priv_key dh)))
    (set-DH-priv_key! dh (BN_new))
    (when (= 0 (BN_rand (DH-priv_key dh) bits-needed*2 0 0))
      (eprintf "dh_gen_key: BN_rand failed"))
    (when (= 0 (DH_generate_key dh))
      (eprintf "DH_generate_key failed"))
    (if (not (DiffieHellmanPubIsValid dh (DH-pub_key dh) "desc"))
     (begin 
      (printf "ISVALID FAILED\n")
      (loop))
     (begin
      (printf "ISVALID SUCCEEDED\n")
      #t))))

(define-syntax-rule (with-BN ([a b]...) body ...)
  (let* ([a null] ...)
    (dynamic-wind
      (lambda ()
        (set! a b) ...)
      (lambda ()
        body ...)
      (lambda ()
        (BN_clear_free a) ...))))

(define-syntax-rule (for/sum ([a b]...) body ...)
  (for/fold ([sum 0]) ([a b]...)
    (+ sum (begin body ...)))) 

(define (DiffieHellmanPubIsValid dh pub desc)
 (with-BN ([tmp (BN_new)])
  (printf "publ ") (BNp (DH-pub_key dh))
  (printf "priv ") (BNp (DH-priv_key dh))
  (printf "p    ") (BNp (DH-p dh))
  (BN_sub tmp (DH-p dh) (BN_value_one))
  (printf "p-1  ") (BNp tmp)
  (printf "cmp pub tmp ~a\n" (BN_cmp pub tmp))
  (cond 
   [(not (zero? (BN-neg pub))) (eprintf "~a pub is negative" desc) #f]
   [(not (= 1 (BN_cmp pub (BN_value_one)))) (eprintf "~a pub is <= 1" desc) #f]
   [(or (zero? (BN_sub tmp (DH-p dh) (BN_value_one)))
        (not (= -1 (BN_cmp pub tmp))))
        (eprintf "invalid public DH value: >= p-1\n")
        (eprintf "~a ~a ~a\n" (DH-p dh) pub (BN_cmp pub tmp))
        (BNp (DH-p dh))
        (BNp tmp)
        (BNp pub)
        #f]
  [else
    (define pbits (BN_num_bits (DH-p dh)))
    (define pub-bits-set (for/sum ([i (in-range pbits)]) (BN_is_bit_set pub i)))
    (eprintf "bits set ~a/~a\n" pub-bits-set pbits)
    (if (pub-bits-set . > . 1)
      #t
      (begin
        (eprintf "invalid public DH value (~a/~a)\n" pub-bits-set pbits)
        #f))])))
  
      
    
  

(define (DiffieHellmanGroup14-get-shared-secret peer-public-key)
  (define p_s (bytes-append
#"FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
#"29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
#"EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
#"E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
#"EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"
#"C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"
#"83655D23DCA3AD961C62F356208552BB9ED529077096966D"
#"670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
#"E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9"
#"DE2BCBF6955817183995497CEA956AE515D2261898FA0510"
#"15728E5A8AACAA68FFFFFFFFFFFFFFFF"))
  (define dh (DH_new))
  (define p (BN_new))
  (define g (BN_new))
  (define e (BN_new))
  (BN_hex2bn p p_s)
  (BN_dec2bn g #"2")
  (BNp p)
  (BNp g)
  (BN_bin2bn peer-public-key (bytes-length peer-public-key) e)
  (set-DH-p! dh p)
  (set-DH-g! dh g)
  (DiffieHellmanGenerateKey dh 20)
#|
  (define bits-needed (cond [(bits-neededx . <= . 128) 1024]
                            [(bits-neededx . <= . 192) 2048]
                            [else 4096]))
|#
  (define dhsize (DH_size dh))
  (define shared-secret (make-bytes dhsize 0))
  (DH_compute_key shared-secret e dh)
  (values dh (build-ssh-bn (DH-pub_key dh)) shared-secret))
