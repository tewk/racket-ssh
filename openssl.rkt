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
         sha256->bin
         build-ssh-bn
         build-ssh-bin
         fn->EVP_PKEY-private
         sha1-rsa-signature
         sha1-rsa-signature/fn)

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
  (begin
    (define name (and libcrypto (get-ffi-obj (quote name) libcrypto func-signature (lambda () #f))))
    (provide name)))


(define-cstruct _BN ([j1 _long] [top _int] [dmax _int] [neg _int] [flags _int]))
(define-cstruct _DH ([pad _int] [version _int] [p _BN-pointer][g _BN-pointer] [length _long] [pub_key _BN-pointer] [priv_key _BN-pointer]))


(define _MD5_CTX-pointer _pointer)
(define _SHA1_CTX-pointer _pointer)
(define _SHA256_CTX-pointer _pointer)
(define _RSA-pointer _pointer)
(define _DSA-pointer _pointer)
(define _EC_KEY-pointer _pointer)
(define _BIO-pointer _pointer)
(define _BIO_METHOD-pointer _pointer)
(define _FILE-pointer _pointer)
(define _EVP_MD_CTX-pointer _pointer)
(define _EVP_MD-pointer _pointer)
(define _EVP_PKEY-pointer _pointer)
(define _ENGINE-pointer _pointer)
(define _EVP_CIPHER_CTX-pointer _pointer)
(define _EVP_CIPHER-pointer _pointer)
(define _ASN1_TYPE-pointer _pointer)
(define _HMAC_CTX-pointer _pointer)

(define-crypto-func OpenSSL_add_all_algorithms (_fun -> _void))
(define-crypto-func OpenSSL_add_all_digests    (_fun -> _void))

(define EVP_MAX_MD_SIZE 64)
(define NID_sha1 64)
(define SHA256_DIGEST_LENGTH 32)

(define-crypto-func DH_new          (_fun                                     -> _DH-pointer))
(define-crypto-func DH_generate_key (_fun _DH-pointer                         -> _int))
(define-crypto-func DH_compute_key  (_fun _bytes _BN-pointer _DH-pointer      -> _int))
(define-crypto-func DH_size         (_fun _DH-pointer                         -> _int))
(define-crypto-func DH_free         (_fun _DH-pointer                         -> _int))

(define-crypto-func BN_new          (_fun                                     -> _BN-pointer))
(define-crypto-func BN_free         (_fun _BN-pointer                         -> _int))
(define-crypto-func BN_bin2bn       (_fun _bytes _int _BN-pointer             -> _BN-pointer))
(define-crypto-func BN_hex2bn       (_fun (_ptr i _BN-pointer) _bytes         -> _int))
(define-crypto-func BN_dec2bn       (_fun (_ptr i _BN-pointer) _bytes         -> _int))
(define-crypto-func BN_num_bits     (_fun _BN-pointer                         -> _int))
(define-crypto-func BN_bn2bin       (_fun _BN-pointer _bytes                  -> _int))
(define-crypto-func BN_print_fp     (_fun _pointer _BN-pointer                -> _int))
(define-crypto-func BN_rand         (_fun _BN-pointer _int  _int _int         -> _int))
(define-crypto-func BN_cmp          (_fun _BN-pointer _BN-pointer             -> _int))
(define-crypto-func BN_is_bit_set   (_fun _BN-pointer _int                    -> _int))
(define-crypto-func BN_value_one    (_fun                                     -> _BN-pointer))
(define-crypto-func BN_sub          (_fun _BN-pointer _BN-pointer _BN-pointer -> _int))
(define-crypto-func BN_clear_free   (_fun _BN-pointer                         -> _int))

(define-crypto-func PEM_read_bio_RSAPrivateKey  (_fun _BIO-pointer (_or-null _RSA-pointer) (_or-null _pointer) (_or-null _pointer)  -> _RSA-pointer))
(define-crypto-func PEM_read_RSAPrivateKey      (_fun _FILE-pointer _RSA-pointer _pointer _pointer -> _RSA-pointer))
(define-crypto-func PEM_read_bio_PrivateKey     (_fun _BIO-pointer (_or-null _EVP_PKEY-pointer) (_or-null _pointer) (_or-null _pointer) -> _EVP_PKEY-pointer))
(define-crypto-func PEM_read_PrivateKey         (_fun _FILE-pointer (_or-null _EVP_PKEY-pointer) (_or-null _pointer) (_or-null _pointer) -> _EVP_PKEY-pointer))

(define-crypto-func BIO_s_file   (_fun                                   -> _BIO_METHOD-pointer))
(define-crypto-func BIO_new_file (_fun _bytes _bytes                     -> _BIO-pointer))
(define-crypto-func BIO_new_fp   (_fun _FILE-pointer _int                -> _BIO-pointer))
(define-crypto-func BIO_free     (_fun _BIO-pointer                      -> _void))
(define-crypto-func BIO_set_fp   (_fun _BIO-pointer _FILE-pointer _int   -> _void))
(define-crypto-func BIO_get_fp   (_fun _BIO-pointer ( _ptr o _FILE-pointer) -> _void))

(define-crypto-func BIO_write_filename (_fun _BIO-pointer _bytes         -> _int))
(define-crypto-func BIO_append_filename (_fun _BIO-pointer _bytes        -> _int))
(define-crypto-func BIO_rw_filename (_fun _BIO-pointer _bytes            -> _int))

(define-crypto-func MD5_Init           (_fun _MD5_CTX-pointer                    -> _int))
(define-crypto-func MD5_Update         (_fun _MD5_CTX-pointer _bytes _long       -> _int))
(define-crypto-func MD5_Final          (_fun (_bytes o EVP_MAX_MD_SIZE) _MD5_CTX-pointer    -> _int))
(define-crypto-func MD5                (_fun _bytes _long (_ptr i _bytes)        -> _int))
(define-crypto-func MD5_Transform      (_fun _MD5_CTX-pointer _bytes             -> _void))
(define-crypto-func SHA1_Init          (_fun _SHA1_CTX-pointer                   -> _int))
(define-crypto-func SHA1_Update        (_fun _SHA1_CTX-pointer _bytes _long      -> _int))
(define-crypto-func SHA1_Final         (_fun (_bytes o EVP_MAX_MD_SIZE) _SHA1_CTX-pointer   -> _int))
(define-crypto-func SHA1               (_fun _bytes _long (_ptr i _bytes)        -> _int))
(define-crypto-func SHA1_Transform     (_fun _SHA1_CTX-pointer _bytes            -> _void))
(define-crypto-func SHA256_Init        (_fun _SHA256_CTX-pointer                 -> _int))
(define-crypto-func SHA256_Update      (_fun _SHA256_CTX-pointer _bytes _long    -> _int))

(define-crypto-func SHA256_Final       (_fun _bytes _SHA256_CTX-pointer -> _int))
(define-crypto-func SHA256             (_fun _bytes _long (_ptr i _bytes)        -> _int))
(define-crypto-func SHA256_Transform   (_fun _SHA256_CTX-pointer _bytes          -> _void))

(define-crypto-func RSA_sign   (_fun _int _bytes _int _bytes (_ptr io _int) _RSA-pointer -> _int))
(define-crypto-func RSA_verify (_fun _int _bytes _int _bytes _int _RSA-pointer           -> _int))
(define-crypto-func RSA_size   (_fun _RSA-pointer           -> _int))

(define-crypto-func EVP_MD_CTX_init    (_fun _EVP_MD_CTX-pointer                 -> _void))
(define-crypto-func EVP_MD_CTX_create  (_fun                                     -> _EVP_MD_CTX-pointer))

(define-crypto-func EVP_DigestInit_ex   (_fun _EVP_MD_CTX-pointer _EVP_MD-pointer _ENGINE-pointer -> _int))
(define-crypto-func EVP_DigestUpdate    (_fun _EVP_MD_CTX-pointer _bytes _long                    -> _int))
(define-crypto-func EVP_DigestFinal_ex  (_fun _EVP_MD_CTX-pointer _bytes (_ptr io _int)           -> _int))
(define-crypto-func EVP_DigestInit      (_fun _EVP_MD_CTX-pointer _EVP_MD-pointer                 -> _int))
(define-crypto-func EVP_DigestFinal     (_fun _EVP_MD_CTX-pointer _bytes (_ptr io _int)           -> _int))

(define-crypto-func EVP_MD_CTX_cleanup  (_fun _EVP_MD_CTX-pointer -> _int))
(define-crypto-func EVP_MD_CTX_destroy  (_fun _EVP_MD_CTX-pointer -> _void))

(define-crypto-func EVP_MD_CTX_copy_ex  (_fun _EVP_MD_CTX-pointer _EVP_MD_CTX-pointer -> _int))
(define-crypto-func EVP_MD_CTX_copy     (_fun _EVP_MD_CTX-pointer _EVP_MD_CTX-pointer -> _int))

; #define EVP_MAX_MD_SIZE (16+20) /* The SSLv3 md5+sha1 type */

; #define EVP_MD_type(e)                 ((e)->type)
; #define EVP_MD_pkey_type(e)            ((e)->pkey_type)
; #define EVP_MD_size(e)                 ((e)->md_size)
; #define EVP_MD_block_size(e)           ((e)->block_size)

; #define EVP_MD_CTX_md(e)               (e)->digest)
; #define EVP_MD_CTX_size(e)             EVP_MD_size((e)->digest)
; #define EVP_MD_CTX_block_size(e)       EVP_MD_block_size((e)->digest)
; #define EVP_MD_CTX_type(e)             EVP_MD_type((e)->digest)

(define-crypto-func EVP_md_null   (_fun -> _EVP_MD-pointer))
(define-crypto-func EVP_md2       (_fun -> _EVP_MD-pointer))
(define-crypto-func EVP_md5       (_fun -> _EVP_MD-pointer))
(define-crypto-func EVP_sha       (_fun -> _EVP_MD-pointer))
(define-crypto-func EVP_sha1      (_fun -> _EVP_MD-pointer))
(define-crypto-func EVP_dss       (_fun -> _EVP_MD-pointer))
(define-crypto-func EVP_dss1      (_fun -> _EVP_MD-pointer))
(define-crypto-func EVP_mdc2      (_fun -> _EVP_MD-pointer))
(define-crypto-func EVP_ripemd160 (_fun -> _EVP_MD-pointer))

(define-crypto-func EVP_get_digestbyname (_fun _bytes -> _EVP_MD-pointer ))
; #define EVP_get_digestbynid(a) EVP_get_digestbyname(OBJ_nid2sn(a))
; #define EVP_get_digestbyobj(a) EVP_get_digestbynid(OBJ_obj2nid(a))

;(define-crypto-func EVP_SignInit_ex (_fun _EVP_MD_CTX-pointer _EVP_MD-pointer _ENGINE-pointer -> _int))
;(define-crypto-func EVP_SignUpdate  (_fun _EVP_MD_CTX-pointer _bytes _int                     -> _int))
(define-crypto-func EVP_SignFinal   (_fun _EVP_MD_CTX-pointer _bytes (_ptr io _int) _EVP_PKEY-pointer -> _int))
 
;(define-crypto-func EVP_SignInit    (_fun _EVP_MD_CTX-pointer _EVP_MD-pointer                 -> _void))

(define-crypto-func HMAC          (_fun _EVP_MD-pointer _bytes _int _bytes _int _bytes (_ptr io _int) -> _bytes))
(define-crypto-func HMAC_CTX_init (_fun _HMAC_CTX-pointer -> _void))
(define-crypto-func HMAC_Init     (_fun _HMAC_CTX-pointer _bytes _int _EVP_MD-pointer -> _void))
(define-crypto-func HMAC_Init_ex  (_fun _HMAC_CTX-pointer _bytes _int (_or-null _EVP_MD-pointer) (_or-null _ENGINE-pointer) -> _void))
(define-crypto-func HMAC_Update   (_fun _HMAC_CTX-pointer _bytes _int -> _void))
(define-crypto-func HMAC_Final    (_fun _HMAC_CTX-pointer _bytes (_ptr io _int) -> _void))
(define-crypto-func HMAC_CTX_cleanup (_fun _HMAC_CTX-pointer -> _void))
(define-crypto-func HMAC_cleanup     (_fun _HMAC_CTX-pointer -> _void))

(define-crypto-func EVP_PKEY_new         (_fun                       -> _EVP_PKEY-pointer))
(define-crypto-func EVP_PKEY_free        (_fun _EVP_PKEY-pointer     -> _void))
(define-crypto-func EVP_PKEY_set1_RSA    (_fun _EVP_PKEY-pointer _RSA-pointer    -> _int))
(define-crypto-func EVP_PKEY_set1_DSA    (_fun _EVP_PKEY-pointer _DSA-pointer    -> _int))
(define-crypto-func EVP_PKEY_set1_DH     (_fun _EVP_PKEY-pointer _DH-pointer     -> _int))
(define-crypto-func EVP_PKEY_set1_EC_KEY (_fun _EVP_PKEY-pointer _EC_KEY-pointer -> _int))

(define-crypto-func EVP_PKEY_get1_RSA    (_fun _EVP_PKEY-pointer -> _RSA-pointer))
(define-crypto-func EVP_PKEY_get1_DSA    (_fun _EVP_PKEY-pointer -> _DSA-pointer))
(define-crypto-func EVP_PKEY_get1_DH     (_fun _EVP_PKEY-pointer -> _DH-pointer))
(define-crypto-func EVP_PKEY_get1_EC_KEY (_fun _EVP_PKEY-pointer -> _EC_KEY-pointer))

(define-crypto-func EVP_PKEY_assign_RSA    (_fun _EVP_PKEY-pointer _RSA-pointer    -> _int))
(define-crypto-func EVP_PKEY_assign_DSA    (_fun _EVP_PKEY-pointer _DSA-pointer    -> _int))
(define-crypto-func EVP_PKEY_assign_DH     (_fun _EVP_PKEY-pointer _DH-pointer     -> _int))
(define-crypto-func EVP_PKEY_assign_EC_KEY (_fun _EVP_PKEY-pointer _EC_KEY-pointer -> _int))

(define-crypto-func EVP_PKEY_type (_fun _int -> _int))
(define-crypto-func EVP_PKEY_size (_fun _EVP_PKEY-pointer -> _int))

(define-crypto-func EVP_CIPHER_CTX_init (_fun _EVP_CIPHER_CTX-pointer -> _void))
(define-crypto-func EVP_CIPHER_CTX_cleanup (_fun _EVP_CIPHER_CTX-pointer  -> _int))

(define-crypto-func EVP_CIPHER_CTX_new (_fun -> _EVP_CIPHER_CTX-pointer))
(define-crypto-func EVP_CIPHER_CTX_free (_fun _EVP_CIPHER_CTX-pointer -> _void))

(define-crypto-func EVP_CIPHER_CTX_set_padding (_fun  _EVP_CIPHER_CTX-pointer _int -> _int))
(define-crypto-func EVP_CIPHER_CTX_set_key_length (_fun  _EVP_CIPHER_CTX-pointer _int -> _int))
(define-crypto-func EVP_CIPHER_CTX_ctrl (_fun _EVP_CIPHER_CTX-pointer _int _int _pointer -> _int))

(define-crypto-func EVP_CIPHER_CTX_block_size (_fun _EVP_CIPHER_CTX-pointer -> _int))
(define-crypto-func EVP_CIPHER_CTX_key_length (_fun _EVP_CIPHER_CTX-pointer -> _int))
(define-crypto-func EVP_CIPHER_CTX_iv_length  (_fun _EVP_CIPHER_CTX-pointer -> _int))

(define-crypto-func EVP_EncryptInit_ex (_fun _EVP_CIPHER_CTX-pointer _EVP_CIPHER-pointer (_or-null _ENGINE-pointer) (_or-null (_ptr i _bytes)) (_or-null (_ptr i _bytes)) -> _int))
(define-crypto-func EVP_EncryptUpdate (_fun _EVP_CIPHER_CTX-pointer _bytes (_ptr io _int) _bytes _int -> _int))
(define-crypto-func EVP_EncryptFinal_ex (_fun _EVP_CIPHER_CTX-pointer _bytes (_ptr io _int) -> _int))

(define-crypto-func EVP_DecryptInit_ex (_fun _EVP_CIPHER_CTX-pointer _EVP_CIPHER-pointer (_or-null _ENGINE-pointer) (_or-null (_ptr i _bytes)) (_or-null (_ptr i _bytes)) -> _int))
(define-crypto-func EVP_DecryptUpdate (_fun _EVP_CIPHER_CTX-pointer _bytes (i : (_ptr o _int)) _bytes _int -> (i2 : _int) -> (values i2 i)))
(define-crypto-func EVP_DecryptFinal_ex (_fun _EVP_CIPHER_CTX-pointer _bytes (i : (_ptr o _int)) -> (i2 : _int) -> (values i2 i)))

(define-crypto-func EVP_CipherInit_ex (_fun _EVP_CIPHER_CTX-pointer _EVP_CIPHER-pointer (_or-null _ENGINE-pointer) (_or-null (_ptr i _bytes)) (_or-null (_ptr i _bytes)) _int -> _int))
(define-crypto-func EVP_CipherUpdate (_fun _EVP_CIPHER_CTX-pointer _bytes (_ptr io _int) _bytes _int -> _int))
(define-crypto-func EVP_CipherFinal_ex (_fun _EVP_CIPHER_CTX-pointer _bytes (_ptr io _int) -> _int))

(define-crypto-func EVP_EncryptInit (_fun _EVP_CIPHER_CTX-pointer _EVP_CIPHER-pointer _bytes _bytes -> _int))
(define-crypto-func EVP_EncryptFinal (_fun _EVP_CIPHER_CTX-pointer _bytes (_ptr io _int) -> _int))

(define-crypto-func EVP_DecryptInit (_fun _EVP_CIPHER_CTX-pointer _EVP_CIPHER-pointer _bytes _bytes -> _int))
(define-crypto-func EVP_DecryptFinal (_fun _EVP_CIPHER_CTX-pointer _bytes (_ptr io _int) -> _int))

(define-crypto-func EVP_CipherInit (_fun _EVP_CIPHER_CTX-pointer _EVP_CIPHER-pointer _bytes _bytes _int -> _int))
(define-crypto-func EVP_CipherFinal (_fun _EVP_CIPHER_CTX-pointer _bytes (_ptr io _int) -> _int))

(define-crypto-func EVP_get_cipherbyname (_fun _bytes -> _EVP_CIPHER-pointer))
;#define EVP_get_cipherbynid(a) EVP_get_cipherbyname(OBJ_nid2sn(a))
;#define EVP_get_cipherbyobj(a) EVP_get_cipherbynid(OBJ_obj2nid(a))

;#define EVP_CIPHER_nid(e)              ((e)->nid)
;#define EVP_CIPHER_block_size(e)       ((e)->block_size)
;#define EVP_CIPHER_key_length(e)       ((e)->key_len)
;#define EVP_CIPHER_iv_length(e)                ((e)->iv_len)
;#define EVP_CIPHER_flags(e)            ((e)->flags)
;#define EVP_CIPHER_mode(e)             ((e)->flags) & EVP_CIPH_MODE)
(define-crypto-func EVP_CIPHER_type (_fun _EVP_CIPHER-pointer -> _int))

;#define EVP_CIPHER_CTX_cipher(e)       ((e)->cipher)
;#define EVP_CIPHER_CTX_nid(e)          ((e)->cipher->nid)
;#define EVP_CIPHER_CTX_block_size(e)   ((e)->cipher->block_size)
;#define EVP_CIPHER_CTX_key_length(e)   ((e)->key_len)
;#define EVP_CIPHER_CTX_iv_length(e)    ((e)->cipher->iv_len)
;#define EVP_CIPHER_CTX_get_app_data(e) ((e)->app_data)
;#define EVP_CIPHER_CTX_set_app_data(e,d) ((e)->app_data=(char *)(d))
;#define EVP_CIPHER_CTX_type(c)         EVP_CIPHER_type(EVP_CIPHER_CTX_cipher(c))
;#define EVP_CIPHER_CTX_flags(e)                ((e)->cipher->flags)
;#define EVP_CIPHER_CTX_mode(e)         ((e)->cipher->flags & EVP_CIPH_MODE)

(define-crypto-func EVP_CIPHER_param_to_asn1 (_fun _EVP_CIPHER_CTX-pointer _ASN1_TYPE-pointer -> _int)) 
(define-crypto-func EVP_CIPHER_asn1_to_param (_fun _EVP_CIPHER_CTX-pointer _ASN1_TYPE-pointer -> _int))


(define-crypto-func EVP_aes_128_cbc (_fun -> _EVP_CIPHER-pointer))

(define-syntax-rule (define-ciphers a ...)
  (begin
    (define-crypto-func a (_fun -> _EVP_CIPHER-pointer)) ...))

(define-ciphers 
EVP_enc_null         
EVP_des_cbc          
EVP_des_ecb          
EVP_des_cfb          
EVP_des_ofb          
EVP_des_ede_cbc      
EVP_des_ede          
EVP_des_ede_ofb      
EVP_des_ede_cfb      
EVP_des_ede3_cbc     
EVP_des_ede3         
EVP_des_ede3_ofb     
EVP_des_ede3_cfb     
EVP_desx_cbc         
EVP_rc4              
EVP_rc4_40           
EVP_idea_cbc         
EVP_idea_ecb         
EVP_idea_cfb         
EVP_idea_ofb         
EVP_rc2_cbc          
EVP_rc2_ecb          
EVP_rc2_cfb          
EVP_rc2_ofb          
EVP_rc2_40_cbc       
EVP_rc2_64_cbc       
EVP_bf_cbc           
EVP_bf_ecb           
EVP_bf_cfb           
EVP_bf_ofb           
EVP_cast5_cbc        
EVP_cast5_ecb        
EVP_cast5_cfb        
EVP_cast5_ofb        
EVP_rc5_32_12_16_cbc 
EVP_rc5_32_12_16_ecb 
EVP_rc5_32_12_16_cfb 
EVP_rc5_32_12_16_ofb 
EVP_aes_128_ecb      
;EVP_aes_128_cbc      
EVP_aes_128_cfb1     
EVP_aes_128_cfb8     
EVP_aes_128_cfb128   
EVP_aes_128_ofb      
EVP_aes_192_ecb      
EVP_aes_192_cbc      
EVP_aes_192_cfb1     
EVP_aes_192_cfb8     
EVP_aes_192_cfb128
EVP_aes_192_ofb
EVP_aes_256_ecb
EVP_aes_256_cbc
EVP_aes_256_cfb1
EVP_aes_256_cfb8
EVP_aes_256_cfb128
EVP_aes_256_ofb)

(define EVP_aes_128_cfb EVP_aes_128_cfb128)
(define EVP_aes_192_cfb EVP_aes_192_cfb128)
(define EVP_aes_256_cfb EVP_aes_256_cfb128)

(define (sha1-rsa-signature/fn fn b)
  (let ([db (make-bytes EVP_MAX_MD_SIZE)]
        [dl EVP_MAX_MD_SIZE]
        [ctx (EVP_MD_CTX_create)])
    (EVP_DigestInit ctx (EVP_sha1))
    (EVP_DigestUpdate ctx b (bytes-length b))
    (EVP_DigestFinal ctx db dl)
    (define digest (subbytes db 0 20))
    (define pk (fn->RSAPrivateKey fn))
    (define sl (RSA_size pk))
    (define sb (make-bytes sl))
    (RSA_sign NID_sha1 digest (bytes-length digest) sb sl pk)
    (subbytes sb 0 sl)))

(define (sha1-rsa-signature b key)
  (let ([digest (make-bytes EVP_MAX_MD_SIZE)]
        [dl EVP_MAX_MD_SIZE]
        [ctx (EVP_MD_CTX_create)])
    (EVP_DigestInit ctx (EVP_sha1))
    (EVP_DigestUpdate ctx b (bytes-length b))
    (EVP_SignFinal ctx digest dl key)
    (subbytes digest 0 dl)))

(define (fn->EVP_PKEY-private fn)
  (define bio #f)
  (dynamic-wind
    (lambda () (set! bio (BIO_new_file (->bytes fn) #"r")))
    (lambda () (PEM_read_bio_PrivateKey bio #f #f #f))
    (lambda () (BIO_free bio))))

(define (fn->RSAPrivateKey fn)
  (define bio #f)
  (dynamic-wind
    (lambda () (set! bio (BIO_new_file (->bytes fn) #"r")))
    (lambda () (PEM_read_bio_RSAPrivateKey bio #f #f #f))
    (lambda () (BIO_free bio))))

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
        [result (make-bytes SHA256_DIGEST_LENGTH)])
    (SHA256_Init ctx)
    (for ([x lst]) 
      (SHA256_Update ctx x (bytes-length x)))
    (SHA256_Final result ctx)
    result))


(define (->bytes x)
  (cond [(string? x) (string->bytes/locale x)]
        [(bytes? x) x]
        [(number? x) (integer->integer-bytes x 4 #f #t)]))
(define (BN_num_bytes bn)
  (ceiling (/ (+ (BN_num_bits bn) 7) 8)))

(define (build-ssh-bin b)
  (define bl (bytes-length b))
  (if (not (= 0 (bitwise-and #x80 (bytes-ref b 0))))
    (bytes-append (->bytes (+ bl 1)) (bytes 0) b)
    (bytes-append (->bytes bl) b)))

(define (build-ssh-bn bn)
  (define b (make-bytes (BN_num_bytes bn) 0))
  (define bl (BN_bn2bin bn b))
  (build-ssh-bin (subbytes b 0 bl)))

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
  ;(printf "~a ~a ~a\n" bits-needed bits-needed*2 pbits)
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
      (loop)
      #t)))

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
  ;(printf "publ ") (BNp (DH-pub_key dh))
  ;(printf "priv ") (BNp (DH-priv_key dh))
  ;(printf "p    ") (BNp (DH-p dh))
  (BN_sub tmp (DH-p dh) (BN_value_one))
  ;(printf "p-1  ") (BNp tmp)
  ;(printf "cmp pub tmp ~a\n" (BN_cmp pub tmp))
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
    ;(eprintf "bits set ~a/~a\n" pub-bits-set pbits)
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
  (BN_bin2bn peer-public-key (bytes-length peer-public-key) e)
  (set-DH-p! dh p)
  (set-DH-g! dh g)
  (DiffieHellmanGenerateKey dh 20)
#|
  (define bits-needed (cond [(bits-neededx . <= . 128) 1024]
                            [(bits-neededx . <= . 192) 2048]
                            [else 4096]))
|#
  (define shared-secret (make-bytes (DH_size dh)))
  (DH_compute_key shared-secret e dh)
  (values dh (build-ssh-bn (DH-pub_key dh)) shared-secret))