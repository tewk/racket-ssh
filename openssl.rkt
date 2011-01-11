#lang racket/base
(require ffi/unsafe
         racket/runtime-path
         (for-syntax racket/base)
         openssl/sha1)

(provide (struct-out BN)
         (struct-out DH)
         EVP_MAX_MD_SIZE
         SHA1_DIGEST_LENGTH
         SHA256_DIGEST_LENGTH
         NID_sha1
         BNp
         BN_num_bytes)

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
(define HMAC_MAX_MD_CBLOCK 128)
(define NID_sha1 64)
(define SHA1_DIGEST_LENGTH 20)
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

(define-crypto-func PEM_read_bio_RSAPublicKey  (_fun _BIO-pointer (_or-null _RSA-pointer) (_or-null _pointer) (_or-null _pointer)  -> _RSA-pointer))
(define-crypto-func PEM_read_RSAPublicKey      (_fun _FILE-pointer _RSA-pointer _pointer _pointer -> _RSA-pointer))
(define-crypto-func PEM_read_bio_PublicKey     (_fun _BIO-pointer (_or-null _EVP_PKEY-pointer) (_or-null _pointer) (_or-null _pointer) -> _EVP_PKEY-pointer))
(define-crypto-func PEM_read_PublicKey         (_fun _FILE-pointer (_or-null _EVP_PKEY-pointer) (_or-null _pointer) (_or-null _pointer) -> _EVP_PKEY-pointer))

(define-crypto-func BIO_s_file   (_fun                                   -> _BIO_METHOD-pointer))
(define-crypto-func BIO_new_file (_fun _bytes _bytes                     -> _BIO-pointer))
(define-crypto-func BIO_new_fp   (_fun _FILE-pointer _int                -> _BIO-pointer))
(define-crypto-func BIO_new_mem_buf   (_fun _bytes _int                  -> _BIO-pointer))
(define-crypto-func BIO_free     (_fun _BIO-pointer                      -> _void))
(define-crypto-func BIO_set_fp   (_fun _BIO-pointer _FILE-pointer _int   -> _void))
(define-crypto-func BIO_get_fp   (_fun _BIO-pointer ( _ptr o _FILE-pointer) -> _void))

(define-crypto-func BIO_write_filename (_fun _BIO-pointer _bytes         -> _int))
(define-crypto-func BIO_append_filename (_fun _BIO-pointer _bytes        -> _int))
(define-crypto-func BIO_rw_filename (_fun _BIO-pointer _bytes            -> _int))

(define-crypto-func MD5_Init           (_fun _MD5_CTX-pointer                    -> _int))
(define-crypto-func MD5_Update         (_fun _MD5_CTX-pointer _bytes _long       -> _int))
(define-crypto-func MD5_Final          (_fun _bytes _MD5_CTX-pointer             -> _int))
(define-crypto-func MD5                (_fun _bytes _long (_ptr i _bytes)        -> _int))
(define-crypto-func MD5_Transform      (_fun _MD5_CTX-pointer _bytes             -> _void))
(define-crypto-func SHA1_Init          (_fun _SHA1_CTX-pointer                   -> _int))
(define-crypto-func SHA1_Update        (_fun _SHA1_CTX-pointer _bytes _long      -> _int))
(define-crypto-func SHA1_Final         (_fun _bytes _SHA1_CTX-pointer            -> _int))
(define-crypto-func SHA1               (_fun _bytes _long (_ptr i _bytes)        -> _int))
(define-crypto-func SHA1_Transform     (_fun _SHA1_CTX-pointer _bytes            -> _void))
(define-crypto-func SHA256_Init        (_fun _SHA256_CTX-pointer                 -> _int))
(define-crypto-func SHA256_Update      (_fun _SHA256_CTX-pointer _bytes _long    -> _int))

(define-crypto-func SHA256_Final       (_fun _bytes _SHA256_CTX-pointer          -> _int))
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
(define-crypto-func EVP_MD_block_size   (_fun _EVP_MD-pointer -> _int))
(define-crypto-func EVP_MD_size         (_fun _EVP_MD-pointer -> _int))
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
(define-crypto-func HMAC_Final    (_fun _HMAC_CTX-pointer _bytes (i : (_ptr o _int)) -> _void -> i))
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
(define-crypto-func EVP_CipherUpdate (_fun _EVP_CIPHER_CTX-pointer _bytes (ol : (_ptr o _int)) _bytes _int -> (rc : _int) -> (values rc ol)))
(define-crypto-func EVP_CipherFinal_ex (_fun _EVP_CIPHER_CTX-pointer _bytes (ol : (_ptr o _int)) -> (rc : _int) -> (values rc ol)))

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

(define-syntax-rule (for/sum ([a b]...) body ...)
  (for/fold ([sum 0]) ([a b]...)
    (+ sum (begin body ...)))) 

(define (BNp bn)
  (define bits-set (for/sum ([i (in-range (BN_num_bits bn))]) (BN_is_bit_set bn i)))
  (define b (make-bytes (BN_num_bytes bn) 0))
  (define bl (BN_bn2bin bn b))
  (printf "~a ~a ~a ~a ~a/~a\n" (BN-top bn) (BN-dmax bn) (BN-neg bn) (BN-flags bn) bits-set (BN_num_bits bn))
  (printf "~a\n" (bytes->hex-string (subbytes b 0 bl))))

(define (BN_num_bytes bn)
  (ceiling (/ (+ (BN_num_bits bn) 7) 8)))
