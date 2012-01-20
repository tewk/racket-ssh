#lang racket/base
(require racket/class
         racket/match
         "utils.rkt"
         "constants.rkt"
         "session.rkt"
         (for-syntax racket/base)
         racket/date
         (only-in srfi/13 string-prefix-length))
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

(define NDX_DONE         -1)
(define NDX_FLIST_EOF    -2)
(define NDX_DEL_STATS    -3)
(define NDX_FLIST_OFFSET -101)

;/* For use by the itemize_changes code */                                                                     
(define ITEM_REPORT_ATIME       (arithmetic-shift 1 0))
(define ITEM_REPORT_CHANGE      (arithmetic-shift 1 1))
(define ITEM_REPORT_SIZE        (arithmetic-shift 1 2)) ;/* regular files only */
(define ITEM_REPORT_TIMEFAIL    (arithmetic-shift 1 2)) ;/* symlinks only */
(define ITEM_REPORT_TIME        (arithmetic-shift 1 3))
(define ITEM_REPORT_PERMS       (arithmetic-shift 1 4))
(define ITEM_REPORT_OWNER       (arithmetic-shift 1 5))
(define ITEM_REPORT_GROUP       (arithmetic-shift 1 6))
(define ITEM_REPORT_ACL         (arithmetic-shift 1 7))
(define ITEM_REPORT_XATTR       (arithmetic-shift 1 8))
(define ITEM_BASIS_TYPE_FOLLOWS (arithmetic-shift 1 11))
(define ITEM_XNAME_FOLLOWS      (arithmetic-shift 1 12))
(define ITEM_IS_NEW             (arithmetic-shift 1 13))
(define ITEM_LOCAL_CHANGE       (arithmetic-shift 1 14))
(define ITEM_TRANSFER           (arithmetic-shift 1 15))
;(* These are outside the range of the transmitted flags. */                                                   
(define ITEM_MISSING_DATA       (arithmetic-shift 1 16)) ;/* used by log_formatted() */
(define ITEM_DELETED            (arithmetic-shift 1 17)) ;/* used by log_formatted() */
(define ITEM_MATCHED            (arithmetic-shift 1 18)) ;/* used by itemize() */

#|
;          0000 0001  TOP_DIR
;          0000 0010  SAME_MODE
;          0000 0100  EXTENDED_FLAGS
;          0000 1000  SAME_UID
;          0001 0000  SAME_GID
;          0010 0000  SAME_NAME
;          0100 0000  LONG_NAME
;          1000 0000  SAME_TIME
;     0001 0000 0000  RDEV_MAHOR
;
;0000 0000 0001 1000
|#

#|
           S_IFMT     0170000   bit mask for the file type bit fields
           S_IFSOCK   0140000   socket
           S_IFLNK    0120000   symbolic link
           S_IFREG    0100000   regular file
           S_IFBLK    0060000   block device
           S_IFDIR    0040000   directory
           S_IFCHR    0020000   character device
           S_IFIFO    0010000   FIFO
           S_ISUID    0004000   set UID bit
           S_ISGID    0002000   set-group-ID bit (see below)
           S_ISVTX    0001000   sticky bit (see below)
           S_IRWXU    00700     mask for file owner permissions
           S_IRUSR    00400     owner has read permission
           S_IWUSR    00200     owner has write permission
           S_IXUSR    00100     owner has execute permission
           S_IRWXG    00070     mask for group permissions
           S_IRGRP    00040     group has read permission
           S_IWGRP    00020     group has write permission
           S_IXGRP    00010     group has execute permission
           S_IRWXO    00007     mask for permissions for others (not in group)
           S_IROTH    00004     others have read permission
           S_IWOTH    00002     others have write permission
           S_IXOTH    00001     others have execute permission
|#
;000 000 000
; 1000 0001 1010 0100
;81 a4

(define (islink? mode)
  (bitwise-and #x1 mode))

(define (vax->int32 x) (integer-bytes->integer x #t #f))
(define (vax->int16 x) (integer-bytes->integer x #t #f))
(define (vax->uint32 x) (integer-bytes->integer x #f #f))
(define (uint64->vax x) (integer->integer-bytes x 8 #f #f))
(define (uint32->vax x) (integer->integer-bytes x 4 #f #f))
(define (int32->vax x) (integer->integer-bytes x 4 #t #f))
(define (uint16->vax x) (integer->integer-bytes x 2 #f #f))
(define MAXPATHLEN 255)

(define-syntax-rule (let/ccc k body ...)
  (call-with-composable-continuation (lambda (k) body ...)))

(define-syntax (define-flag-pred stx)
  (syntax-case stx ()
    [(_ flag)
    (with-syntax ([name (string->symbol (string-append "is-" (symbol->string (syntax->datum #'flag)) "?"))])
      #'(define (name f) (not (= 0 (bitwise-and f flag)))))]))

(define FERROR_XFER 1)
(define FINFO 2)
(define FERROR 3)
(define FWARNING 4)
(define FERROR_SOCKET 5)
(define FERROR_UTF8 8)
(define FLOG 6)
(define FCLIENT 7)

(define MPLEX_BASE 7)
(define MSG_DATA (+ 0 MPLEX_BASE )) ;/* raw data on the multiplexed stream */
(define MSG_ERROR_XFER FERROR_XFER) ; 
(define MSG_INFO FINFO) ; /* remote logging */                                      
(define MSG_ERROR FERROR) ;
(define MSG_WARNING FWARNING) ; /* protocol-30 remote logging */                              
(define MSG_ERROR_SOCKET FERROR_SOCKET) ; /* sibling logging */                                                 
(define MSG_ERROR_UTF8 FERROR_UTF8) ; /* sibling logging */                                                     
(define MSG_LOG FLOG) ; 
(define MSG_CLIENT FCLIENT) ; /* sibling logging */                                               
(define MSG_REDO 9) ;/* reprocess indicated flist index */                                                 
(define MSG_STATS 10) ;   /* message has stats data for generator */                                            
(define MSG_IO_ERROR 22) ;/* the sending side had an I/O error */                                               
(define MSG_IO_TIMEOUT 33) ;/* tell client about a daemon's timeout value */                                    
(define MSG_NOOP 42) ;    /* a do-nothing message (legacy protocol-30 only) */                                  
(define MSG_ERROR_EXIT 86) ; /* synchronize an error exit (siblings and protocol >  31) */                      
(define MSG_SUCCESS 100) ;/* successfully updated indicated flist index */                                      
(define MSG_DELETED 101) ;/* successfully deleted a file on receiving side */                                   
(define MSG_NO_SEND 102) ;/* sender failed to open a file we wanted */   

(define rsync-session%
  (class session%
  (init-field [upgrade-session #f])
  (field [server #f])
  (field [sender #t])
  (field [k (box #f)])
  (field [k2 #f])
  (field [protocol-version 0])
  (field [rs-r-ndx-pos -1])
  (field [rs-r-ndx-neg 1])
  (field [rs-w-ndx-pos -1])
  (field [rs-w-ndx-neg 1])
  (inherit-field in)
  (inherit-field io)
  (inherit-field out)
  (define-values (pi po) (make-pipe))
  (define-values (opi opo) (make-pipe))
  (define-values (osbi osbo) (make-pipe))
  (define-values (isbi isbo) (make-pipe))
  (inherit send-data)
  (define/public (send-data2 data) 
    (printf "DATAOUT:~a\n" (bytes->hex-string data))
    (send-data data))

  (define (raw-write-uint32 x) (send-data2 (uint32->vax x)))
  (define (raw-write-byte x) (send-data2 (bytes x)))
  (define (raw-read-uint32) (integer-bytes->integer (read-s-bytes 4) #f #f))


  ;rsync stream functions
  (define (rs-flush> x)
    (define bsl (pipe-content-length osbi))
    (cond
      [(bsl . > . x)
       (define nbsl (min #xffffff bsl))
       (define type-length (bitwise-ior (arithmetic-shift MSG_DATA 24) nbsl))
       (send-data2 (bytes-append (uint32->vax type-length) (read-bytes nbsl osbi)))]))
  (define (rs-flush) (rs-flush> 0))

  (define (rs-read-bytes ln)
    (let loop ()
      (define bsl (pipe-content-length isbi))
      (cond
        [(ln . <= . bsl) (read-bytes ln isbi)]
        [else
          (rs-flush)
          (define type-length (raw-read-uint32))
          (define l (bitwise-and #xffffff type-length))
          (define t (arithmetic-shift type-length -24))
          (define data (read-s-bytes l))
          (cond 
            [(= t MSG_DATA)
             (write-bytes data isbo)
             (loop)]
            [else
              (raise "Opps")])])))

  (define (rs-write-bytes bs)
    (write-bytes bs osbo)
    (rs-flush> 4095))
  (define (rs-write-string s) (rs-write-bytes (string->bytes/utf-8 s)))

  (define (rs-read-uint32)    (vax->uint32 (rs-read-bytes 4)))
  (define (rs-read-int32)     (vax->int32 (rs-read-bytes 4)))
  (define (rs-read-int16)     (vax->int16 (rs-read-bytes 2)))
  (define (rs-read-byte/str)  (rs-read-bytes 1))
  (define (rs-read-byte)      (bytes-ref (rs-read-bytes 1) 0))
  (define (write-uint64 x)    (rs-write-bytes (uint64->vax x)))
  (define (rs-write-uint32 x) (rs-write-bytes (uint32->vax x)))
  (define (rs-write-int32 x)  (rs-write-bytes (int32->vax x)))
  (define (rs-write-uint16 x) (rs-write-bytes (uint16->vax x)))
  (define (rs-write-byte x)   (rs-write-bytes (bytes x)))

  (define (read-sum-head)
    (define csum-length 0)
    (define sum-count (rs-read-int32))
    (when (sum-count . < . 0)
      (printf "Invalid checksum count ~a [~a]\n" sum-count "ME")
      (exit 1))
    (define sum-blength (rs-read-int32))
    (when (or (0 . > . sum-blength) (sum-blength . > . max-length))
      (printf "Invalid block length ~a [~a]\n" sum-blength "ME")
      (exit 1))
    (define sum-s2length
      (p<27
        [csum-length]
        [(rs-read-int32)]))
    (when (or (0 . > . sum-s2length) (sum-s2length . > . max-length))
      (printf "Invalid checksum length ~a [~a]\n" sum-s2length "ME")
      (exit 1))
    (define sum-remainder (rs-read-int32))
    (when (or (0 . > . sum-remainder) (sum-remainder . > . sum-blength))
      (printf "Invalid remainder length ~a [~a]\n" sum-count "ME")
      (exit 1))
    (list sum-count sum-blength sum-s2length sum-remainder))

  (define (write-sum-head _sum)
    (define sum (or _sum (sum 0 0 0 0 0)))
    (rs-write-int32 (sum-count sum))
    (rs-write-int32 (sum-blength sum))
    (wp>=27
      (rs-write-int32 (sum-s2length sum)))
    (rs-write-int32 (sum-remainder sum)))

      



  ; Receive a file-list index using a byte reduction method
  (define (rs-read-ndx)
    (p>=30
      [(define (update-return num prev-sel)
         (cond
           [prev-sel
             (set! rs-r-ndx-pos num)
             num]
           [else
             (set! rs-r-ndx-neg num)
             (- num)]))

       (define (add-in-prev num prev-sel)
         (cond 
           [prev-sel (+ num rs-r-ndx-pos)]
           [else (+ num rs-r-ndx-neg)]))

       (define (read-rest b prev-sel)
         (cond 
           [(= b #xfe)
            (define bs (rs-read-bytes 2))
            (cond
              [(bitwise-and #x80 (bytes-ref bs 0))
               (define bs2 (rs-read-bytes 2))
               (define num (bytes (bytes-ref bs 1) (bytes-ref bs2 0) (bytes-ref bs 1) (bitwise-and (bytes-ref bs 0) #x7f)))
               (update-return num prev-sel)
               ]
              [else (update-return (add-in-prev (+ (arithmetic-shift (bytes-ref bs 0) 8) (bytes-ref bs 1))
                                               prev-sel) 
                                   prev-sel)])]
           [else
             (update-return (add-in-prev b prev-sel) prev-sel)]))


       (define b (rs-read-byte))
       (cond 
         [(= b 0) NDX_DONE]  ;done
         [(= b #xff) (read-rest (rs-read-byte) #f) ] ;negative offset
         [else (read-rest b #t)])] ;positive offset
      [(rs-read-int32)]))


  (define (rs-write-ndx ndx)
    (p>=30
      [
       (define (send-diff diff) 
         (cond 
           [(< 0 diff #xfe)
            (rs-write-byte diff)]
           [(or (< diff 0) (> diff #x7ffff))
            (rs-write-bytes (bytes
                              #xfe
                              (bitwise-ior (arithmetic-shift ndx -24) #x80)
                              (bitwise-and ndx #xff)
                              (bitwise-and (arithmetic-shift ndx -8) #xff)
                              (bitwise-and (arithmetic-shift ndx -16) #xff)))]
           [else
            (rs-write-bytes (bytes
                              #xfe
                              (bitwise-and (arithmetic-shift ndx -8) #xff)
                              (bitwise-and ndx #xff)))])
         (void))
       (cond 
         [(= ndx NDX_DONE) (rs-write-byte 0) (void)]  ;done
         [(>= ndx 0) ;positive offset
          (define diff (- ndx rs-w-ndx-pos))
          (set! rs-w-ndx-pos ndx)
          (send-diff diff)]
         [else ;negative offset 
           (rs-write-byte #xff)
           (define diff (- (- ndx) rs-w-ndx-neg))
           (set! rs-w-ndx-neg (- ndx))
           (send-diff diff)])]
      [(rs-write-int32 ndx)]))




  (define/public (read-long-int)
    (define f (rs-read-uint32))
    (cond [(not (= f #xffffffff)) f]
          [else (+ (read-int) (* (read-int) 65536 64436))]))

  (define/public (read-int) (rs-read-uint32))

  (define (highbits x)
    (for/fold ([b 0]) ([i (in-range x 7)])
      (bitwise-ior b (arithmetic-shift 1 i))))
  (define (write-varint x)
    (define b (integer->integer-bytes x 4 #t #f))
    (define cnt (let loop ([c 4])
                  (cond [(and (c . > . 1) (equal? #"\0" (subbytes b (sub1 c) c)))
                         (loop (sub1 c))]
                        [else c])))
    (define bit (arithmetic-shift 1 (add1 (- 7 cnt))))
    (define bs (subbytes 
      (bytes-append
        (cond [((subbytes b (sub1 cnt) cnt) . >= . bit)
               (bytes (highbits (add1 (- 7 cnt))))]
              [(cnt . > . 1) (bytes (bitwise-ior (subbytes b (sub1 cnt) cnt)
                                              (highbits (+ 2 (- 7 cnt)))))]
              [else (subbytes b (sub1 cnt) 1)])
        b)
      0 cnt))
    (printf "write-varint: ~a\n" (bytes->hex-string bs))
    (rs-write-bytes bs))

  (define (write-varlong x min-bytes)
    (define b (integer->integer-bytes x 8 #t #f))
    (printf "i->ib ~a\n" (bytes->hex-string b))
    (define cnt (let loop ([c 8])
                  (cond [(and (c . > . min-bytes) (equal? #"\0" (subbytes b (sub1 c) c)))
                         (loop (sub1 c))]
                        [else c])))
    (define bit (arithmetic-shift 1 (+ min-bytes(- 7 cnt))))
    (define bitn (- (+ min-bytes(- 7 cnt)) 1))
    (printf "~a ~a ~a\n" (bytes->hex-string (integer->integer-bytes bit 2 #t #f)) bitn cnt)
    (define bs (subbytes 
      (bytes-append
        (cond [((bytes-ref (subbytes b (sub1 cnt) cnt) 0) . >= . bit)
               (bytes (highbits bitn))]
              [(cnt . > . min-bytes) (bytes (bitwise-ior (subbytes b (sub1 cnt) cnt)
                                              (highbits bitn)))]
              [else (subbytes b (sub1 cnt) cnt)])
        b)
      0 cnt))
    (printf "write-varlong: ~a\n" (bytes->hex-string bs))
    (rs-write-bytes bs))


  (define (rs-write-varint30 x)
    (if (protocol-version . < . 30)
      (rs-write-uint32 x)
      (write-varint x)))

  (define (write-varlong30 x min-bytes)
    (if (protocol-version . < . 30)
      (write-uint64 x)
      (write-varlong x min-bytes)))

  (define (buffer-has-n n)
    ((pipe-content-length pi) . >= . n))

  (define fl (list "/home/tewk/macromod.pdf"))

  (define (is-XMIT_EXTENDED_FLAGS? flags) (not (= 0 (bitwise-and flags XMIT_EXTENDED_FLAGS))))
  (define (is-XMIT_SAME_NAME? flags) (not (= 0 (bitwise-and flags XMIT_SAME_NAME))))
  (define (is-XMIT_LONG_NAME? flags) (not (= 0 (bitwise-and flags XMIT_LONG_NAME))))
  (define (is-XMIT_MOD_NSEC? flags) (not (= 0 (bitwise-and flags XMIT_MOD_NSEC))))
  (define (is-XMIT_SAME_MODE? flags) (not (= 0 (bitwise-and flags XMIT_SAME_MODE))))
  (define (is-XMIT_SAME_TIME? flags) (not (= 0 (bitwise-and flags XMIT_SAME_TIME))))
  (define-flag-pred XMIT_SAME_UID)
  (define-flag-pred XMIT_SAME_GID)

  (define-syntax-rule (p>=28 [a ...] [b ...])
    (cond 
      [(protocol-version . >= . 28) a ...]
      [else b ...]))

  (define-syntax-rule (p>=29 [a ...] [b ...])
    (cond 
      [(protocol-version . >= . 29) a ...]
      [else b ...]))

  (define-syntax-rule (p>=30 [a ...] [b ...])
    (cond 
      [(protocol-version . >= . 30) a ...]
      [else b ...]))

  (define-syntax-rule (p<27 [a ...] [b ...])
    (cond 
      [(protocol-version . < . 27) a ...]
      [else b ...]))

  (define-syntax-rule (wp>=30 a ...)
    (when (protocol-version . >= . 30) a ...))

  (struct last-file-info
          (name
           fsize
           uid
           gid
           mode))

  (define (send-file-list fl)
    (define ostr (open-output-bytes))
    (let loop ([fl fl]
               [lfi (last-file-info "" 0 0 0 0)]
               [nfl null])
      (match fl
        [(list) (rs-write-byte 0) (rs-flush) nfl]
        [(list-rest h t)
          (define wholename h)
          (define isfile (file-exists? h))
          (define islink (link-exists? h))
          (define isdirectory (not isfile))
          (define mtime (file-or-directory-modify-seconds h))
          (define fsize (file-size h))
          (define fmod  (file-or-directory-permissions h 'bits))
          (define-values (base name hastrailingslash) (split-path h))
          (define xflags (bitwise-ior XMIT_SAME_UID XMIT_SAME_GID))

          (define name-prefix-match-length 
            (string-prefix-length h (last-file-info-name lfi)))
          (define transmit-name-length (- (string-length h) name-prefix-match-length))

          (define (send-file-flag)
            (p>=28
              [(let* ([f (or (and (not (zero? xflags)) xflags) 
                             (not isdirectory) 
                             (bitwise-ior xflags XMIT_TOP_DIR))])
                 (cond 
                   [(or (not (zero? (bitwise-and xflags #xff00))) (zero? xflags))
                    (rs-write-uint16 (bitwise-ior xflags XMIT_EXTENDED_FLAGS))]
                   [else 
                     (rs-write-byte xflags)]))]
              [(let* ([f (or (and (not (zero? (bitwise-ior xflags #xff)))
                                  xflags)
                             (and isdirectory (bitwise-ior xflags XMIT_LONG_NAME))
                             (bitwise-ior xflags XMIT_TOP_DIR))])
                 (rs-write-byte f))]))

          (define (send-filename)
            (when (is-XMIT_SAME_NAME? xflags)
              (rs-write-byte name-prefix-match-length))
            (if (is-XMIT_LONG_NAME? xflags)
                (rs-write-varint30 transmit-name-length)
                (rs-write-byte transmit-name-length))
            (define name (substring wholename name-prefix-match-length transmit-name-length))
            (printf "~a\n~a\n" name (bytes->hex-string (string->bytes/locale name)))
            (rs-write-string (substring wholename name-prefix-match-length transmit-name-length)))

          (define (send-file-mode)
            (rs-write-uint32 #o100644))

          (send-file-flag)
          (send-filename)
          (write-varlong30 fsize 3)
          (unless (is-XMIT_SAME_TIME? xflags)
            (p>=30
              [(write-varlong mtime 4)]
              [(rs-write-uint32 mtime)]))
          (when (is-XMIT_MOD_NSEC? xflags)
            (write-varint 0))
          (unless (is-XMIT_SAME_MODE? xflags)
            (send-file-mode))
          ;uid
          ;gid
          ;devices
          ;symlink
          ;hardlink2
          ;checksum
          ;(rs-flush)
          (define lfi-new (last-file-info h fsize 0 0 fmod))
          (loop t lfi-new (cons lfi-new nfl))])))

  (struct sum (flength sums count blength remainder s2length))
  (struct sum-buf (offset len sum1 chain flags sum2))
  (define (receive-sums)
    (define-values (count blength s2length remainder) (read-sum-head))
    (define offset 0)
    (define sums
      (for/vector #:length count ([i (in-range count)])
        (define sum1 (rs-read-int32))
        (define sum2 (rs-read-bytes s2length))
        (define len
          (if (and (= i (sub1 count)) (not (= remainder 0)))
              remainder
              blength))
        (begin0
          (sum-buf offset len sum1 0 0 sum2)
          (set! offset (+ offset len)))))

    (sum offset sums count blength remainder s2length))




  (define (send-files)
    (let loop ()
      (define ndx (rs-read-ndx))
      (define iflags 
        (p>=29
        [(rs-read-int16)]
        [(bitwise-ior ITEM_TRANSFER ITEM_MISSING_DATA)]))
      (cond
        [(= ndx NDX_DONE)
      (define sums (recieive-sums))
      (write-ndx-and-attrs ndx iflags)
      (write-sum-head s)
      (match-sums 
      (printf "NDX ~a ~a ~a\n" ndx iflags sh)))

  (define (do-rsync die)
    (when upgrade-session
      (define-values (_io _in _out _iws _mps) (send upgrade-session get-params))
      (set! io  _io) 
      (set! in  _in)
      (set! out _out)
      (set! server #f))

    (define (read-byte-int) (bytes-ref (read-s-byte) 0))
    (define (read-30varuint32) (rs-read-uint32))
    (define (rs-read-varint) (rs-read-uint32))

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
      (define mod-nseconds (if (is-XMIT_MOD_NSEC? flags) (rs-read-varint) 0))
      (define file-mode (if (not (is-XMIT_SAME_MODE? flags)) (rs-read-varint) 0))
      (rs-read-varint)

      (printf "FILENAME ~a ~a ~a\n" file-name file-size (date->string (seconds->date mod-seconds) #t))
      (list file-name file-size mod-seconds file-mode))


    

    (define (negotiate-versions server)
      (define our-version 30)
      (printf "Sending version server:~a sender:~a\n" server sender)
      (send-data2 (uint32->vax our-version))  ;version
      (define peer-version (integer-bytes->integer (read-s-bytes 4) #f #f)) 
      (set! protocol-version (min our-version peer-version))
      (cond 
        [server 
          (wp>=30 (send-data2 (bytes #x0e)))
          (send-data2 (bytes #x46 #xe5 #x59 #x98))]
        [else
          (define readb (p>=30 [(read-s-byte)] [0]))
          (define checksum (read-s-bytes 4))
          (void)])
      )


    (negotiate-versions server)
    (cond 
      [server (void)]
      [else 
        (cond 
          [sender
            ;send-filter-list
            ;(rs-write-uint32 0)
            (rs-flush)
            (send-file-list (list "macromod.pdf"))
            (send-files)
            (let loop ()
              (printf "BYTE ~a\n" (bytes->hex-string (rs-read-byte/str)))
              (loop))
          ]
          [else
            (let loop ([flags (read-flags)]
                       [lastname #""])
              (print-flags flags)
              (when (not (zero? flags))
                (define fi (read-file-metadata flags lastname))
                (loop (read-flags) (list-ref fi 0))))])])
    (die))


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

  (define/override (setup id _io)
    (super setup id _io)
    (sendp io SSH_MSG_CHANNEL_OPEN "session" in 32768 32768))

  (define/override (channel/success sc _iws _mps)
    (super channel/success sc _iws _mps)
    ;(sendp io SSH_MSG_CHANNEL_REQUEST out "exec" #f "rsync --server --sender -e.Lsf . /home/tewk/WardCampFlyer.svg /home/tewk/WardCamp2011.pdf"))
    (sendp io SSH_MSG_CHANNEL_REQUEST out "exec" #f "/home/tewk/srcs/rsync/rsync --server -e.Lsf . doc"))

  (define/override (stderr type data)               (printf "~a\n" (bytes->hex-string data)) (flush-output))
  (define/override (stdout data)
    (printf "DATAIN: ~a\n" (bytes->hex-string data))
    (for ([x (bytes->string/latin-1 data)])
      (cond [(or (char-alphabetic? x) (char-numeric? x) (char-symbolic? x) (char-punctuation? x)) (printf "~a" x)]
            [else (printf  ".")]))
    (newline)
    (flush-output)
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
