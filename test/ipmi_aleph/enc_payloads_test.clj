(ns ipmi-aleph.enc-payloads-test
  (:require [clojure.test :refer :all]
            [ipmi-aleph.codec :refer [compile-codec rmcp-header]]
            [ipmi-aleph.crypto :refer [calc-sha1-key]]
            [gloss.io :refer [decode encode]]
            [gloss.core :refer [compile-frame]]
            [buddy.core.mac :as mac]
            [buddy.core.crypto :as crypto]
            [buddy.core.bytes :as bytes]
            [buddy.core.padding :as padding]
            [buddy.core.nonce :as nonce]
            [buddy.core.codecs :as codecs]
            [taoensso.timbre :as log]
            [clj-uuid :as uuid]
            [byte-streams :as bs])
  (:import (java.nio ByteBuffer)))

                                        ; Cipher slots
;; ID   IANA    Auth Alg        Integrity Alg   Confidentiality Alg
;; 0    N/A     none            none            none
;; 1    N/A     hmac_sha1       none            none
;; 2    N/A     hmac_sha1       hmac_sha1_96    none
;; 3    N/A     hmac_sha1       hmac_sha1_96    aes_cbc_128
;; 4    N/A     hmac_sha1       hmac_sha1_96    xrc4_128
;; 5    N/A     hmac_sha1       hmac_sha1_96    xrc4_40
;; 6    N/A     hmac_md5        none            none
;; 7    N/A     hmac_md5        hmac_md5_128    none
;; 8    N/A     hmac_md5        hmac_md5_128    aes_cbc_128
;; 9    N/A     hmac_md5        hmac_md5_128    xrc4_128
;; 10   N/A     hmac_md5        hmac_md5_128    xrc4_40
;; 11   N/A     hmac_md5        md5_128         none
;; 12   N/A     hmac_md5        md5_128         aes_cbc_128
;; 13   N/A     hmac_md5        md5_128         xrc4_128
;; 14   N/A     hmac_md5        md5_128         xrc4_40
;; 15   N/A     hmac_sha256     none            none
;; 16   N/A     hmac_sha256     sha256_128      none
;; 17   N/A     hmac_sha256     sha256_128      aes_cbc_128
;; 18   N/A     hmac_sha256     sha256_128      xrc4_128
;; 19   N/A     hmac_sha256     sha256_128      xrc4_40  


(def rmcp-enc-payloads-cipher-1
  {:open-session-response    [0x06 0x00 0xff 0x07 0x06 0x11 0x00 0x00 0x00 0x00 0x00
                              0x00 0x00 0x00 0x24 0x00 0x00 0x00 0x04 0x00 0xa4 0xa3
                              0xa2 0xa0 0x01 0x18 0x00 0x02 0x00 0x00 0x00 0x08 0x01
                              0x00 0x00 0x00 0x01 0x00 0x00 0x08 0x00 0x00 0x00 0x00
                              0x02 0x00 0x00 0x08 0x00 0x00 0x00 0x00]
   :rmcp-rakp-1              [0x06 0x00 0xff 0x07 0x06 0x12 0x00 0x00 0x00 0x00 0x00
                              0x00 0x00 0x00 0x20 0x00 0x00 0x00 0x00 0x00 0x01 0x18
                              0x00 0x02 0x35 0xf7 0xfc 0x77 0x92 0xb8 0xf7 0x28 0xe0
                              0xfa 0x49 0xfb 0x58 0x04 0x6f 0xe5 0x14 0x00 0x00 0x04
                              0x72 0x6f 0x6f 0x74]
   :rmcp-rakp-2              [0x06 0x00 0xff 0x07 0x06 0x13 0x00 0x00 0x00 0x00 0x00 0x00
                              0x00 0x00 0x3c 0x00 0x00 0x00 0x00 0x00 0xa4 0xa3 0xa2 0xa0
                              0x42 0xfa 0xe7 0x0f 0x38 0x1a 0x44 0x1d 0x9e 0x78 0xf3 0x87
                              0xc9 0xd0 0x49 0xa0 0xa1 0x23 0x45 0x67 0x89 0xab 0xcd 0xef
                              0xa1 0x23 0x45 0x67 0x89 0xab 0xcd 0xef 0x7f 0xfc 0xdb 0xc8
                              0x04 0x34 0xeb 0xb3 0x5b 0x4e 0x50 0x62 0xda 0x18 0x21 0xb2
                              0xce 0xb5 0xbc 0xb4]})



;; (deftest auth-key-generator
;;   (testing "test auth key generation from RAKP-1/RAKP-2"
;;     (comment "HMACK[UID] (SIDM, SIDC, RM, RC, GUIDC, RoleM, ULengthM, < UNameM >)"
;;              " Parameter  bytes    Name
;;                SIDM       4        Remote_Console_Session_ID
;;                SIDC       4        Managed_System_Session_ID
;;                RM         16       Remote Console Random_Number
;;                RC         16       Managed System Random Number
;;                GUIDC      16       Managed_System_GUID
;;                RoleM      1        Requested Privilege Level (Role)
;;                ULengthM   1        User Name Length byte (number of bytes of UNameM = 0 for ‘null’ username)
;;                UNameM     var      User Name bytes (absent for ‘null’ username)")
;;     (let [compiled-decoder (compile-codec  :rmcp-rakp-2-hmac-sha1)
;;           decoder (partial decode compiled-decoder)
;;           rakp1-message (decoder (byte-array (:rmcp-rakp-1 rmcp-enc-payloads-cipher-1)))
;;           rakp2-message (decoder (byte-array (:rmcp-rakp-2 rmcp-enc-payloads-cipher-1)))
;;           key-exch-code (get-in rakp2-message [:rmcp-class
;;                                                :ipmi-session-payload
;;                                                :ipmi-2-0-payload
;;                                                :key-exchange-code])
;;           SIDC  (int->bytes
;;                  (get-in rakp1-message [:rmcp-class
;;                                         :ipmi-session-payload :ipmi-2-0-payload :managed-system-session-id]))
;;           SIDM (int->bytes
;;                 (get-in rakp2-message [:rmcp-class
;;                                        :ipmi-session-payload :ipmi-2-0-payload :remote-session-console-id]))
;;           RM  (byte-array (get-in rakp1-message [:rmcp-class
;;                                                  :ipmi-session-payload
;;                                                  :ipmi-2-0-payload
;;                                                  :remote-console-random-number]))
;;           RC (byte-array (get-in rakp2-message [:rmcp-class
;;                                                 :ipmi-session-payload
;;                                                 :ipmi-2-0-payload
;;                                                 :managed-system-random-number]))
;;           GUIDC (byte-array
;;                  (get-in rakp2-message [:rmcp-class
;;                                         :ipmi-session-payload
;;                                         :ipmi-2-0-payload
;;                                         :managed-system-guid]))
;;           ROLEM (byte-array [(byte (get-in rakp1-message [:rmcp-class
;;                                                           :ipmi-session-payload :ipmi-2-0-payload :requested-max-priv-level
;;                                                           :requested-max-priv-level]))])
;;           UNAMEM (->>
;;                   (get-in rakp1-message [:rmcp-class
;;                                          :ipmi-session-payload :ipmi-2-0-payload :user-name])
;;                   (codecs/str->bytes))
;;           ULENGTHM (byte-array [(byte (count UNAMEM))])
;;           buffer (byte-array (mapcat seq [SIDM SIDC RM RC GUIDC ROLEM ULENGTHM UNAMEM]))]

;;       (prn "BUFFER" (codecs/bytes->hex buffer))
;;       (prn "SIDM" (codecs/bytes->hex SIDM))
;;       (prn "SIDC" (codecs/bytes->hex SIDC))
;;       (prn "RM" (codecs/bytes->hex RM))
;;       (prn "RC" (codecs/bytes->hex RC))
;;       (prn "GUIDC" (codecs/bytes->hex GUIDC))
;;       (prn "ROLEM" (codecs/bytes->hex ROLEM))
;;       (prn "ULENGTHM" (codecs/bytes->hex ULENGTHM))
;;       (prn "UNAMEM" (codecs/bytes->hex UNAMEM))

;;       (is (buddy.core.bytes/equals? key-exch-code
;;                                     (-> (mac/hash buffer {:key "Dell0SS!" :alg :hmac :digest
;;                                                           :sha1})))))))


(deftest key-generation
  (let [SIDM       (-> (encode int->bytes  0xa0a2a3a4) bs/to-byte-array reverse)
        SIDC       (-> (encode int->bytes  0x02001b00) bs/to-byte-array reverse)
        RM         (byte-array [0xfe 0xd2 0xf2 0xb3 0x7c 0xe4 0xac 0x7d 0x98 0x13 0x86 0x5b 0x73 0x07 0x0c 0x4e])
        RC         (-> (.toByteArray (biginteger 0x9323b34dc958cd939d6ce76d4d3189e2)) (bytes/slice 1 17))
        GUIDC      (.toByteArray (biginteger 0x44454c4c380010528036c2c04f573532))
        ROLEM      (byte-array 1 (byte 20)) ;Need to find out why this is 0x14
        UNAME      (codecs/str->bytes "root")
        ULENGTHM   (byte-array 1 (byte (count UNAME)))
        UID        (bytes/slice (codecs/str->bytes "Dell0SS!") 0 20)
        KG         (byte-array 20)
        ;; Test data
        RAKP2HMACT (byte-array [0xe0 0x55 0x78 0xdf 0x37 0x66 0xe6 0xa5 0x86 0x5d
                                0xc8 0xa7 0x61 0x97 0x28 0x75 0xdd 0xf9 0x45 0x21])
        RAKP3HMACT (byte-array [0xc1 0x5f 0x1d 0x7b 0x82 0x9b 0x29 0x13 0x69 0xee
                                0x63 0xf8 0x3a 0x69 0x9d 0x26 0xf8 0xee 0x4d 0x27])
        SIKT       (byte-array [0x0f 0x86 0xc2 0x83 0xe8 0x74 0xe5 0x83 0x3d 0x8a 0x2b 0xec 0x44 0xee 0xa1 0x16
                                0x71 0xef 0xd5 0xca])
        K1         nil
        K2         nil
        RAKP4HMACT (byte-array [0xb3 0x62 0x59 0x92 0xac 0x2b 0xcc 0x55 0xa5 0x43 0xc4 0xe3 0xc4 0x02 0x5d 0x18
                                0x01 0x63 0xee 0xd4])
        ;;
        KG-INPUT   (byte-array  [0x23 0xb3 0x4d 0xc9 0x58 0xcd 0x93 0x9d 0x6c 0xe7 0x6d 0x4d 0x31 0x89 0xe2 0xa4
                                 0xa3 0xa2 0xa0 0x14 0x04 0x72 0x6f 0x6f 0x74])
        test-input (byte-array [0xa4 0xa3 0xa2 0xa0 0x00 0x1b 0x00 0x02 0xfe 0xd2 0xf2 0xb3 0x7c 0xe4 0xac 0x7d
                                0x98 0x13 0x86 0x5b 0x73 0x07 0x0c 0x4e 0x93 0x23 0xb3 0x4d 0xc9 0x58 0xcd 0x93
                                0x9d 0x6c 0xe7 0x6d 0x4d 0x31 0x89 0xe2 0x44 0x45 0x4c 0x4c 0x38 0x00 0x10 0x52
                                0x80 0x36 0xc2 0xc0 0x4f 0x57 0x35 0x32 0x14 0x04 0x72 0x6f 0x6f 0x74])

        RAKP2-MAC-INPUT (buddy.core.bytes/concat  SIDM SIDC RM RC GUIDC ROLEM ULENGTHM UNAME)
        RAKP2-MACUID    (calc-sha1-key UID RAKP2-MAC-INPUT)

        RAKP3-MAC-INPUT (buddy.core.bytes/concat RC SIDM ROLEM ULENGTHM UNAME)
        RAKP3-MACKUID   (calc-sha1-key UID RAKP3-MAC-INPUT)

        SIK-INPUT (buddy.core.bytes/concat RM RC ROLEM ULENGTHM UNAME)
        SIK       (calc-sha1-key UID SIK-INPUT)

        RAKP4-SIDM-INPUT (buddy.core.bytes/concat RM SIDC GUIDC)
        SIDM (calc-sha1-key SIK RAKP4-SIDM-INPUT)]

    (testing "test hmac-sha1-encoder-rakp2"
      (is (bytes/equals? RAKP2HMACT
                         RAKP2-MACUID)))
    (testing "test hmac-sha1-encoder-rakp3"
      (is (bytes/equals? RAKP3HMACT
                         RAKP3-MACKUID)))
    (testing "test hmac-sha1-encoder-rakp4-remote"
      (log/debug (codecs/bytes->hex SIDM))
      (is (bytes/equals? RAKP4HMACT
                         SIDM)))))

