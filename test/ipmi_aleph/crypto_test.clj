(ns ipmi-aleph.crypto-test
  (:require [clojure.test :refer :all]
            [ipmi-aleph.codec :refer [compile-codec  int->bytes]]
            [ipmi-aleph.crypto :refer [calc-sha1-key calc-rakp-1]]
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


(deftest key-generation
  (let [SIDM       (-> (encode int->bytes  0xa0a2a3a4) bs/to-byte-array vec reverse)
        SIDC       (-> (encode int->bytes  0x02001b00) bs/to-byte-array vec reverse)
        RM         [0xfe 0xd2 0xf2 0xb3 0x7c 0xe4 0xac 0x7d 0x98 0x13 0x86 0x5b 0x73 0x07 0x0c 0x4e]
        RC         (-> (.toByteArray (biginteger 0x9323b34dc958cd939d6ce76d4d3189e2)) (bytes/slice 1 17))
        GUIDC      (.toByteArray (biginteger 0x44454c4c380010528036c2c04f573532))
        ROLEM      (byte-array 1 (byte 20)) ;Need to find out why this is 0x14
        UNAME      (codecs/str->bytes "root")
        ULENGTHM   (byte-array 1 (byte (count UNAME)))
        UID        (bytes/slice (codecs/str->bytes "Dell0SS!") 0 20)
        ;; Test data
        RAKP2HMACT (byte-array [0xe0 0x55 0x78 0xdf 0x37 0x66 0xe6 0xa5 0x86 0x5d
                                0xc8 0xa7 0x61 0x97 0x28 0x75 0xdd 0xf9 0x45 0x21])
        RAKP3HMACT (byte-array [0xc1 0x5f 0x1d 0x7b 0x82 0x9b 0x29 0x13 0x69 0xee
                                0x63 0xf8 0x3a 0x69 0x9d 0x26 0xf8 0xee 0x4d 0x27])
        SIKT       (byte-array [0x0f 0x86 0xc2 0x83 0xe8 0x74 0xe5 0x83 0x3d 0x8a 0x2b 0xec 0x44 0xee 0xa1 0x16
                                0x71 0xef 0xd5 0xca])
        RAKP4HMACT (byte-array [0xb3 0x62 0x59 0x92 0xac 0x2b 0xcc 0x55 0xa5 0x43 0xc4 0xe3 0xc4 0x02 0x5d 0x18
                                0x01 0x63 0xee 0xd4])
        ;;
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


(deftest test-encode-byte-format
  (testing "vector encoder"
    (let [codec  (compile-frame (repeat 10 :ubyte))
          encode (encode codec [0 1 2 3 4 5 6 7 8 9])]
      (is (= "00010203040506070809"
             (-> encode
                 bs/to-byte-array
                 codecs/bytes->hex)))))
  (testing "hmac-calc"
    (let   [rc         [2 4 6 5 3 8 8 0 13 14 11 0 11 9 3 0]
            guidc      [0x99 0xe2 0x74 0x97 0x77 0x28 0x4f 0x5a 0xab 0x09 0xc5 0x90 0xda 0xbc 0x68b]
            rm         [0xfe 0xd2 0xf2 0xb3 0x7c 0xe4 0xac 0x7d 0x98 0x13 0x86 0x5b 0x73 0x07 0x0c 0x4e]
            sidc       2695013284
            sidm       2695013282
            unamem     "root"
            rolem      4
            rakp2-hmac (calc-rakp-1  {:rm rm :rc rc :guidc guidc :sidc sidc :sidm sidm :unamem unamem :rolem rolem})]
      (is (bs/compare-bytes
               "261e97e47fcb8c7996e14b9326ddcfa09100cd75"
               rakp2-hmac)))))

;; Bad RAKP1
(comment {:version 6, :reserved 0, :sequence 255, :rmcp-class {:ipmi-session-payload {:ipmi-2-0-payload {:session-id 0, :session-seq 0, :payload-type {:encrypted? false, :authenticated? false, :type 19}, :managed-system-random-number [8 14 14 10 8 10 5 13 5 5 10 1 0 7 4 1], :status-code 0, :message-tag 0, :key-exchange-code [37 103 22 -64 57 104 -24 17 -58 -65 -17 56 -112 100 25 -115 -4 -10 58 36], :reserved [0 0], :message-length 60, :managed-system-guid [66 115 -125 78 -92 -127 64 36 -71 -118 77 -65 112 10 -24 16], :remote-session-console-id 2695013284}, :type :ipmi-2-0-session}, :type :ipmi-session}})

;; 0000   06 12 00 00 00 00 00 00 00 00 21 00 00 00 00 00
;; 0010   73 14 00 00 59 8d d2 bd 11 b9 13 ed e8 c5 2a c1
;; 0020   ea ac d4 e9 14 00 00 05 41 44 4d 49 4e


;; <<RAKP 2 MESSAGE
;; <<  Message tag                   : 0x00
;; <<  RMCP+ status                  : no errors
;; <<  Console Session ID            : 0xa0a2a3a4
;; <<  BMC random number             : 0x080e0e0a080a050d05050a0100070401
;; <<  BMC GUID                      : 0x4273834ea4814024b98a4dbf700ae810
;; <<  Key exchange auth code [sha1] : 0x0000000000000000000000000000000000000000

;; bmc_rand (16 bytes)
;; 08 0e 0e 0a 08 0a 05 0d 05 05 0a 01 00 07 04 01
;; >> rakp2 mac input buffer (63 bytes)
;; a4 a3 a2 a0 73 14 00 00 59 8d d2 bd 11 b9 13 ed
;; e8 c5 2a c1 ea ac d4 e9 08 0e 0e 0a 08 0a 05 0d
;; 05 05 0a 01 00 07 04 01 42 73 83 4e a4 81 40 24
;; b9 8a 4d bf 70 0a e8 10 14 05 41 44 4d 49 4e
;; >> rakp2 mac key (20 bytes)
;; 41 44 4d 49 4e 00 00 00 00 00 00 00 00 00 00 00
;; 00 00 00 00
;; >> rakp2 mac as computed by the remote console (20 bytes)
;; 3c 43 e4 33 f2 53 a2 27 34 29 11 d3 68 f1 de ab
;; 8e 3d c0 1c
;; > RAKP 2 HMAC is invalid  
