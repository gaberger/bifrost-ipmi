(ns bifrost.ipmi.crypto
  (:require [buddy.core.mac :as mac]
            [byte-streams :as bs]
            [gloss.io :refer [encode]]
            [buddy.core.codecs :as codecs]
            [buddy.core.crypto :as crypto]
            [buddy.core.padding :as padding]
            [buddy.core.bytes :as bytes]
            [bifrost.ipmi.codec :refer [int->bytes]]
            [buddy.core.nonce :as nonce]
            [taoensso.timbre :as log]))

(defn calc-sha1-key [k input]
  (let [hmac (mac/hash input {:key k :alg :hmac :digest :sha1})]
    hmac))

(defn calc-rakp-1
  [{:keys [sidm sidc rc guidc rm rolem unamem uid]}]
  (let [unamem'     (codecs/str->bytes unamem)
        guidc'      (byte-array guidc)
        ulengthm    (byte-array 1 (byte (count unamem)))
        sidm'       (-> (encode int->bytes sidm) bs/to-byte-array reverse vec)
        sidc'       (-> (encode int->bytes sidc) bs/to-byte-array reverse vec)
        rolem'      (byte-array 1 (byte 0x14))
        rakp2-input (bytes/concat sidm' sidc' rm rc guidc rolem' ulengthm unamem')
        rakp2-hmac  (calc-sha1-key uid rakp2-input)]
    #_(log/debug  {:rm          (-> rm byte-array codecs/bytes->hex)
                   :rc          (-> rc byte-array codecs/bytes->hex)
                   :sidm        (format "%X" sidm)
                   :sidc        (format "%X" sidc)
                   :rolem       rolem
                   :guidc       (->  guidc byte-array codecs/bytes->hex)
                   :rakp2-input (codecs/bytes->hex rakp2-input)
                   :rakp2-hmac  (codecs/bytes->hex rakp2-hmac)})
    rakp2-hmac))

(defn calc-rakp-3
  [{:keys [sidm rc rolem unamem uid]}]
  {:pre  [(string? unamem)]}
  (let [;uid         (bytes/slice (codecs/str->bytes unamem) 0 20)
        unamem'     (codecs/str->bytes unamem)
        ulengthm    (byte-array 1 (byte (count unamem)))
        sidm'       (-> (encode int->bytes sidm) bs/to-byte-array reverse vec)
        rolem'      (byte-array 1 (byte 0x14))
        sidc-input (bytes/concat rc sidm' rolem' ulengthm unamem')
        sidc-hmac  (calc-sha1-key uid sidc-input)]
    #_(log/debug  {:rc          (-> rc byte-array codecs/bytes->hex)
                   :sidm        (format "%X" sidm)
                   :rolem       rolem
                   :sidc-input (codecs/bytes->hex sidc-input)
                   :sidc-hmac  (codecs/bytes->hex sidc-hmac)})
    sidc-hmac))

(defn calc-rakp-4-sik
  [{:keys [rm rc rolem unamem uid]}]
  (let [unamem'     (codecs/str->bytes unamem)
        ulengthm    (byte-array 1 (byte (count unamem)))
        rolem'      (byte-array 1 (byte 0x14))
        sik-input (bytes/concat rm rc rolem' ulengthm unamem')
        sik-hmac  (calc-sha1-key uid sik-input)]
    #_(log/debug  {:rm          (-> rm byte-array codecs/bytes->hex)
                   :rc          (-> rc byte-array codecs/bytes->hex)
                   :rolem       rolem
                   :sik-input (codecs/bytes->hex sik-input)
                   :sik-hmac  (codecs/bytes->hex sik-hmac)})
    sik-hmac))

(defn calc-rakp-4-sidm
  [{:keys [rm sidc guidc sik]}]
  (let [sidc'       (-> (encode int->bytes sidc) bs/to-byte-array reverse vec)
        sidm-input (bytes/concat rm sidc' guidc)
        sidm-hmac  (calc-sha1-key sik sidm-input)]
    #_(log/debug  {:rm          (-> rm byte-array codecs/bytes->hex)
                   :sidc        (format "%X" sidc)
                   :guidc       (->  guidc byte-array codecs/bytes->hex)
                   :sidm-input (codecs/bytes->hex sidm-input)
                   :sidm-hmac  (codecs/bytes->hex sidm-hmac)})
    sidm-hmac))

(defn K1 [sik]
  (let [const1 (byte-array [01 01 01 01 01 01 01 01 01 01])]
    (calc-sha1-key sik const1)))

(defn K2 [sik]
  (let [const2 (byte-array [02 02 02 02 02 02 02 02 02 02])]
    (calc-sha1-key sik const2)))

(defn pad-count [size]
  (if-not (= 0 (mod size 16))
    (- 16 (mod size 16))
    0))

(defn -encrypt-block [block iv key]
  (let [engine (crypto/block-cipher :aes :cbc)]
    (crypto/init! engine {:key key :iv iv :op :encrypt})
    (crypto/process-block! engine (byte-array block))))

(defn -decrypt-block [block iv key]
  (let [engine (crypto/block-cipher :aes :cbc)]
    (crypto/init! engine {:key key :iv iv :op :decrypt})
    (crypto/process-block! engine (byte-array block))))

(defn encrypt
  "AES-128 uses a 128-bit Cipher Key. The Cipher Key is the first 128-bits of key “K2”, K2 is generated from the
  Session Integrity Key (SIK) that was created during session activation. See Section 13.22, RAKP Message 3 and Section 13.32,
  Generating Additional Keying Material. Once the Cipher Key has been generated it is used to encrypt the payload data. The
  payload data is padded to make it an integral numbers of blocks in length (a block is 16 bytes for AES). The payload is then
  encrypted one block at a time from the lowest data offset to the highest using Cipher_Key as specified in [AES].
  K2 = HMACsik
  "
  [sik payload]
  (let [iv      (nonce/random-nonce 16)
        key     (bytes/slice (K2 sik) 0 16)
        padding (pad-count (count payload))
        buffer (mapv #(-encrypt-block (vec %) iv key)
                     (partition 16 16 [0 0 0 0 0 0 0 0 0 0 0 0 0 0 0] payload))]
    {:iv iv :padding padding :data (reduce (fn [x y]
                                             (bytes/concat x y))
                                           []
                                           buffer)}))

(defn decrypt
  [sik iv payload padding]
  (let [engine        (crypto/block-cipher :aes :cbc)
        key           (bytes/slice (K2 sik) 0 16)
        _             (crypto/init! engine {:key key :iv iv :op :decrypt})
        output-buffer (mapv #(-decrypt-block (vec %) iv key)
                            (partition 16 payload))
        buffer        (reduce (fn [x y]
                                (bytes/concat x y))
                              []
                              output-buffer)
        trim-buffer        (bytes/slice buffer 0 (- (count buffer) padding))]
    trim-buffer))
