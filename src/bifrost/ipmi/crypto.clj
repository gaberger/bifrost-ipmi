(ns bifrost.ipmi.crypto
  (:require [buddy.core.mac :as mac]
            [byte-streams :as bs]
            [gloss.io :refer [encode to-buf-seq]]
            [gloss.core :refer [defcodec]]
            [buddy.core.padding :as padding]
            [buddy.core.bytes :as bytes]
            [buddy.core.codecs :as codecs]
            [buddy.core.crypto :as crypto]
            [buddy.core.nonce :as nonce]
            [taoensso.timbre :as log]))

(defcodec int->bytes :uint32)
(defcodec int->byte :ubyte)

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
    sidc-hmac))

(defn calc-rakp-4-sik
  [{:keys [rm rc rolem unamem uid]}]
  (let [unamem'     (codecs/str->bytes unamem)
        ulengthm    (byte-array 1 (byte (count unamem)))
        rolem'      (byte-array 1 (byte 0x14))
        sik-input (bytes/concat rm rc rolem' ulengthm unamem')
        sik-hmac  (calc-sha1-key uid sik-input)]
    sik-hmac))

(defn calc-rakp-4-sidm
  [{:keys [rm sidc guidc sik]}]
  (let [sidc'       (-> (encode int->bytes sidc) bs/to-byte-array reverse vec)
        sidm-input (bytes/concat rm sidc' guidc)
        sidm-hmac  (calc-sha1-key sik sidm-input)]
    sidm-hmac))

(defn K1 [sik]
  (let [const1 (byte-array [01 01 01 01 01 01 01 01 01 01
                            01 01 01 01 01 01 01 01 01 01])
        K1 (calc-sha1-key sik const1)]
    K1
    ))

(defn K2 [sik]
  (let [const2 (byte-array [02 02 02 02 02 02 02 02 02 02
                            02 02 02 02 02 02 02 02 02 02])]
    (calc-sha1-key sik const2)))

(defn pad-count [size]
  (let [x (mod size 16)]
    (condp = x
      0 (- 16 (mod (inc size) 16))
      15 1
      (- 16 (mod size 16))
      )))

;;TODO fix interval handling
(defn pad-vec
  "Encrypted traffic must terminate with a pad length byte. If no padding is required this byte must be 0x00
  special case if mod size 16 == 0 must add 15 bytes of padding and padding-length"
  [v]
  (let [pad-count (pad-count (count v))
        pad-vec   (vec (concat (range 1  pad-count) [(dec pad-count)]))]
    (if (= 15 pad-count)
      (let [pad-vec (vec (concat (range 1 (inc pad-count)) [pad-count]))
            p-cnt (+ (inc pad-count) (count v))
            p-div (quot p-cnt 16)
            p-mult (* 16 p-div)]
        (partition p-mult 16 pad-vec v))
      (partition 16 16 pad-vec v))))


(defn calc-integrity-96
  ^{:doc          "HMAC [sik] and iv"
    :test         (fn []
                    (assert (vector? iv))
                    (assert (vector? sik)))
    :user/comment "Unless otherwise specified, the integrity algorithm is applied to the packet data starting with the
                    AuthType/Format field up to and including the field that immediately precedes the AuthCode field itself."}
  [sik payload]
  (let [sik'      (byte-array sik)
        key      (K1 sik')
        hmac      (calc-sha1-key key (byte-array payload))
        auth-code (-> (bytes/slice hmac 0 12) byte-array vec)
        ]
    (log/debug "auth-code-hmac" (-> hmac bs/to-byte-array codecs/bytes->hex))
    (log/debug "auth-code-input" (-> payload bs/to-byte-array codecs/bytes->hex))
    (log/debug "auth-code-output" (-> auth-code byte-array codecs/bytes->hex))
    auth-code))

(defn -process-block
  "Takes a vector of 16 byte elements, byte-arrays for initialization vector and key returns a encrypted/decrypted vector"
  [engine block]
  (crypto/process-block! engine (byte-array block)))

(defn  encrypt
  ^{:doc          "Encrypt data using K2[sik] and iv"
    :test         (fn []
                    (assert (vector? iv))
                    (assert (vector? sik)))
    :user/comment "AES-128 uses a 128-bit Cipher Key. The Cipher Key is the first 128-bits of key “K2”, K2 is generated from the
    Session Integrity Key (SIK) that was created during session activation. See Section 13.22, RAKP Message 3 and Section 13.32,
    Generating Additional Keying Material. Once the Cipher Key has been generated it is used to encrypt the payload data. The
    payload data is padded to make it an integral numbers of blocks in length (a block is 16 bytes for AES). The payload is then
    encrypted one block at a time from the lowest data offset to the highest using Cipher_Key as specified in [AES].
    K2 = HMACsik"}
  [sik iv payload]
  (let [engine        (crypto/block-cipher :aes :cbc)
        sik'          (byte-array sik)
        iv'           (byte-array iv)
        key'          (K2 sik')
        key16         (bytes/slice key' 0 16)
        _             (crypto/init! engine {:key key16 :iv iv' :op :encrypt})
        output-buffer (mapv #(-process-block engine %)
                            (pad-vec payload))
        buffer        (reduce (fn [x y]
                                (bytes/concat x y))
                              []
                              output-buffer)]
    (log/debug "Encrypting with IV " (-> iv byte-array codecs/bytes->hex))
    (log/debug "Encrypting with Key " (codecs/bytes->hex key16))
    (log/debug "Encrypting Input Data" (-> payload byte-array codecs/bytes->hex))
    (log/debug "Encrypted Payload" (codecs/bytes->hex buffer) "Count" (count buffer))
    buffer))

(defn decrypt
  [sik iv payload]
  (let [engine         (crypto/block-cipher :aes :cbc)
        iv'            (byte-array iv)
        sik'           (byte-array sik)
        key'           (K2 (byte-array sik'))
        key            (bytes/slice (K2 (byte-array sik')) 0 16)
        _              (crypto/init! engine {:key key :iv iv' :op :decrypt})
        output-buffer  (mapv #(-process-block engine %)
                             (partition 16 payload))
        buffer         (vec (reduce (fn [x y]
                                      (bytes/concat x y))
                                    []
                                    output-buffer))
        padding-length (last buffer)
        new-buffer_    (if (> padding-length 0)
                         (->
                          (take (- 16 (inc padding-length)) buffer)
                          byte-array)
                         (butlast buffer))]
    (log/debug "Decrypting with IV " (codecs/bytes->hex iv'))
    (log/debug "Decrypting with key " (codecs/bytes->hex key))
    (log/debug "Decrypted Payload" (codecs/bytes->hex new-buffer_) "Count" (count new-buffer_))
    new-buffer_))
