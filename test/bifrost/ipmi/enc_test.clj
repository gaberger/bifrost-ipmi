(ns bifrost.ipmi.enc-test
  (:require  [clojure.test :as t]
             [gloss.core :refer [defcodec repeated finite-block finite-frame delimited-frame ordered-map]]
             [gloss.core.codecs :refer [wrap-suffixed-codec]]
             [gloss.data.primitives :refer [primitive-codecs]]
             [gloss.core.structure :refer :all]
             [gloss.io :refer [encode decode to-buf-seq]]
             [byte-streams :as bs]
             [clojure.walk :refer [postwalk-replace]]
             [bifrost.ipmi.crypto :refer :all]
             [gloss.core.protocols :refer :all]
             [buddy.core.codecs :as codecs]
             [byte-streams :as bs]
             [taoensso.timbre :as log]))

(defn- compile-frame-enc- [f]
  (cond
    (map? f) (convert-map (zipmap (keys f) (map compile-frame-enc- (vals f))))
    (sequential? f) (convert-sequence (map compile-frame-enc- f))
    :else f))

(defn compile-frame-enc
  ([frame]
   (if (reader? frame)
     frame
     (->> frame
          (postwalk-replace primitive-codecs)
          compile-frame-enc-)))
  ([frame pre-encoder pre-decoder post-decoder]
   (let [codec (compile-frame-enc frame)
         read-codec (compose-callback
                     codec
                     (fn [x b]
                       [true (post-decoder x) b]))]
     (reify
       Reader
       (read-bytes [_ b]
         (read-bytes read-codec (pre-decoder b)))
       Writer
       (sizeof [_]
         (sizeof codec))
       (write-bytes [_ buf v]
         (write-bytes codec buf (pre-encoder v)))))))

(comment
  "" "
  {:rmcp-header [0x06 0xc0 0x02 0x07 0x00 0x00 0x03 0x00
                 0x00 0x00]
   :length      [0x20 0x00] ; 32 iv + data
   :iv          [0x4c 0xea 0xec 0x47 0x49 0xbd 0x5f 0xa6
                 0x0d 0x2e 0xd8 0xe8 0x19 0x19 0xaf 0x89]
   :data        [0x44 0xe5 0xfa 0xbb 0xdd 0x15 0x40 0xfe
                 0xfc 0xdf 0x83 0xb2 0x0b 0x53 0x45 0xb5]
   :pad         [0xff 0xff]
   :pad-length  [0x02]
   :rmcp        [0x07]
   :auth-code   [0x30 0xf8 0x89 0x7d 0xcd 0x6b 0x00 0xa2
                 0x3a 0x86 0x09 0x19]}
 " "")

(defn to-bufs [b]
  (-> b byte-array codecs/bytes->hex))

(defn from-hbb [h]
  (-> (bs/to-byte-array codecs/bytes->hex)))

(defn to-vec [bb]
  (-> bb bs/to-byte-array vec))

(defn v-buf-seq [v]
  (-> v byte-array to-buf-seq))

(defn transform-padding [b]
  (let [v (to-vec b)]
    (loop [cnt 0
           acc v]
      (if (= (first acc) -1)
        (recur (inc cnt) (next acc))
        (v-buf-seq (into [] (conj (next acc) cnt)))))))

(def payload (byte-array  [0x20 0x00
                           0x4c 0xea 0xec 0x47 0x49 0xbd 0x5f 0xa6
                           0x0d 0x2e 0xd8 0xe8 0x19 0x19 0xaf 0x89
                           0x44 0xe5 0xfa 0xbb 0xdd 0x15 0x40 0xfe
                           0xfc 0xdf 0x83 0xb2 0x0b 0x53 0x45 0xb5
                           0xff 0xff 0x02 0x07 0x30 0xf8 0x89 0x7d
                           0xcd 0x6b 0x00 0xa2 0x3a 0x86 0x09 0x19]))

(def padding-codec
  (compile-frame-enc :ubyte
                     identity
                     transform-padding
                     identity))

(defn decode-aes-payload [b]
  (let [codec (compile-frame (ordered-map
                              :iv (repeat 16 :ubyte)
                              :data (repeat 16 :ubyte)))
        decoded (decode codec (byte-array b))]
    decoded))

(def aes-payload
  (compile-frame-enc
   (repeated :ubyte
             :prefix :uint16-le)
   identity
   identity
   decode-aes-payload))

(def sik [0x28 0x40 0x28 0xad 0xf1 0x1e 0x6e 0x9a 0x0d 0xdc 0x59 0x29 0x4f 0xd8 0x5b 0x61])


(defn aes-post-decoder [a]
  (clojure.pprint/pprint a)
  (let [iv (get-in a [:payload :iv])
        data (get-in a [:payload :data])
        decrypted (-> (decrypt sik iv data) bs/to-byte-array vec)]
    (assoc-in a [:payload :data] decrypted)))

(def aes-codec
  (compile-frame-enc
   (ordered-map
    :payload aes-payload
    :pad padding-codec
    :rcmp :ubyte
    :auth-code (repeat 12 :ubyte))
   identity
   identity
   aes-post-decoder))



;(def e (decode aes-codec payload))
;(println (map #(format "%x" %) (:auth-code e)))
;(println e)



;; (def auth-code-input [0x06 0xc0 0x02 0x07 0x00 0x00 0x03 0x00
;;                       0x00 0x00 0x20 0x00 0x4c 0xea 0xec 0x47
;;                       0x49 0xbd 0x5f 0xa6 0x0d 0x2e 0xd8 0xe8
;;                       0x19 0x19 0xaf 0x89 0x44 0xe5 0xfa 0xbb
;;                       0xdd 0x15 0x40 0xfe 0xfc 0xdf 0x83 0xb2
;;                       0x0b 0x53 0x45 0xb5 0xff 0xff 0x02 0x07])

;; (def buf (byte-array [0x00 0x20 0x00 0x4c 0xea 0xec 0x47 0x49
;;                       0xbd 0x5f 0xa6 0x0d 0x2e 0xd8 0xe8 0x19
;;                       0x19 0xaf 0x89 0x44 0xe5 0xfa 0xbb 0xdd
;;                       0x15 0x40 0xfe 0xfc 0xdf 0x83 0xb2 0x0b
;;                       0x53 0x45 0xb5 0xff 0xff 0x02 0x07 0x30
;;                       0xf8 0x89 0x7d 0xcd 0x6b 0x00 0xa2 0x3a
;;                       0x86 0x09 0x19]))


;;0x06 0x00 0xff 0x07
;;x06 0xc0 0x82 0x07 0x00 0x00 0x03 0x00
;;0x00 0x00 0x20 0x00 0xda 0xa3 0x37 0x41 0x95 0x4b 0x08 0x0d
;;0xf6 0xe4 0x1c 0x35 0x97 0xf2 0x88 0xef 0x5a 0x00 0xa7 0xc0
;;0x24 0x0c 0xb7 0x78 0x75 0x14 0xe1 0xd8 0x1d 0xe3 0xe1 0xda
;;0xff 0xff 0x02 0x07 0xb3 0x5d 0xa1 0x64 0x23 0xb1 0x06 0x38
;;0x26 0x36 0x46 0x14


;; (def sik (byte-array (vec (repeat 16 (conj 10)))))
;; (def d  (byte-array (vec (repeat 31 (conj 10)))))
;; (def result  (encrypt sik d))

;; (declare encrypt-aes)

;; (defcodec aes-frame (finite-block  (count d)))

;; (def encoded-payload (encode (compile-frame aes-frame) (:data result)))



;; (defn x-post-decoder [data]
;;   data)

;; (def aes-codec (compile-frame-enc
;;                 aes-frame
;;                 #(identity %)
;;                 x-pre-decoder
;;                 x-post-decoder))

;; (def s (decode aes-codec (:data result) false))
;; (println "Decoded Payload " (-> s bs/to-byte-array codecs/bytes->hex) "Count " (-> s bs/to-byte-array

;;                                                                                    count))


