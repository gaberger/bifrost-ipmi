(ns ipmi-aleph.crypto
  (:require [buddy.core.mac :as mac]
            [taoensso.timbre :as log]
            [byte-streams :as bs]
            [gloss.io :refer [encode]]
            [buddy.core.codecs :as codecs]
            [clj-uuid :as uuid]
            [buddy.core.bytes :as bytes]
            [ipmi-aleph.codec :refer [int->bytes]]))

(defn calc-sha1-key [k input]
  (let [hmac (mac/hash input {:key k :alg :hmac :digest :sha1})]
    hmac))

(defn calc-rakp-1
  [{:keys [sidm sidc rc guidc rm rolem unamem]}]
  (let [uid         (bytes/slice (codecs/str->bytes unamem) 0 20)
        unamem'     (codecs/str->bytes unamem)
        ulengthm    (byte-array 1 (byte (count unamem)))
        sidm'       (-> (encode int->bytes sidm) bs/to-byte-array reverse vec)
        sidc'       (-> (encode int->bytes sidc) bs/to-byte-array reverse vec)
        rolem'      (byte-array 1 (byte 0x14))
        rakp2-input (bytes/concat sidm' sidc' rm rc guidc rolem' ulengthm unamem')
        rakp2-hmac  (calc-sha1-key uid rakp2-input)]
    (log/debug  {:rm          (-> rm byte-array codecs/bytes->hex)
                 :rc          (-> rc byte-array codecs/bytes->hex)
                 :sidm        (format "%X" sidm)
                 :sidc        (format "%X" sidc)
                 :rolem       rolem
                 :guidc       (->  guidc byte-array codecs/bytes->hex)
                 :rakp2-input (codecs/bytes->hex rakp2-input)
                 :rakp2-hmac  (codecs/bytes->hex rakp2-hmac)})
    rakp2-hmac))

(defn calc-rakp-3
  [{:keys [sidm rc rolem unamem]}]
  (let [uid         (bytes/slice (codecs/str->bytes unamem) 0 20)
        unamem'     (codecs/str->bytes unamem)
        ulengthm    (byte-array 1 (byte (count unamem)))
        sidm'       (-> (encode int->bytes sidm) bs/to-byte-array reverse vec)
        rolem'      (byte-array 1 (byte 0x14))
        sidc-input (bytes/concat rc sidm' rolem' ulengthm unamem')
        sidc-hmac  (calc-sha1-key uid sidc-input)]
    (log/debug  {
                 :rc          (-> rc byte-array codecs/bytes->hex)
                 :sidm        (format "%X" sidm)
                 :rolem       rolem
                 :sidc-input (codecs/bytes->hex sidc-input)
                 :sidc-hmac  (codecs/bytes->hex sidc-hmac)})
    sidc-hmac))


(defn calc-rakp-4-sik
  [{:keys [rm rc rolem unamem]}]
  (let [uid         (bytes/slice (codecs/str->bytes unamem) 0 20)
        unamem'     (codecs/str->bytes unamem)
        ulengthm    (byte-array 1 (byte (count unamem)))
        rolem'      (byte-array 1 (byte 0x14))
        sik-input (bytes/concat rm rc rolem' ulengthm unamem')
        sik-hmac  (calc-sha1-key uid sik-input)]
    (log/debug  {:rm          (-> rm byte-array codecs/bytes->hex)
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
    (log/debug  {:rm          (-> rm byte-array codecs/bytes->hex)
                 :sidc        (format "%X" sidc)
                 :guidc       (->  guidc byte-array codecs/bytes->hex)
                 :sidm-input (codecs/bytes->hex sidm-input)
                 :sidm-hmac  (codecs/bytes->hex sidm-hmac)})
    sidm-hmac))
