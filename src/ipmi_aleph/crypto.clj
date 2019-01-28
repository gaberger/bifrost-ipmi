(ns ipmi-aleph.crypto
  (:require [buddy.core.mac :as mac]
            [taoensso.timbre :as log]
            [byte-streams :as bs]
            [buddy.core.codecs :as codecs]))

(defn calc-sha1-key [k input]
  (log/debug "Calculating hash on k" k "with input" input)
  (let [hmac (mac/hash input {:key k :alg :hmac :digest :sha1})
              ]
    (log/debug "HMAC:" (codecs/bytes->hex hmac))
    hmac))
