(ns ipmi-aleph.crypto
  (:require [buddy.core.mac :as mac]))

(defn calc-sha1-key [k input]
  (mac/hash input {:key k :alg :hmac :digest
                   :sha1}))
