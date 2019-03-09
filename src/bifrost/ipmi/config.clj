(ns bifrost.ipmi.config
  (:require [bifrost.ipmi.decode :as decode]
            [clojure.core.async :as async]))

(defn server-config [fsm]
  (atom {:decode-channel  (async/chan 10 (conj (decode/decode-xf fsm)))
         :command-channel (async/chan)}))
