(ns bifrost.ipmi.decode
  (:require [bifrost.ipmi.state-machine :as state]
            [bifrost.ipmi.codec :as c]
            [clojure.core.async :as async]
            [gloss.io :as i]
            [taoensso.timbre :as log]
            [byte-streams :as bs]
            [buddy.core.codecs :as codecs]))

(defn decode-message [state message]
  (log/debug "Decoding Message" message)
  (let [codec (c/compile-codec state)
        decoded (try
                  (i/decode codec message)
                  (catch Exception e
                    (throw (ex-info "Decoder exception"
                                    {:error (.getMessage e)
                                     :payload (codecs/bytes->hex message)}))
                    nil))
        aes-payload? (contains?
                      (get-in decoded [:rmcp-class :ipmi-session-payload :ipmi-2-0-payload])
                      :aes-decoded-payload)
        message (if aes-payload?
                  (let [aes-payload (get-in decoded [:rmcp-class
                                                     :ipmi-session-payload
                                                     :ipmi-2-0-payload
                                                     :aes-decoded-payload])]
                    (-> (update-in decoded [:rmcp-class :ipmi-session-payload :ipmi-2-0-payload] merge aes-payload)
                        (update-in  [:rmcp-class
                                     :ipmi-session-payload
                                     :ipmi-2-0-payload]
                                    dissoc :aes-decoded-payload)))
                  decoded)]
                   ;; TODO need to respond with an error message here
    (log/debug "Decoded Message " message)
    message))


(defn decoder-xf [fsm]
  (fn [xf]
    (let [state (atom {})]
      (fn
        ([] (xf))
        ([result] (xf result))
        ([result item]
         (let [decoded-message (decode-message (:value @state) item)
               new-state       (fsm @state decoded-message)]
           (reset! state new-state)
           (log/debug (:state-index new-state))
           (condp = (:state-index @state)
             5 (xf result (assoc {} :type :command :state (:value @state) :message decoded-message))
             6 (reduced result)
             (xf result {}) )))))))


(defn make-decoder [fsm]
  (let [decoder-chan (async/chan 1 (decoder-xf fsm))]
    decoder-chan))
