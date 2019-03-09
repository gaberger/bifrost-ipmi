(ns bifrost.ipmi.decode
  (:require [bifrost.ipmi.state-machine :as state]
            [bifrost.ipmi.codec :as c]
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

#_(defn decode-message [state message host-map]
  (let [codec           (c/compile-codec state)
        decoded         (try
                          (i/decode codec message)
                          (catch Exception e
                            (throw (ex-info "Decoder exception"
                                            {:error (.getMessage e)}))
                            nil))
        aes-payload?    (contains?
                         (get-in decoded [:rmcp-class :ipmi-session-payload :ipmi-2-0-payload])
                         :aes-decoded-payload)
        decoded-message (if aes-payload?
                          (let [aes-payload (get-in decoded [:rmcp-class
                                                             :ipmi-session-payload
                                                             :ipmi-2-0-payload
                                                             :aes-decoded-payload])]
                            (-> (update-in decoded [:rmcp-class :ipmi-session-payload :ipmi-2-0-payload] merge aes-payload)
                                (update-in  [:rmcp-class
                                             :ipmi-session-payload
                                             :ipmi-2-0-payload]
                                            dissoc :aes-decoded-payload)))
                          decoded)
        message         (merge decoded-message host-map)]
                   ;; TODO need to respond with an error message here
    (log/debug "Decoded Message " message)
    message))

;; (defn decode-xf [fsm]
;;   (fn [xf]
;;     (let [state (volatile! {})]
;;       (fn
;;         ([result] result)
;;         ([result input]
;;          (let [decoded-message (decode-message (:value @state) input)]
;;            (condp (log/spy (:state-index @state))
;;                5 (xf result decoded-message)
;;                1 (vreset! state {})
;;                (do
;;                  (vreset! state (log/spy (fsm @state decoded-message)))
;;                  (xf result)))))))))


(defn decode-xf [fsm]
  (fn [xf]
    (let [state (atom {})]
      (completing
       (fn
         ([result input]
          (let [message (:message input)
                decoded-message (decode-message (:value @state) message)
                new-state       (log/spy (fsm @state decoded-message))
                _               (log/debug "new-state" new-state)]
            (reset! state new-state)
            (condp = (get @state :state-index 0)
              4 (merge @state decoded-message)
              5 (merge @state decoded-message)
              nil))))))))
