(ns bifrost.ipmi.decode
  (:require [bifrost.ipmi.state-machine :as state]
            [bifrost.ipmi.codec :as c]
            [gloss.io :as i]
            [taoensso.timbre :as log]))

(defn decode-message [state udp-message]
  (let [host-map        (state/get-session-state udp-message)
        encoded-message (:message udp-message)
        codec           (c/compile-codec state)
        decoded         (try
                          (i/decode codec encoded-message)
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
    (let [state (atom {})
          _     (log/debug "STATE " @state)]
      (fn
        ([result] result)
        ([result input]
         (let [decoded-message (decode-message (:value @state) input)]
           (condp = (log/spy (get @state :state-index 0))
             5 (do
                 (reset! state (fsm @state decoded-message))
                 (xf result decoded-message))
               6 (reset! state {})
               (do
                 (reset! state (fsm @state decoded-message))
                 #_(xf result @state)))
           ))))))
