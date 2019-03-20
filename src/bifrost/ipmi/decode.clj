(ns bifrost.ipmi.decode
  (:require [bifrost.ipmi.state-machine :as state]
            [bifrost.ipmi.codec :as c]
            [clojure.core.async :as async]
            [gloss.io :as i]
            [taoensso.timbre :as log]
            [byte-streams :as bs]
            [buddy.core.codecs :as codecs]))

(defn decode-message [state message]
  (let [codec (c/compile-codec state)
        decoded (try
                  (i/decode codec message false)
                  (catch Exception e
                    (throw (ex-info "Decoder exception"
                                    {:error (.getMessage e)
                                     :payload (if (bytes? message)
                                                (codecs/bytes->hex message)
                                                message)}))
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
    (log/debug "Decoded Message " message)
    message))

(defn decode-parser [msg]
  (c/get-message-type msg))

(defn decode [state msg]
  (->>
   msg
   (decode-message state)
   decode-parser))

(defn get-session-state [msg]
  (let [sender (:sender msg)
        address (-> (.getAddress sender) (.getHostAddress))
        port (.getPort sender)]
    {:host address :port port}))

(defn server-decoder-xf [fsm]
  (fn [xf]
    (let [state (atom {})]
      (fn
        ([] (xf))
        ([result] (xf result))
        ([result item]
         (let [message (get item :message)
               host-map (state/get-session-state message)
               payload (:message message)
               decoded-message (decode (get-in @state [:value :state]) payload)
               decorate-message (merge host-map decoded-message)
               new-state       (try
                                 (fsm @state decorate-message)
                                 (catch IllegalArgumentException e
                                   (throw (ex-info "State Machine Error"
                                                   {:error   (.getMessage e)
                                                    :state   @state
                                                    :message decorate-message}))
                                   nil))]
           (log/debug "New State" new-state)
           (reset! state new-state)
           (condp = (:state-index new-state)
             6 (do (reset! state {}) (log/debug "Reseting State to " @state)  (reduced result))
             7 (do (log/debug "Command Message" (:type decorate-message))
                   (xf result (assoc {} :type :command :state (:value @state) :message decorate-message)))
             {})))))))

(defn client-decoder-xf [fsm]
  (fn [xf]
    (let [state (atom {})]
      (fn
        ([] (xf))
        ([result] (xf result))
        ([result item]
         (let [host-map        (state/get-session-state item)
               payload         (:message item)
               decoded-message (decode (:value @state) payload)
               decorate-message (merge host-map decoded-message)
               new-state       (try
                                 (fsm @state decorate-message)
                                 (catch IllegalArgumentException e
                                   (throw (ex-info "State Machine Error"
                                                   {:error   (.getMessage e)
                                                    :state   @state
                                                    :message decorate-message}))
                                   nil))]
           (log/debug "New State" new-state)
           (reset! state new-state)
           (condp = (:state-index new-state)
             7 (reduced result)
             6 (xf result (assoc {} :type :command :state (:value @state) :message decorate-message))
             {})))))))

(defn ex-handler [ex]
  (log/error "Exception while processing message" ex))

(defn make-server-decoder []
  (let [decoder-chan (async/chan 10 (server-decoder-xf (state/bind-server-fsm)) ex-handler)]
    decoder-chan))

(defn make-client-decoder [fsm]
  (let [decoder-chan (async/chan 10 (client-decoder-xf fsm) ex-handler)]
    decoder-chan))
