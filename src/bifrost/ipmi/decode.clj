(ns bifrost.ipmi.decode
  (:require [bifrost.ipmi.state-machine :as state]
            [bifrost.ipmi.codec :as c]
            [clojure.core.async :as async]
            [gloss.io :as i]
            [taoensso.timbre :as log]
            [byte-streams :as bs]
            [buddy.core.codecs :as codecs]))


(defn get-fct [msg]
  (let [f (get-in msg [:rmcp-class :ipmi-session-payload :ipmi-2-0-payload :network-function :function])
        c (get-in msg [:rmcp-class :ipmi-session-payload :ipmi-2-0-payload :command])
        t (get-in msg [:rmcp-class :ipmi-session-payload :ipmi-2-0-payload :payload-type :type])
        ]
    {:function f :command c :type t}))

(defn decode-parser [msg]
  (log/debug "Decode Parser" (get-fct msg))
  (try
    (c/get-message-type msg)
    (catch Exception e
      (throw (ex-info "Error in parser"
                      {:error (.getMessage e)
                       :msg msg})))))

(defn decode-message
  "This function takes a map _state_ with the current state of the decode pipeline used to
  feed dispatching of encrypted payloads to the codec and a byte-array representing the IPMI
  message which is passed to the decoder library"
  [state message]
  (let [codec        (c/compile-codec state)
        decoded      (try
                       (i/decode codec message) 
                       (catch Exception e
                         (log/error (ex-info "Decoder exception"
                                             {:error   (.getMessage e)
                                              :payload (if (bytes? message)
                                                         (codecs/bytes->hex message)
                                                         message)}))
                         nil))
        aes-payload? (contains?
                      (get-in decoded [:rmcp-class :ipmi-session-payload :ipmi-2-0-payload])
                      :aes-decoded-payload)
        message      (if aes-payload?
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

(defn decode
  "This function takes as input _state_ which is fed to the decode-message function to select appropriate codec
  for encryption types and the byte-array for the IPMI message. It returns a new map with the transformation from
  IPMI decode to a selection map that is passed into the state-machine. Output is a map with keys [:type :state :message]"
  [state msg]
  (decode-parser (decode-message state (byte-array msg)))
  #_(try
    (some->>
     (byte-array msg)
      (decode-message state)
      (decode-parser))
    (catch Exception e
      (throw (ex-info "Error in decode"
                      {:message (.getMessage e)
                       :state   state})))))

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
         (let [udp-message      (get item :message)
               host-map         (state/get-session-state udp-message)
               payload          (:message udp-message)
               decoded-message  (decode (get @state  :value) payload)
               decorate-message (merge host-map decoded-message)
               new-state        (try
                                  (fsm @state decorate-message)
                                  (catch IllegalArgumentException e
                                    (log/error (ex-info "State Machine Error"
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
  (throw (ex-info  "Exception while processing message"
                             {:message ex})))

(defn make-server-decoder []
  (let [decoder-chan (async/chan 10 (server-decoder-xf (state/bind-server-fsm)) ex-handler)]
    decoder-chan))

(defn make-client-decoder [fsm]
  (let [decoder-chan (async/chan 10 (client-decoder-xf fsm) ex-handler)]
    decoder-chan))
