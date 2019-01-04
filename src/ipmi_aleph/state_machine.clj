(ns ipmi-aleph.state-machine
  (:require
   [automat.viz :refer [view]]
   [automat.core :as a]
   [gloss.io :refer [encode decode]]
   [ipmi-aleph.codec :as c]
   [manifold.stream :as s]
   [ipmi-aleph.handlers :as h]
   [taoensso.timbre :as log]))

(def udp-session (atom {}))
(def fsm-state   (atom {}))

(add-watch fsm-state :watcher
           (fn [key atom old-state new-state]
             (prn "-- Atom Changed --")
             (prn "key" key)
             (prn "atom" atom)
             (prn "old-state" old-state)
             (prn "new-state" new-state)))

(defn get-session-state [msg]
  (let [sender (:sender msg)
        address (-> (.getAddress sender) (.getHostAddress))
        port (.getPort sender)]
  {:host address :port port}))

(defn send-pong [session message-tag]
  (log/debug "SEND_PONG " session message-tag)
  (let [server-socket (get @udp-session :socket)
        host (get session :host)
        port (get session :port)]
    (log/debug "Sending RMCP-PONG to host:" host " port:" port)
    (s/put! server-socket {:host host
                           :port port
                           :message (encode c/rmcp-header (h/presence-pong-msg message-tag))})))

(defn send-auth-cap-response [session]
  (log/debug "SEND_AUTH_CAP_RESPONSE: SESSION:" session)
  (let [server-socket (get @udp-session :socket)
        host (get session :host )
        port (get session :port)]
    (s/put! server-socket {:host host
                           :port port
                           :message (encode c/rmcp-header (h/auth-capabilities-response-msg))})))

(defn send-open-session-response [session]
  (log/debug "SEND_OPEN_SESSION_RESPONSE: SESSION:" session)
  (let [server-socket (get @udp-session :socket)
        host (get session :host)
        port (get session :port)]
    (s/put! server-socket {:host host
                           :port port
                           :message (encode c/rmcp-header (h/rmcp-open-session-response-msg 0 0))})))

(defn send-rakp-2-response [session]
  (log/debug "SEND_RAKP_2_REPONSE: SESSION:" session)
  (let [server-socket (get @udp-session :socket)
        host (get session :host)
        port (get session :port)]
    (s/put! server-socket {:host host
                           :port port
                           :message (encode c/rmcp-header (h/rmcp-rakp-2-response-msg))})))

(defn send-rakp-4-response [session]
  (log/debug "SEND_RAKP_4_REPONSE: SESSION:" session)
  (let [server-socket (get @udp-session :socket)
        host (get session :host)
        port (get session :port)]
    (s/put! server-socket {:host host
                           :port port
                           :message (encode c/rmcp-header (h/rmcp-rakp-4-response-msg))})))

(defn send-rmcp-ack [session seq-no]
  (let [server-socket (get @udp-session :socket)
        host (get session :host)
        port (get session :port)]
    (log/info "Sending rmcp-ack id: " seq-no" host: " host " port: " port)
    (s/put! server-socket {:host host
                           :port port
                           :message (encode c/rmcp-header (h/rmcp-ack seq-no))})))

(defn send-set-session-priv-level-response [session seq-no]
  (let [server-socket (get @udp-session :socket)
        host (get session :host)
        port (get session :port)]
    (log/info "Sending Set Session Priv Level Response host: " host " port: " port)
    (s/put! server-socket {:host host
                           :port port
                           :message (encode c/rmcp-header (h/set-session-priv-level-rsp-msg seq-no))})))


(defn send-rmcp-close-response [session sid]
  (let [server-socket (get @udp-session :socket)
        host (get session :host)
        port (get session :port)]
    (log/info "Sending RMCP Close Response host: " host " port: " port " sid:" sid)
    (s/put! server-socket {:host host
                           :port port
                           :message (encode c/rmcp-header (h/rmcp-close-response-msg sid))})))


(def ipmi-fsm
  [(a/+
    (a/$ :init)
    (a/or
     (a/+ [:asf-ping (a/$ :asf-ping)])
     (interpose (a/* a/any)
      [:get-channel-auth-cap-req (a/$ :get-channel-auth-cap-req)
       :open-session-request (a/$ :open-session-request)
       :rmcp-rakp-1 (a/$ :rmcp-rakp-1)
       :rmcp-rakp-3 (a/$ :rmcp-rakp-3)
       :set-session-priv-level (a/$ :set-session-priv-level)
       :rmcp-close-session (a/$ :rmcp-close-session)])))])

(def ipmi-handler
   {:signal #(:type (c/get-message-type %))
                                 :reducers {:init (fn [state _] (assoc state :last-message []))
                                            :rmcp-close-session (fn [state input]
                                                                  (log/debug "Session Closing " state)
                                                                  (let [sid (get state :sid)]
                                                                    (send-rmcp-close-response input sid)
                                                                    (log/debug "Resetting Session State")
                                                                    (reset! fsm-state {})
                                                                    (log/debug "++++" @fsm-state)
                                                                    (reset! fsm-state {})
                                                                    nil))
                                            :get-channel-auth-cap-req (fn [state input]
                                                                        (let [message (conj {} (c/get-message-type input))
                                                                              state (update-in state [:last-message] conj message)]
                                                                          (log/debug "Auth Capabilities Request")
                                                                          (send-auth-cap-response input)
                                                                          state))
                                            :open-session-request (fn [state input]
                                                                    (log/debug "Open Session Request ")
                                                                    (let [message (conj {} (c/get-message-type input))
                                                                          sid (get-in input [:rmcp-class :ipmi-session-payload :ipmi-2-0-payload :remote-session-id])
                                                                          state (-> state
                                                                                    (update-in [:last-message] conj message)
                                                                                    (assoc :sid sid))]
                                                                      (send-open-session-response input)
                                                                      state))
                                            :rmcp-rakp-1 (fn [state input]
                                                           (log/debug "RAKP-1 Request")
                                                           (let [message (conj {} (c/get-message-type input))
                                                                 state (update-in state [:last-message] conj message)]
                                                             (send-rakp-2-response input)
                                                             state))
                                            :rmcp-rakp-3 (fn [state input]
                                                           (log/debug "RAKP-3 Request")
                                                           (let [message (conj {} (c/get-message-type input))
                                                                 state (update-in state [:last-message] conj message)]
                                                             (send-rakp-4-response input)
                                                             state))
                                            :set-session-priv-level (fn [state input]
                                                                      (log/debug "Set Session Priv Level")
                                                                      (let [message (conj {} (c/get-message-type input))
                                                                            sid (get input :remote-session-id)
                                                                            state (update-in state [:last-message] conj message)]
                                                                        (log/debug "INPUT: " input " Seq: " sid)
                                                                        (send-set-session-priv-level-response input sid)
                                                                        state))
                                            :asf-ping (fn [state input]
                                                        (log/debug "ASF PING")
                                                        (let [message-tag (get-in input [:rmcp-class
                                                                                         :asf-payload
                                                                                         :asf-message-header
                                                                                         :message-tag])
                                                              message-type (conj {} (c/get-message-type input))
                                                              message (assoc message-type :message-tag message-tag)]
                                                          (send-pong input message-tag)
                                                          state))}})


(defn view-fsm []
  (automat.viz/view (a/compile ipmi-fsm ipmi-handler)))

