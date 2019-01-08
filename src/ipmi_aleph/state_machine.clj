(ns ipmi-aleph.state-machine
  (:require
   [automat.viz :refer [view]]
   [automat.core :as a]
   [gloss.io :refer [encode decode]]
   [ipmi-aleph.codec :as c]
   [manifold.stream :as s]
   [clj-uuid :as uuid]
   [ipmi-aleph.handlers :as h]
   [taoensso.timbre :as log]))

(def udp-session (atom {}))
(def fsm-state   (atom {}))

;; (add-watch fsm-state :watcher
;;            (fn [key atom old-state new-state]
;;              (prn "-- Atom Changed --")
;;              (prn "key" key)
;;              (prn "atom" atom)
;;              (prn "old-state" old-state)
;;              (prn "new-state" new-state)))

(defn get-session-state [msg]
  (let [sender (:sender msg)
        address (-> (.getAddress sender) (.getHostAddress))
        port (.getPort sender)]
    {:host address :port port}))

(defn send-message [session message]
  (let [server-socket (get @udp-session :socket)
        host (get session :host)
        port (get session :port)]
    (log/debug "Sending Message " message " to host:" host " port:" port)
    (s/put! server-socket {:host host
                           :port port
                           :message (encode c/rmcp-header message)})))

(defn send-pong [session message-tag]
  (let [message (h/presence-pong-msg message-tag)]
    (log/info "SEND_PONG " message message-tag)
    (log/debug "Message: " message)
    (send-message session message)))

(defn send-auth-cap-response [session]
  (let [message (h/auth-capabilities-response-msg)]
    (log/info "SEND_AUTH_CAP_RESPONSE: SESSION:" session)
    (log/debug "Message: " message)
    (send-message session message)))

(defn send-open-session-response [session rsid mssid]
  (log/info "SEND_OPEN_SESSION_RESPONSE: SESSION:" session rsid mssid)
  (let [message (h/rmcp-open-session-response-msg rsid mssid)]
    (comment "Need to see if that can be an unsigned 32-bit integer")
    (log/debug "Message: " message)
    (send-message session message)))

(defn send-rakp-2-response [session rsid msrand msguid]
  (log/info "SEND_RAKP_2_REPONSE: SESSION:" session  rsid msrand msguid)
  (let [message (h/rmcp-rakp-2-response-msg rsid msrand msguid)]
    (log/debug "Message: " message)
    (send-message session message)))

(defn send-rakp-4-response [session rsid]
  (log/info "SEND_RAKP_4_REPONSE SID:" rsid)
  (let [message (h/rmcp-rakp-4-response-msg rsid)]
    (log/debug "Message: " message)
    (send-message session message)))

(defn send-rmcp-ack [session seq-no]
  (log/info "Sending rmcp-ack " seq-no)
  (let [message (h/rmcp-ack seq-no)]
    (log/debug "Message: " message)
    (send-message session message)))

(defn send-set-session-priv-level-response [session sid]
  (log/info "Sending Set Session Priv Level Response")
  (let [message (h/set-session-priv-level-rsp-msg sid)]
    (log/debug "Message: " message)
    (send-message session message)))

(defn send-rmcp-close-response [session sid seq]
  (log/info "Sending RMCP Close Response")
  (let  [message (h/rmcp-close-response-msg sid seq)]
    (log/debug "Message: " message)
    (send-message session message)))

(defn send-chassis-status-response [session sid]
  (log/info "Sending Status Chassis Response: ")
  (let [message (h/chassis-status-response-msg sid)]
    (log/debug "Message: " message)
    (send-message session message)))

(def ipmi-fsm
  [(a/* (a/$ :init)
        (a/or
         [:asf-ping (a/$ :asf-ping)]
         (a/*
          [:get-channel-auth-cap-req (a/$ :get-channel-auth-cap-req)
           :open-session-request (a/$ :open-session-request)
           :rmcp-rakp-1 (a/$ :rmcp-rakp-1)
           :rmcp-rakp-3 (a/$ :rmcp-rakp-3)]
          (a/* (a/or
                 [:chassis-status-req (a/$ :chassis-status)]
                 [:set-session-priv-level (a/$ :session-priv-level)]))
          [:rmcp-close-session (a/$ :rmcp-close-session)])))])

(def ipmi-fsm-sample
  [(a/or (a/* [:Z])
         (a/or (a/* [:A :B :C]
                    (a/or [:D] [:E] [:F])
                    [:G])))])

(def ipmi-handler
  {:signal #(:type  (log/spy (c/get-message-type %)))
   :reducers {:init (fn [state _] (assoc state :last-message []))
              :chassis-status (fn [state input]
                                (log/debug "Chassis Status Request")
                                (let [message (conj {} (c/get-message-type input))
                                      state (update-in state [:last-message] conj message)
                                      sid (get state :sid)]
                                  (send-chassis-status-response input sid)
                                  state))
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
                                            mssid (rand-int (.pow (BigInteger. "2") 16))
                                            state (-> state
                                                      (update-in [:last-message] conj message)
                                                      (assoc :sid sid)
                                                      (assoc :mssid mssid))]
                                        (send-open-session-response input sid mssid)
                                        state))
              :rmcp-rakp-1 (fn [state input]
                             (log/debug "RAKP-1 Request")
                             (let [message (conj {} (c/get-message-type input))
                                   state (update-in state [:last-message] conj message)
                                   msrand  (vec (take 16 (repeatedly #(rand-int 16))))
                                   msguid (vec (uuid/as-byte-array (uuid/v4)))
                                   rsid (get state :sid)]
                               (send-rakp-2-response input rsid msrand msguid)
                               state))
              :rmcp-rakp-3 (fn [state input]
                             (log/debug "RAKP-3 Request " state)
                             (let [message (conj {} (c/get-message-type input))
                                   state (update-in state [:last-message] conj message)
                                   ms-sid (get-in input [:rmcp-class :ipmi-session-payload :ipmi-2-0-payload :managed-system-session-id])
                                   user-name (get-in input [:rmcp-class :ipmi-session-payload :ipmi-2-0-payload :user-name])
                                   remote-random-number (get-in input [:rmcp-class :ipmi-session-payload :ipmi-2-0-payload :remote-console-random-number])
                                        ;(def a (-> (cod/long->bytes (.pow (BigInteger. "2") 32)) (cod/to-bytes)))
                                   sid (get state :sid)]
                               (send-rakp-4-response input sid)
                               state))
              :session-priv-level (fn [state input]
                                    (log/debug "State " state)
                                    (log/debug "Set Session Priv Level")
                                    (let [message (conj {} (c/get-message-type input))
                                          sid (get state :sid)
                                          seq (get-in input [:rmcp-class :ipmi-session-payload :ipmi-2-0-payload :session-seq] 0)
                                          state (-> state
                                                    (update-in [:last-message] conj message)
                                                    (assoc :sid sid)
                                                    (assoc :seq seq))]
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
                            state))
              :rmcp-close-session (fn [state input]
                                    (log/debug "Session Closing " state)
                                    (let [sid (get state :sid)
                                          seq (get-in input [:rmcp-class :ipmi-session-payload :ipmi-2-0-payload :session-seq] 0)]
                                      (send-rmcp-close-response input sid seq)
                                      (reset! fsm-state {})
                                      nil))}})

(defn view-fsm []
  (automat.viz/view (a/compile ipmi-fsm ipmi-handler)))

(defn view-fsm-sample []
  (automat.viz/view (a/compile ipmi-fsm-sample ipmi-handler)))
