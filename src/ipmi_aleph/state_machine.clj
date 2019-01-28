(ns ipmi-aleph.state-machine
  (:require
   [automat.viz :refer [view]]
   [automat.core :as a]
   [gloss.io :refer [encode decode]]
   [ipmi-aleph.codec :as c]
   [ipmi-aleph.packet :as p]
   [ipmi-aleph.crypto :refer [calc-sha1-key]]
   [manifold.stream :as s]
   [clj-uuid :as uuid]
   [ipmi-aleph.handlers :as h]
   [taoensso.timbre :as log]
   [buddy.core.codecs :as codecs]
   [buddy.core.bytes :as bytes]
   [byte-streams :as bs]))

(def udp-session (atom {}))
(def fsm-state   (atom {}))

(declare ipmi-fsm)
(declare ipmi-handler)

(defn fsm []
  (let [fsm (a/compile ipmi-fsm ipmi-handler)]
    (partial a/advance fsm)))




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
        port (get session :port)
        ipmi-encode (partial encode (c/compile-codec))
        payload (ipmi-encode message)]
    (log/debug "Sending Message " message " to host:" host " port:" port)
    (log/debug  "Bytes" (-> payload
                            bs/to-byte-array
                            codecs/bytes->hex))
    (s/put! server-socket {:host host
                           :port port
                           :message payload})))

(defn send-pong [session message-tag]
  (let [message (h/presence-pong-msg message-tag)]
    (log/info "SEND_PONG " message message-tag)
    (send-message session message)))

(defn send-auth-cap-response [session]
  (let [message (h/auth-capabilities-response-msg)]
    (log/info "SEND_AUTH_CAP_RESPONSE: SESSION:" session)
    (send-message session message)))

(defn send-open-session-response [session sidc sidm a i c]
  (log/info "SEND_OPEN_SESSION_RESPONSE: SESSION:" session)
  (let [message (h/rmcp-open-session-response-msg sidc sidm a i c )]
    (comment "Need to see if that can be an unsigned 32-bit integer")
    (send-message session message)))

(defn send-rakp-2-response [session ks]
  (log/info "SEND_RAKP_2_REPONSE: SESSION:" session)
  (let [message (log/spy (h/rmcp-rakp-2-response-msg ks))]
    (send-message session message)))

(defn send-rakp-4-response [session rsid]
  (log/info "SEND_RAKP_4_REPONSE SID:" rsid)
  (let [message (h/rmcp-rakp-4-response-msg rsid)]
    (send-message session message)))

(defn send-rmcp-ack [session seq-no]
  (log/info "Sending rmcp-ack " seq-no)
  (let [message (h/rmcp-ack seq-no)]
    (send-message session message)))

(defn send-set-session-priv-level-response [session sid]
  (log/info "Sending Set Session Priv Level Response")
  (let [message (h/set-session-priv-level-rsp-msg sid)]
    (send-message session message)))

(defn send-rmcp-close-response [session sid seq]
  (log/info "Sending RMCP Close Response")
  (let  [message (h/rmcp-close-response-msg sid seq)]
    (send-message session message)))

(defn send-chassis-status-response [session sid]
  (log/info "Sending Status Chassis Response: ")
  (let [message (h/chassis-status-response-msg sid)]
    (send-message session message)))

(defn send-device-id-response [session sid]
  (log/info "Sending Device ID Response: ")
  (let [message (h/device-id-response-msg sid)]
    (send-message session message)))

(defn send-chassis-reset-response [session sid seq]
  (log/info "Sending Chassis Reset Response: ")
  (let [message (h/chassis-reset-response-msg sid seq)]
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
                [:chassis-reset-req (a/$ :chassis-reset)]
                [:device-id-req (a/$ :device-id-req)]
                [:set-session-prv-level-req (a/$ :session-priv-level)]))
          [:rmcp-close-session-req (a/$ :rmcp-close-session)])))])
(def ipmi-fsm-sample
  [(a/or (a/* [:Z])
         (a/or (a/* [:A :B :C]
                    (a/or [:D] [:E] [:F])
                    [:G])))])

(def ipmi-handler
  {:signal   #(:type  (log/spy (c/get-message-type %)))
   :reducers {:init           (fn [state _] (assoc state :last-message []))
              :chassis-status (fn [state input]
                                (log/debug "Chassis Status Request")
                                (let [message (conj {} (c/get-message-type input))
                                      state   (update-in state [:last-message] conj message)
                                      sid     (get state :sidc)]
                                  (send-chassis-status-response input sid)
                                  state))
              :device-id-req  (fn [state input]
                                (log/debug "Device ID Request")
                                (let [message (conj {} (c/get-message-type input))
                                      state   (update-in state [:last-message] conj message)
                                      sid     (get state :sidc)]
                                  (send-device-id-response input sid)
                                  state))
              :chassis-reset  (fn [state input]
                                (log/debug "Chassis Reset Request -->" input)
                                (let [message (conj {} (c/get-message-type input))
                                      state   (update-in state [:last-message] conj message)
                                      sid     (get state :sidc)
                                      seq     (get-in input [:rmcp-class :ipmi-session-payload :ipmi-2-0-payload :session-seq] 0)]
                                  (send-chassis-reset-response input sid seq)
                                        ;(reboot-device [device api-key])

                                  state))
              :get-channel-auth-cap-req (fn [state input]
                                          (let [message (conj {} (c/get-message-type input))
                                                state   (update-in state [:last-message] conj message)]
                                            (log/debug "Auth Capabilities Request")
                                            (send-auth-cap-response input)
                                            state))
              :open-session-request     (fn [state input]
                                          (log/debug "Open Session Request ")
                                          (let [message                 (conj {} (c/get-message-type input))
                                                auth-payload            (get-in input [:rmcp-class :ipmi-session-payload
                                                                                       :ipmi-2-0-payload :authentication-payload
                                                                                       :algo
                                                                                       :algorithm])
                                                integrity-payload       (get-in input [:rmcp-class :ipmi-session-payload
                                                                                       :ipmi-2-0-payload :integrity-payload
                                                                                       :algo
                                                                                       :algorithm])
                                                confidentiality-payload (get-in  input [:rmcp-class :ipmi-session-payload
                                                                                        :ipmi-2-0-payload :confidentiality-payload
                                                                                        :algo :algorithm])
                                                sidm                    (get-in input [:rmcp-class :ipmi-session-payload
                                                                                       :ipmi-2-0-payload
                                                                                       :remote-session-id])
                                                sidc                    (rand-int (.pow (BigInteger. "2") 16))
                                                rolem                   (get-in input [:rmcp-class :ipmi-session-payload
                                                                                       :ipmi-2-0-payload :privilege-level
                                                                                       :max-priv-level])
                                                state                   (-> state
                                                                            (update-in [:last-message] conj message)
                                                                            (merge {:sidc                    sidc
                                                                                    :sidm                    sidm
                                                                                    :priv-level              rolem
                                                                                    :authentication-payload  auth-payload
                                                                                    :confidentiality-payload confidentiality-payload
                                                                                    :integrity-payload       integrity-payload}))]
                                        ; TODO Need selector for auth, ident, conf types
                                            (send-open-session-response input sidc sidm 1 0 0)
                                            state))
              :rmcp-rakp-1              (fn [state input]
                                          (log/debug "RAKP-1 Request")
                                          (log/debug "DEBUG STATE" state)
                                          (let [message     (conj {} (c/get-message-type input))
                                                rm          (get-in input [:rmcp-class :ipmi-session-payload
                                                                           :ipmi-2-0-payload :remote-console-random-number])
                                                rc          (vec (take 16 (repeatedly #(rand-int 16))))
                                                guidc       (vec (uuid/as-byte-array (uuid/v4)))
                                                unamem      (get-in input [:rmcp-class :ipmi-session-payload
                                                                           :ipmi-2-0-payload :user-name])
                                                uid         (bytes/slice (codecs/str->bytes unamem) 0 20)
                                                ulengthm    (byte-array 1 (byte (count unamem)))
                                                role        (:priv-level state)
                                                state       (-> state
                                                                (update-in [:last-message] conj message)
                                                                (merge {:rm rm :rc rc :guidc guidc :role role}))
                                        ; Calculate hash for response
                                                sidm        (-> (encode c/int->bytes (:sidm state)) bs/to-byte-array reverse)
                                                sidc        (-> (encode c/int->bytes (:sidc state)) bs/to-byte-array reverse) 
                                                rolem       (byte-array 1 (byte role))
                                                rakp2-input (buddy.core.bytes/concat sidm sidc (byte-array rm) (byte-array rc) guidc rolem )
                                                rakp2-hmac  (calc-sha1-key uid rakp2-input)
                                                auth        (-> (get c/authentication-codec (:authentication-payload state)) :codec)]
                                            (log/debug "\nRM" rm "\nRC "rc "\nSIDM "sidm "\nSIDC " sidc "\nROLEM " rolem "\nRAKP2-INPUT" rakp2-input "\nRAKP2-HMAC" rakp2-hmac)

                                            (send-rakp-2-response  input {:sidm       (:sidm state)
                                                                          :rc         rc
                                                                          :guidc      guidc
                                                                          :rakp2-hmac (vec rakp2-hmac)
                                                                          :auth       auth})
                                            state))
              :rmcp-rakp-3              (fn [state input]
                                          (log/debug "RAKP-3 Request " state)
                                          (let [message              (conj {} (c/get-message-type input))
                                                state                (update-in state [:last-message] conj message)
                                                ms-sid               (get-in input [:rmcp-class :ipmi-session-payload :ipmi-2-0-payload :managed-system-session-id])
                                                user-name            (get-in input [:rmcp-class :ipmi-session-payload :ipmi-2-0-payload :user-name])
                                                remote-random-number (get-in input [:rmcp-class :ipmi-session-payload :ipmi-2-0-payload :remote-console-random-number])
                                        ;(def a (-> (cod/long->bytes (.pow (BigInteger. "2") 32)) (cod/to-bytes)))
                                                sid                  (get state :sid)]
                                            (send-rakp-4-response input sid)
                                            state))
              :session-priv-level       (fn [state input]
                                          (log/debug "State " state)
                                          (log/debug "Set Session Priv Level")
                                          (let [message (conj {} (c/get-message-type input))
                                                sid     (get state :sidc)
                                                seq     (get-in input [:rmcp-class :ipmi-session-payload :ipmi-2-0-payload :session-seq] 0)
                                                state   (-> state
                                                            (update-in [:last-message] conj message)
                                                            (assoc :seq seq))]
                                            (send-set-session-priv-level-response input sid)
                                            state))
              :asf-ping                 (fn [state input]
                                          (log/debug "ASF PING")
                                          (let [message-tag  (get-in input [:rmcp-class
                                                                            :asf-payload
                                                                            :asf-message-header
                                                                            :message-tag])
                                                message-type (conj {} (c/get-message-type input))
                                                message      (assoc message-type :message-tag message-tag)]
                                            (send-pong input message-tag)
                                            state))
              :rmcp-close-session       (fn [state input]
                                          (log/debug "Session Closing " state)
                                          (let [sid (get state :sidc)
                                                seq (get-in input [:rmcp-class :ipmi-session-payload :ipmi-2-0-payload :session-seq] 0)]
                                            (send-rmcp-close-response input sid seq)
                                        ;(reset! fsm-state {})
                                            state))}})

(defn view-fsm []
  (automat.viz/view (a/compile ipmi-fsm ipmi-handler)))

(defn view-fsm-sample []
  (automat.viz/view (a/compile ipmi-fsm-sample ipmi-handler)))
