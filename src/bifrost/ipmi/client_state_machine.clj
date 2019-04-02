(ns bifrost.ipmi.client-state-machine
  (:require [automat.viz :refer [view]]
            [automat.core :as a]
            [buddy.core.nonce :as nonce]
            [taoensso.timbre :as log]
            [bifrost.ipmi.crypto :as crypto]
            [bifrost.ipmi.utils :as u]
            [bifrost.ipmi.messages :as messages]))



(declare ipmi-client-fsm)
(declare ipmi-client-handler)

(defn bind-client-fsm []
  (partial a/advance (a/compile ipmi-client-fsm ipmi-client-handler)))

(defn create-server-rn! []
  (vec (nonce/random-nonce 16)))

(defn create-server-sid! []
  (rand-int (.pow (BigInteger. "2") 16)))

(defn get-session-state [msg]
  (let [sender (:sender msg)
        address (-> (.getAddress sender) (.getHostAddress))
        port (.getPort sender)]
    {:host address :port port}))

(defn get-seq-no [m]
  (get-in m [:rmcp-class :ipmi-session-payload
             :ipmi-1-5-payload :ipmb-payload
             :source-lun :seq-no] 0))

(def ipmi-client-fsm
  [[(a/$ :init)
    (a/* :asm-ping)
    [:get-channel-auth-cap-rsp (a/$ :get-channel-auth-cap-rsp)
     :open-session-response (a/$ :open-session-response)
     :rmcp-rakp-2 (a/$ :rmcp-rakp-2)
     :rmcp-rakp-4 (a/$ :rmcp-rakp-4)]]
   [(a/*
     (a/or
      [:device-id-rsp (a/$ :device-id-rsp)]
      [:hpm-capabilities-rsp (a/$ :hpm-capabilities-rsp)]
      [:picmg-properties-rsp (a/$ :picmg-properties-rsp)]
      [:vso-capabilities-rsp (a/$ :vso-capabilities-rsp)]
      [:set-session-prv-level-rsp (a/$ :session-priv-level-rsp)]))]
   [(a/*
     (a/or
      [:chassis-status-rsp (a/$ :chassis-status-rsp)]
      [:chassis-reset-rsp (a/$ :chassis-reset-rsp)]))]
   [:rmcp-close-session-rsp (a/$ :rmcp-close-session-rsp)]])


;;TODO create schemas for send-message input to test handlers


(def ipmi-client-handler
  {:signal   :type
   :reducers {:init                     (fn [state _]
                                          #_(assoc state :state {}))
              :get-channel-auth-cap-req (fn [state input]
                                          (log/debug "Channel Auth Request")
                                          state)
              :get-channel-auth-cap-rsp (fn [state input]
                                          (log/info "Auth Capabilities Response")
                                          (let [seq   (get-seq-no input)
                                                state (assoc state :seq seq)]
                                            (messages/send-message {:type :get-channel-auth-cap-req :input input :seq seq})
                                            state))
              :open-session-response    (fn [state input]
                                          (log/debug "Open Session Response" input)
                                          (let [remote-sid   (get input :remote-sid)
                                                server-sid   (get input :server-sid)
                                                rolem        (get input :rolem)
                                                auth-codec   (get input :auth-codec)
                                                conf-codec   (get input :conf-codec)
                                                integ-codec  (get input :integ-codec)
                                                msg-type     (get input :type)
                                                [unamem uid] (u/get-user-account)
                                                remote-rn    (u/get-remote-rn)
                                                state        (assoc state
                                                                    :remote-sid  remote-sid
                                                                    :server-sid  server-sid
                                                                    :remote-rn remote-rn
                                                                    :rolem rolem
                                                                    :auth-codec auth-codec
                                                                    :integ-codec integ-codec
                                                                    :conf-codec conf-codec
                                                                    :unamem unamem
                                                                    :uid uid)]
                                            ;; send RAKP1
                                            ;; server-sid
                                            ;; remote-rn
                                            ;; rolem
                                            ;; unamem
                                            (messages/send-message {:type       :rmcp-rakp-1
                                                                    :server-sid server-sid
                                                                    :remote-rn  remote-rn
                                                                    :rolem      rolem
                                                                    :unamem     unamem})
                                            state))
              :rmcp-rakp-2              (fn [state input]
                                          (let [auth        (get state :auth-codec)
                                                remote-rn   (get state :remote-rn)
                                                server-rn   (get input :server-rn)
                                                server-guid (get input :server-guid)
                                                msg-type    (get input :type)
                                                server-kec  (get input :kec)
                                                remote-sid  (get state :remote-sid)
                                                server-sid  (get state :server-sid)
                                                rolem       (get state :rolem)
                                                unamem      (get state :unamem)
                                                uid         (get state :uid)]
                                        ; state       (assoc state
                                        ;                    :server-rn server-rn
                                        ;                   :server-guid server-guid
                                        ;                  :kec kec)]
                                            (condp = auth
                                              :rmcp-rakp           (let [m {:type       :rmcp-rakp-3
                                                                            :auth       auth
                                                                            :input      input
                                                                            :server-sid server-sid}]
                                                                     (messages/send-message m)
                                                                     state)
                                              :rmcp-rakp-hmac-sha1 (let [remote-kec (crypto/calc-rakp-message-3 {:remote-sid remote-sid
                                                                                                                 :server-rn  server-rn
                                                                                                                 :rolem      rolem
                                                                                                                 :unamem     unamem})
                                                                         sik        (crypto/calc-sik {:remote-rn remote-rn
                                                                                                      :server-rn server-rn
                                                                                                      :rolem     rolem
                                                                                                      :unamem    unamem
                                                                                                      :uid       uid})
                                                                         state      (assoc state
                                                                                           :server-kec server-kec
                                                                                           :remote-kec remote-kec
                                                                                           :sik (vec sik))]
                                                                     (messages/send-message {:type       :rmcp-rakp-3
                                                                                             :auth       auth
                                                                                             :state      state
                                                                                             :remote-sid remote-sid
                                                                                             :server-sid server-sid
                                                                                             :kec        remote-kec
                                                                                             })
                                                                     state))))


              ;; Calculate rakp2 HMAC
              ;; Calculate rakp3 HMAC
              ;; Calculate SIK
              ;; Generate K1
              ;; Generate K2
              ;; Send rakp-3

              :rmcp-rakp-4 (fn [state input]
                             ;; Calculate RAKP4 MAC

                             state)
              :device-id-rsp          (fn [state input]
                                        (log/debug "Device ID Response")
                                        state)
              :hpm-capabilities-rsp   (fn [state input]
                                        state)
              :picmg-properties-rsp   (fn [state input]
                                        state)
              :vso-capabilities-rsp   (fn [state input]
                                        state)
              :session-priv-level-rsp (fn [state input]
                                        state)
              :chassis-reset-rsp      (fn [state input]
                                        state)
              :rmcp-close-session-rsp (fn [state input]
                                        state)}})
(comment
  "" "
    sidm     - Remote console session ID                      - remote-sid
    sidc     - BMC (Managed-System) session ID                - server-sid
    rm       - Remote console random number                   - remote-rn
    rc       - BMC (Managed-System) random number             - server-rn
    guidc    - BMC guid                                       - server-guid
    rolem    - Requested privilege level 
    unamem   - Username (absent for null user names) " "")


(defn view-client-fsm []
  (automat.viz/view (a/compile ipmi-client-fsm ipmi-client-handler)))


