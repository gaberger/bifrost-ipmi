(ns bifrost.ipmi.messages
  (:require [manifold.stream :as s]
            [byte-streams :as bs]
            [taoensso.timbre :as log]
            [buddy.core.codecs :as codecs]
            [gloss.io :as i]
            [bifrost.ipmi.handlers :as h]
            [bifrost.ipmi.codec :as c]
            [bifrost.ipmi.utils :as u]))

(defonce server-socket (atom nil))

(defn send-udp [session message]
  {:pre (string? (:host session))}
  (let [host  (get session :host)
        port  (get session :port)
        bytes (-> message bs/to-byte-array)]
    (log/info "Sending Message to host:" host " port:" port)
    (log/debug  "Bytes" (-> message
                            bs/to-byte-array
                            codecs/bytes->hex))
    (try
      (s/put! @server-socket {:host    host
                              :port    port
                              :message bytes})
      (catch Exception e
        (throw (ex-info "Exception sending udp"
                        {:host    host
                         :port    port
                         :message bytes
                         :error   (.getMessage e)}))
        false))))

(defn encode-message [state message]
  (let [codec (c/compile-codec state)
        ipmi-encode (partial i/encode codec)]
    (ipmi-encode message)))

(defmulti send-message :type)
(defmethod send-message :error-response [{:keys [state remote-sid sa ta session-seq command seq-no function status csum a e]}]
  (log/info "Sending Response: ")
  (let [message             (h/error-response-msg remote-sid sa ta session-seq command seq-no function status csum a e)
        encoded-message     (encode-message nil message)]
    (u/safe (send-udp state encoded-message))))

(defmulti send-message :type)
(defmethod send-message :chassis-status [{:keys [state remote-sid seq-no a e]}]
  (log/info "Sending Status Chassis Response: ")
  (let [message             (h/chassis-status-response-msg remote-sid seq-no a e)
        encoded-message     (encode-message nil message)]
    (u/safe (send-udp state encoded-message))))

(defmethod send-message :device-id-req [{:keys [state remote-sid seq-no a e]}]
  (log/info "Sending Device ID  Response: ")
  (let [message             (h/device-id-response-msg remote-sid seq-no a e)
        encoded-message     (encode-message nil message)]
    (u/safe (send-udp state encoded-message))))

(defmethod send-message :chassis-reset [{:keys [state remote-sid session-seq seq-no a e]}]
  (log/info "Sending Chassis Reset Response")
  (let [message         (h/chassis-reset-response-msg remote-sid seq-no a e)
        encoded-message (encode-message nil message)]
    (u/safe (send-udp state encoded-message))))

(defmethod send-message :get-channel-auth-cap-req [state seq-no]
  (log/info "Sending Chassis Auth Capability Response")
  (let [message         (h/auth-capabilities-response-msg seq-no)
        encoded-message (encode-message nil message)]
    (u/safe (send-udp state encoded-message))))

(defmethod send-message :auth-capabiities-request-msg [{:keys [state]}]
  (let [message         (h/auth-capabilities-request-msg)
        encoded-message (encode-message message)]
    (u/safe (send-udp state encoded-message))))

(defmethod send-message :open-session-request [{:keys [state remote-sid server-sid a i c]}]
  (log/info "Sending Open Session Response ")
  (let [message         (h/rmcp-open-session-response-msg remote-sid server-sid a i c)
        encoded-message  (encode-message nil message)]
    (u/safe (send-udp state encoded-message))))

(defmethod send-message :rmcp-rakp-1 [{:keys [state server-sid remote-rn rolem unamem]}]
  (log/info "Sending RAKP1")
  (let [message         (h/rmcp-rakp-1-request-msg server-sid remote-rn rolem unamem)
        encoded-message (encode-message nil message)]
    (u/safe (send-udp state encoded-message))))

(defmethod send-message :rmcp-rakp-2 [state]
  (log/info "Sending RAKP2")
  (let [message         (h/rmcp-rakp-2-response-msg)
        encoded-message (encode-message nil message)]
    (u/safe (send-udp state encoded-message))))

(defmethod send-message :rmcp-rakp-3 [{:keys [auth state remote-sid server-sid kec]}]
(log/info "Sending RAKP1")
(let [message         (h/rmcp-rakp-3-request-msg {:auth auth :remote-sid remote-sid :server-sid server-sid :kec kec})
  encoded-message (encode-message state message)]
(u/safe (send-udp state encoded-message))))


(defmethod send-message :rmcp-rakp-4 [{:keys [state server-sid]}]
  (log/info "Sending RAKP4")
  (let [message              (h/rmcp-rakp-4-response-msg server-sid)
        encoded-message      (encode-message nil message)]
    (u/safe (send-udp state encoded-message))))

(defmethod send-message :session-priv-level [{:keys [state remote-sid session-seq-no seq-no a e]}]
  (log/info "Sending Session Priv Level Response")
  (let [message             (h/set-session-priv-level-rsp-msg remote-sid session-seq-no seq-no a e)
        encoded-message     (encode-message nil message)]
    (u/safe (send-udp state encoded-message))))

(defmethod send-message :rmcp-close-session [{:keys [state remote-sid session-seq seq-no a e]}]
  (log/info "Sending Session Close Response")
  (let [message                 (h/rmcp-close-response-msg remote-sid session-seq seq-no a e)
        encoded-message         (encode-message nil message)]
    (u/safe (send-udp state encoded-message))))

(defmethod send-message :asf-ping [{:keys [state message-tag]}]
  (log/info "Sending Ping Response")
  (let [message                     (h/presence-pong-msg message-tag)
        encoded-message             (encode-message nil message)]
    (u/safe (send-udp state encoded-message))))

(defmethod send-message :hpm-capabilities-req [{:keys [state remote-sid seq-no a e]}]
  (log/info "Sending HPM Capabilities Response")
  (let [message         (h/hpm-capabilities-response-msg remote-sid seq-no a e)
        encoded-message (encode-message nil message)]
    (u/safe (send-udp state encoded-message))))

(defmethod send-message :picmg-properties-req [{:keys [state remote-sid seq-no a e]}]
  (log/info "Sending PICMG Properties Response")
  (let [message         (h/picmg-response-msg remote-sid seq-no a e)
        encoded-message (encode-message nil message)]
    (u/safe (send-udp state encoded-message))))

(defmethod send-message :vso-capabilities-req [{:keys [state remote-sid seq-no a e]}]
  (log/info "Sending VSO Capabilities Response")
  (let [message         (h/vso-response-msg remote-sid seq-no a e)
        encoded-message (encode-message nil message)]
    (u/safe (send-udp state encoded-message))))

;; (defn send-rmcp-ack [session seq-no]
;;   (log/info "Sending rmcp-ack " seq-no)
;;   (let [message         (h/rmcp-ack seq-no)
;;         codec           (c/compile-codec (:hash input))
;;         ipmi-encode     (partial encode codec)
;;         encoded-message (u/safe (ipmi-encode message))]
;;     (send-message session encoded-message)))

