(ns ipmi-aleph.codec
  (:require [gloss.core :refer [defcodec compile-frame bit-map
                                ordered-map header finite-frame
                                string enum]]
            [clojure.string :as str]
            [clojure.datafy :as d]
            [clojure.walk :as w]
            [gloss.io :refer [decode]]
            [taoensso.timbre :as log]
            [taoensso.timbre.appenders.core :as appenders]))

(log/refer-timbre)
(log/merge-config! {:appenders {:println {:enabled? true}}})
#_(log/merge-config!
   {:appenders
    {:spit (appenders/spit-appender {:fname (str/join [*ns* ".log"])})}})

(defn build-merge-header-with-data
  "Build a function that takes a header and returns a compiled
  frame (using `frame-fn`) that post-processes the frame to merge the
  header and the data."
  [frame-fn]
  (fn [h]
    (compile-frame
     (frame-fn h)
     identity
     (fn [data]
       (merge h data)))))

(defn get-message-type [m]
  (log/debug "Message: " m)
  (if (-> (:rmcp-class m) (contains? :asf-payload))
    (let [message-type  (get-in m [:rmcp-class :asf-payload :asf-message-header :asf-message-type])]
      (condp = message-type
        128  {:type :asf-ping :message message-type}
        64 {:type :asf-pong :message message-type}))
    (condp = (-> (get-in m [:rmcp-class :ipmi-session-payload]) keys first)
      :ipmi-1-5-payload  (let [response? (contains? (get-in m [:rmcp-class :ipmi-session-payload :ipmi-1-5-payload :ipmb-payload]) :command-completion-code)
                               message-type (get-in m [:rmcp-class :ipmi-session-payload :ipmi-1-5-payload :ipmb-payload :command])]
                           (if response?
                             (condp = message-type
                               56 {:type :get-channel-auth-cap-rsp
                                   :message 56})
                             (condp = message-type
                               56 {:type :get-channel-auth-cap-req
                                   :message 56})))
      :ipmi-2-0-payload (let [message-type (get-in m [:rmcp-class :ipmi-session-payload :ipmi-2-0-payload :payload-type :type])]
                          (condp = message-type
                            16 {:type :open-session-request
                                :message 16}
                            17 {:type :open-session-response
                                :message 17}
                            18 {:type :rmcp-rakp-1
                                :message 18})))))

(def authentication-codec
  {0x00 {:name :RAKP-none
         :auth nil
         :size 0
         :optional false}
   0x01 {:name :RAKP-HMAC-SHA1
         :auth :hmac-sha1
         :size 20
         :optional false}
   0x02 {:name :RAKP-HMAC-MD5
         :auth :hmac-md5
         :size 16
         :optional true}
   0x03 {:name :RAKP-HMAC-SHA256
         :auth :hmac-sha256
         :size 64
         :optional true}})

(defcodec get-channel-auth-cap-req
  (ordered-map
   :version-compatibility
   (bit-map :version-compatibility 1
            :reserved              3
            :channel               4)
   :privilege-level
   (bit-map :reserved        4
            :privilege-level 4)
   :checksum :ubyte))

(defcodec get-channel-auth-cap-rsp
  (ordered-map
   :command-completion-code :ubyte
   :channel (bit-map :reserved 4
                     :channel-num 4)
   :version-compatibility (bit-map :version-compatibility 1
                                   :reserved              1
                                   :oem-proprietary-auth  1
                                   :password-key          1
                                   :reserved              1
                                   :md5-support           1
                                   :md2-support           1
                                   :no-auth-support       1)
   :auth-compatibility (bit-map    :reserved              2
                                   :key-generation        1
                                   :per-message-auth      1
                                   :user-level-auth       1
                                   :non-null-user-names   1
                                   :null-user-names       1
                                   :anonymous-login-enabled 1)
   :supported-connections (bit-map :reserved                6
                                   :ipmi-2-0                1
                                   :ipmi-1-5                1)
   :oem-id (repeat 3 :ubyte)
   :oem-aux-data :ubyte
   :checksum     :ubyte))

(defcodec open-session-request
  (ordered-map   :type :ubyte
                 :reserved (repeat 2 :ubyte)
                 :length :ubyte
                 :algo (bit-map :reserved 2
                                :algorithm 6)
                 :reserved (repeat 3 :ubyte)))

;; Should be 32 bytes
(defcodec rmcp-open-session-request
  (ordered-map
   :message-tag :ubyte
   :privilege-level (bit-map :reserved 4
                             :max-priv-level 4)
   :reserved :uint16
   :remote-session-id :uint32
   :authentication-payload open-session-request
   :integrity-payload open-session-request
   :confidentiality-payload open-session-request))

(defcodec rmcp-open-session-response
  (ordered-map
   :message-tag :ubyte
   :status-code :ubyte
   :privilege-level (bit-map :reserved 4
                             :max-priv-level 4)
   :reserved :ubyte
   :remote-session-id :uint32
   :managed-system-session-id :uint32

   :authentication-payload open-session-request
   :integrity-payload open-session-request
   :confidentiality-payload open-session-request))

(defcodec network-function-header
  (bit-map :function 6
           :target-lun 2))

(defcodec ipmb-header
  (ordered-map
   :target-address :ubyte
   :network-function network-function-header
   :header-checksum :ubyte
   :source-address :ubyte
   :source-lun :ubyte))

(defcodec ipmb-body
  (ordered-map
   :command :ubyte))

(defn get-command-request-codec [h]
  (condp = (:command h)
    0x38 get-channel-auth-cap-req))

(defn get-command-response-codec [h]
  (condp = (:command h)
    0x38 get-channel-auth-cap-rsp))

(defcodec ipmb-body-request-message
  (header ipmb-body
          (build-merge-header-with-data
           #(get-command-request-codec %))
          (fn [b]
            b)))

(defcodec ipmb-body-response-message
  (header ipmb-body
          (build-merge-header-with-data
           #(get-command-response-codec %))
          (fn [b]
            b)))

(defn get-network-codec [h]
  (condp = (get-in h [:network-function :function])
    6 ipmb-body-request-message
    7 ipmb-body-response-message))

(defcodec ipmb-message
  (header ipmb-header
          (build-merge-header-with-data
           #(get-network-codec %))
          (fn [b]
            b)))

(comment "Page 123")
(defcodec ipmi-1-5-session
  {:type :ipmi-1-5-session
   :ipmi-1-5-payload (compile-frame
                      (ordered-map
                       :session-seq [:ubyte :ubyte :ubyte :ubyte]
                       :session-id  [:ubyte :ubyte :ubyte :ubyte]
                       :message-length :ubyte
                       :ipmb-payload ipmb-message))})


;(defcodec key-exchange
;  (ordered-map
;   :key-exchange-code )

(defcodec rmcp-plus-rakp-1
  (ordered-map
   :message-tag :ubyte
   :reserved1 (repeat 3 :ubyte)
   :managed-system-session-id :uint32-le
   :remote-console-random-number (repeat 16 :ubyte)
   :requested-max-priv-level (bit-map :reserved 3
                                      :user-lookup 1
                                      :requested-max-priv-level 4)
   :reserved2 (repeat 2 :ubyte)
   :user-name (finite-frame :ubyte (string :ascii))))

(defcodec rmcp-plus-rakp-2
  (ordered-map
   :message-tag :ubyte
   :status-code :ubyte
   :reserved (repeat 2 :ubyte)
   :remote-session-console-id :uint32-le
   :managed-system-random-number (repeat 16 :ubyte)
   :managed-system-guid (repeat 16 :ubyte)))

(defcodec rmcp-plus-rakp-3
  (ordered-map
   :message-tag :ubyte
   :status-code :ubyte
   :reserved (repeat 2 :ubyte)
   :remote-session-console-id :uint32-le
   :managed-system-random-number (repeat 16 :ubyte)
   :managed-system-guid (repeat 16 :ubyte)))
   





(defn get-rmcp-message-type [h]
  (condp = (get-in h [:payload-type :type])
    0x10 rmcp-open-session-request
    0x11 rmcp-open-session-response
    0x12 rmcp-plus-rakp-1
    0x13 rmcp-plus-rakp-2))
                                        ; 0x14 rmcp-plus-rakp-3
                                        ; 0x15 rmcp-plus-rakp-4


(defcodec rmcp-message-type
  (bit-map :encrypted? 1
           :authenticated? 1
           :type 6))

(defcodec rmcp-plus-header
  (ordered-map
   :payload-type rmcp-message-type
   :session-seq (repeat 4 :ubyte)
   :session-id (repeat 4 :ubyte)
   :message-length :uint16-le))

(defcodec ipmi-2-0-session
  {:type :ipmi-2-0-session

   :ipmi-2-0-payload (compile-frame (header rmcp-plus-header
                                            (build-merge-header-with-data
                                             #(get-rmcp-message-type %))
                                            (fn [b]
                                              b)))})
(defcodec authentication-type
  (enum :ubyte {:ipmi-1-5-session 0x00
                :ipmi-2-0-session 0x06}))

(defcodec asf-presence-ping
  (ordered-map :message-tag :ubyte
               :reserved :ubyte
               :data-length :ubyte))

(defcodec asf-presence-pong
  (ordered-map
   :message-tag :ubyte
   :reserved1 :ubyte
   :data-length :ubyte
   :oem-iana-number :uint32
   :oem-defined :uint32
   :supported-entities :ubyte
   :supported-interactions :ubyte
   :reserved2 (repeat 6 :ubyte)))

(defn get-asf-message-type [h]
  (condp = (:asf-message-type h)
    0x40 asf-presence-pong
    0x80 asf-presence-ping))

(defcodec asf-message-type
  {:asf-message-type :ubyte})

(defcodec asf-message-header
  (header asf-message-type
          (build-merge-header-with-data
           #(get-asf-message-type %))
          (fn [b]
            b)))

(defcodec asf-session
  {:type :asf-session
   :asf-payload (compile-frame (ordered-map
                                :iana-enterprise-number :uint32
                                :asf-message-header asf-message-header))})

(defcodec ipmi-session
  {:type :ipmi-session
   :ipmi-session-payload (compile-frame
                          (header
                           authentication-type
                           {:ipmi-1-5-session ipmi-1-5-session
                            :ipmi-2-0-session ipmi-2-0-session}
                           :type))})

(defcodec class-of-message
  (enum :ubyte {:asf-session 0x06
                :ipmi-session 0x07}))

(defcodec rmcp-class-header
  (header
   class-of-message
   {:asf-session asf-session
    :ipmi-session ipmi-session}
   :type))

(defcodec rmcp-header
  (ordered-map :version :ubyte ; 0x06
               :reserved :ubyte ; 0x00
               :sequence :ubyte
               :rmcp-class rmcp-class-header))

(def rmcp-decode (partial decode rmcp-header))
