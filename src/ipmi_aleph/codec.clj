(ns ipmi-aleph.codec
  (:require [gloss.core :refer [defcodec compile-frame bit-map
                                ordered-map header finite-frame
                                string enum]]
            #_[gloss.io]
            [clojure.string :as str]
            [clojure.datafy :as d]
            [taoensso.timbre :as log]
            [taoensso.timbre.appenders.core :as appenders]))

(timbre/refer-timbre)
(timbre/merge-config! {:appenders {:println {:enabled? true}}})
(timbre/merge-config!
 {:appenders
  {:spit (appenders/spit-appender {:fname (str/join [*ns* ".log"])})}})

(defn build-merge-header-with-data
  "Build a function that takes a header and returns a compiled
  frame (using `frame-fn`) that post-processes the frame to merge the
  header and the data."
  [frame-fn]
  (fn [h]
    (log/info (d/datafy (frame-fn h)))
    (compile-frame
     (frame-fn h)
     identity
     (fn [data]
       (log/debug data)
       (merge h data)))))

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
   :payload (compile-frame
             (ordered-map
              :session-seq [:ubyte :ubyte :ubyte :ubyte]
              :session-id  [:ubyte :ubyte :ubyte :ubyte]
              :message-length :ubyte
              :ipmb-payload ipmb-message))})

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
   :managed-system-guid (repeat 16 :ubyte)
   :key-exchange-code (repeat 3 :ubyte)))

(defn get-rmcp-message-type [h]
  (condp = (get-in h [:payload-type :type])
    0x10 rmcp-open-session-request
    0x11 rmcp-open-session-response
    0x12 rmcp-plus-rakp-1
    0x13 rmcp-plus-rakp-2
                                        ; 0x14 rmcp-plus-rakp-3
                                        ; 0x15 rmcp-plus-rakp-4
))

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

   :payload (compile-frame (header rmcp-plus-header
                                   (build-merge-header-with-data
                                    #(get-rmcp-message-type %))
                                   (fn [b]
                                     b)))})
(defcodec authentication-type
  (enum :ubyte {:ipmi-1-5-session 0x00
                :ipmi-2-0-session 0x06}))

(defcodec ipmi-session
  {:type :ipmi-session
   :payload (compile-frame
             (header
              authentication-type
              {:ipmi-1-5-session ipmi-1-5-session
               :ipmi-2-0-session ipmi-2-0-session}
              :type))})

(defcodec presence-ping
  (ordered-map :message-tag :ubyte
               :reserved :ubyte
               :data-length :ubyte))

(defcodec presence-pong
  (ordered-map  :message-tag :ubyte
                :reserved :ubyte
                :data-length :ubyte
                :oem-enterprise-number :uint32
                :oem-defined :uint32
                :supported-entities :ubyte
                :supported-interactions :ubyte
                :reserved (repeat 6 :ubyte)))

(defn get-rmcp-presence-type [h]
  (println (str "g-r-p-t" h))
  (condp = (:rmcp-presence-type h)
    0x40 presence-pong
    0x80 presence-ping
    ))

(defcodec rmcp-presence-type
    {:rmcp-presence-type :ubyte})

(defcodec rmcp-message-header
  (header rmcp-presence-type
          (build-merge-header-with-data
           #(get-rmcp-presence-type %))
          (fn [b]
            (prn b)
            b)))

(defcodec rmcp-presence-body
  (ordered-map
   :iana-enterprise-number :uint32
   :message-type rmcp-message-header
   ))

(defcodec class-of-message
  (enum :ubyte {:rmcp-presence-body 0x06
                :ipmi-session 0x07}))

(defcodec rmcp-class-header
  (header
   class-of-message
     {:rmcp-presence-body rmcp-presence-body
      :ipmi-session ipmi-session}
     :type))

(defcodec rmcp-header
  (ordered-map :version :ubyte ; 0x06
               :reserved :ubyte ; 0x00
               :sequence :ubyte
               :class


               rmcp-class-header))



