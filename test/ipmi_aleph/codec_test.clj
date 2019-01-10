(ns ipmi-aleph.codec-test
  (:require [clojure.test :refer :all]
            [gloss.io :refer :all]
            [ipmi-aleph.test-payloads :refer :all]
            [ipmi-aleph.handlers :as h]
            [ipmi-aleph.codec :refer :all]
            [ipmi-aleph.core :refer :all]))

(deftest test-rmcp-ack
  (testing "ack"
    (is (=  {:version 6, :reserved 0, :sequence 255, :rmcp-class {:type :rmcp-ack}}
            (decode rmcp-header (byte-array (:rmcp-ack rmcp-payloads)))))))

(deftest test-rmcp-presence
  (testing "Test PING"
    (let [payload (encode rmcp-header (decode rmcp-header (byte-array (:rmcp-ping rmcp-payloads))))]
      (is (= {:version 6,
              :reserved 0,
              :sequence 255,
              :rmcp-class
              {:asf-payload
               {:iana-enterprise-number 4542,
                :asf-message-header
                {:asf-message-type 128,
                 :message-tag 196,
                 :reserved 0,
                 :data-length 0}},
               :type :asf-session}}
             (decode rmcp-header payload false)))))
  (testing "Test PONG"
    (let [payload (encode rmcp-header (decode rmcp-header (byte-array (:rmcp-pong rmcp-payloads))))]
          ;payload (byte-array (:rmcp-pong rmcp-payloads))]
      (is (=   {:version 6,
                :reserved 0,
                :sequence 255,
                :rmcp-class
                {:asf-payload
                 {:iana-enterprise-number 4542,
                  :asf-message-header
                  {:asf-message-type 64,
                   :reserved2 [0 0 0 0 0 0],
                   :data-length 16,
                   :oem-defined 0,
                   :supported-interactions 0,
                   :message-tag 196,
                   :reserved1 0,
                   :oem-iana-number 4542,
                   :supported-entities 129}},
                 :type :asf-session}}
               (decode rmcp-header payload))))))

(deftest test-rakp
  (testing "RAKP1 encoding"
    (let [rakp1 (encode rmcp-header (decode rmcp-header (byte-array (rmcp-payloads :rmcp-rakp-1))))]
      (is (=  {:version 6,
               :reserved 0,
               :sequence 255,
               :rmcp-class
               {:ipmi-session-payload
                {:ipmi-2-0-payload
                 {:session-id 0
                  :session-seq 0
                  :reserved2 [0 0],
                  :payload-type {:encrypted? false, :authenticated? false, :type 18},
                  :remote-console-random-number
                  [207 101 36 153 230 186 137 68 79 143 233 101 74 214 188 76],
                  :user-name "admin",
                  :requested-max-priv-level
                  {:reserved 0, :user-lookup true, :requested-max-priv-level 4},
                  :message-tag 0,
                  :managed-system-session-id 0,
                  :reserved1 [0 0 0],
                  :message-length 33},
                 :type :ipmi-2-0-session},
                :type :ipmi-session}}
              (decode rmcp-header rakp1)))))
  (testing "RAKP2 encoding"
    (let [rakp2 (encode rmcp-header (decode rmcp-header (byte-array (rmcp-payloads :rmcp-rakp-2))))]
      (is (= {:reserved 0
              :rmcp-class {:ipmi-session-payload {:ipmi-2-0-payload {:managed-system-guid [161
                                                                                           35
                                                                                           69
                                                                                           103
                                                                                           137
                                                                                           171
                                                                                           205
                                                                                           239
                                                                                           161
                                                                                           35
                                                                                           69
                                                                                           103
                                                                                           137
                                                                                           171
                                                                                           205
                                                                                           239]
                                                                     :managed-system-random-number [44
                                                                                                    136
                                                                                                    83
                                                                                                    174
                                                                                                    184
                                                                                                    62
                                                                                                    221
                                                                                                    169
                                                                                                    8
                                                                                                    213
                                                                                                    171
                                                                                                    112
                                                                                                    135
                                                                                                    146
                                                                                                    119
                                                                                                    101]
                                                                     :message-length 40
                                                                     :message-tag 0
                                                                     :payload-type {:authenticated? false
                                                                                    :encrypted? false
                                                                                    :type 19}
                                                                     :remote-session-console-id 2695013284
                                                                     :reserved [0
                                                                                0]
                                                                     :session-id 0
                                                                     :session-seq 0
                                                                     :status-code 0}
                                                  :type :ipmi-2-0-session}
                           :type :ipmi-session}
              :sequence 255
              :version 6}
             (decode rmcp-header rakp2)))))
  (testing "RAKP3 encoding"
    (let [rakp3 (encode rmcp-header (decode rmcp-header (byte-array (rmcp-payloads :rmcp-rakp-3))))]
      (is (= {:version 6,
              :reserved 0,
              :sequence 255,
              :rmcp-class
              {:ipmi-session-payload
               {:ipmi-2-0-payload
                {:payload-type {:encrypted? false, :authenticated? false, :type 20},
                 :session-seq 0,
                 :session-id 0,
                 :message-length 8,
                 :message-tag 0,
                 :status-code 0,
                 :reserved [0 0],
                 :managed-system-session-id 0},
                :type :ipmi-2-0-session},
               :type :ipmi-session}}
             (decode rmcp-header rakp3))))))

(deftest test-open-close-session
  (testing "open session request"
    (let [request (encode rmcp-header (decode rmcp-header (byte-array (rmcp-payloads :open-session-request))))]
      (is (=  {:version 6,
               :reserved 0,
               :sequence 255,
               :rmcp-class
               {:ipmi-session-payload
                {:ipmi-2-0-payload
                 {:session-id 0,
                  :session-seq 0,
                  :payload-type {:encrypted? false, :authenticated? false, :type 16},
                  :authentication-payload
                  {:type 0,
                   :reserved [0 0 0],
                   :length 8,
                   :algo {:reserved 0, :algorithm 1}},
                  :integrity-payload
                  {:type 1,
                   :reserved [0 0 0],
                   :length 8,
                   :algo {:reserved 0, :algorithm 1}},
                  :remote-session-id 2695013284,
                  :message-tag 0,
                  :reserved 0,
                  :message-length 32,
                  :confidentiality-payload
                  {:type 2,
                   :reserved [0 0 0],
                   :length 8,
                   :algo {:reserved 0, :algorithm 1}},
                  :privilege-level {:reserved 0, :max-priv-level 0}},
                 :type :ipmi-2-0-session},
                :type :ipmi-session}}
              (decode rmcp-header request)))))
  (testing "open session response"
    (let [response (encode rmcp-header (decode rmcp-header (byte-array (rmcp-payloads :open-session-response))))]
      (is (= {:version 6,
              :reserved 0,
              :sequence 255,
              :rmcp-class
              {:ipmi-session-payload
               {:ipmi-2-0-payload
                {:session-id 0,
                 :session-seq 0,
                 :payload-type {:encrypted? false, :authenticated? false, :type 17},
                 :authentication-payload
                 {:type 0,
                  :reserved [0 0 0],
                  :length 8,
                  :algo {:reserved 0, :algorithm 1}},
                 :integrity-payload
                 {:type 1,
                  :reserved [0 0 0],
                  :length 8,
                  :algo {:reserved 0, :algorithm 1}},
                 :status-code 0,
                 :remote-session-id 2695013284,,
                 :message-tag 0,
                 :managed-system-session-id 1154,
                 :reserved 0,
                 :message-length 36,
                 :confidentiality-payload
                 {:type 2,
                  :reserved [0 0 0],
                  :length 8,
                  :algo {:reserved 0, :algorithm 1}},
                 :privilege-level {:reserved 0, :max-priv-level 0}},
                :type :ipmi-2-0-session},
               :type :ipmi-session}}
             (decode rmcp-header response)))))
  (testing "close session request"
    (let [payload (encode rmcp-header (decode rmcp-header (byte-array (:rmcp-close-session-req rmcp-payloads))))]
      (is (=     {:version 6,
                  :reserved 0,
                  :sequence 255,
                  :rmcp-class
                  {:ipmi-session-payload
                   {:ipmi-2-0-payload
                    {:session-id 898,
                     :session-seq 9,
                     :payload-type {:encrypted? false, :authenticated? false, :type 0},
                     :command 60,
                     :source-lun 28,
                     :source-address 129,
                     :checksum 162,
                     :header-checksum 200,
                     :target-address 32,
                     :network-function {:function 6, :target-lun 0},
                     :message-length 11},
                    :type :ipmi-2-0-session},
                   :type :ipmi-session}}
                 (decode rmcp-header payload)))))
  (testing "close session response"
    (let [payload (encode rmcp-header (decode rmcp-header (byte-array (:rmcp-close-session-rsp rmcp-payloads))))]
      (is (=     {:version 6,
                  :reserved 0,
                  :sequence 255,
                  :rmcp-class
                  {:ipmi-session-payload
                   {:ipmi-2-0-payload
                    {:session-id 2695013284,
                     :session-seq 7,
                     :payload-type {:encrypted? false, :authenticated? false, :type 0},
                     :command 60,
                     :source-lun 28,
                     :source-address 32,
                     :checksum 136,
                     :header-checksum 99,
                     :target-address 129,
                     :network-function {:function 7, :target-lun 0},
                     :completion-code 0,
                     :message-length 8},
                    :type :ipmi-2-0-session},
                   :type :ipmi-session}}
                 (decode rmcp-header payload))))))

(deftest test-channel-authentication
  (testing "Get Channel Auth Cap Request"
    (let [request (encode rmcp-header (decode rmcp-header (byte-array (rmcp-payloads :get-channel-auth-cap-req))))]
      (is (= {:version 6,
              :reserved 0,
              :sequence 255,
              :rmcp-class
              {:ipmi-session-payload
               {:ipmi-1-5-payload
                {:session-seq 0
                 :session-id 0
                 :message-length 9,
                 :ipmb-payload
                 {:version-compatibility
                  {:version-compatibility true, :reserved 0, :channel 14},
                  :command 56,
                  :source-lun 0,
                  :source-address 129,
                  :checksum 181,
                  :header-checksum 200,
                  :target-address 32,
                  :network-function {:function 6, :target-lun 0},
                  :privilege-level {:reserved 0, :privilege-level 4}}},
                :type :ipmi-1-5-session},
               :type :ipmi-session}}
             (decode rmcp-header request false)))))
  (testing "Get Channel Auth Cap Response"
    (let [response (encode rmcp-header (decode rmcp-header (byte-array (rmcp-payloads :get-channel-auth-cap-rsp))))]
      (is (=   {:version 6,
                :reserved 0,
                :sequence 255,
                :rmcp-class
                {:ipmi-session-payload
                 {:ipmi-1-5-payload
                  {:session-seq 0
                   :session-id 0
                   :message-length 16,
                   :ipmb-payload
                   {:oem-id [0 0 0],
                    :oem-aux-data 0,
                    :auth-compatibility
                    {:reserved 0,
                     :key-generation false,
                     :per-message-auth false,
                     :user-level-auth false,
                     :non-null-user-names true,
                     :null-user-names false,
                     :anonymous-login-enabled false},
                    :version-compatibility
                    {:version-compatibility true,
                     :reserved false,
                     :oem-proprietary-auth false,
                     :password-key true,
                     :md5-support true,
                     :md2-support true,
                     :no-auth-support true},
                    :command 56,
                    :channel {:reserved 0, :channel-num 1},
                    :source-lun 0,
                    :source-address 32,
                    :supported-connections
                    {:reserved 0, :ipmi-2-0 true, :ipmi-1-5 true},
                    :checksum 9,
                    :header-checksum 99,
                    :target-address 129,
                    :network-function {:function 7, :target-lun 0},
                    :command-completion-code 0}},
                  :type :ipmi-1-5-session},
                 :type :ipmi-session}}
               (decode rmcp-header response false))))))

(deftest test-privilege-level_request
  (testing "Set Session Priv Level Request"
    (let [payload (encode rmcp-header (decode rmcp-header (byte-array (rmcp-payloads :set-sess-prv-level-req))))]
      (is (=       {:version 6,
                    :reserved 0,
                    :sequence 255,
                    :rmcp-class
                    {:ipmi-session-payload
                     {:ipmi-2-0-payload
                      {:session-id 898,
                       :session-seq 3,
                       :requested-priv-level {:reserved 0, :requested-priv-level 4},
                       :payload-type {:encrypted? false, :authenticated? false, :type 0},
                       :command 59,
                       :source-lun 4,
                       :source-address 129,
                       :checksum 60,
                       :header-checksum 200,
                       :target-address 32,
                       :network-function {:function 6, :target-lun 0},
                       :message-length 8},
                      :type :ipmi-2-0-session},
                     :type :ipmi-session}}
                   (decode rmcp-header payload))))
    (testing "Set Session Priv Level Response"
      (let [payload (encode rmcp-header (decode rmcp-header (byte-array (rmcp-payloads :set-sess-prv-level-rsp))))]
        (is (=      {:version 6,
                     :reserved 0,
                     :sequence 255,
                     :rmcp-class
                     {:ipmi-session-payload
                      {:ipmi-2-0-payload
                       {:session-id 2695013284,
                        :session-seq 1,
                        :payload-type {:encrypted? false, :authenticated? false, :type 0},
                        :command 59,
                        :source-lun 4,
                        :source-address 32,
                        :checksum 157,
                        :header-checksum 99,
                        :target-address 129,
                        :network-function {:function 7, :target-lun 0},
                        :completion-code 0,
                        :message-length 9,
                        :privilege-level {:reserved 0, :priv-level 4}},
                       :type :ipmi-2-0-session},
                      :type :ipmi-session}}
                    (decode rmcp-header payload)))))))

(deftest test-chassis-command
  (testing "Get Chassis Status Request"
    (let [payload (encode rmcp-header (decode rmcp-header (byte-array (rmcp-payloads :chassis-status-req))))]
      (is (=    {:version 6,
                 :reserved 0,
                 :sequence 255,
                 :rmcp-class
                 {:ipmi-session-payload
                  {:ipmi-2-0-payload
                   {:session-id 0,
                    :session-seq 21,
                    :payload-type {:encrypted? false, :authenticated? false, :type 0},
                    :command 1,
                    :source-lun 24,
                    :source-address 129,
                    :checksum 102,
                    :header-checksum 224,
                    :target-address 32,
                    :network-function {:function 0, :target-lun 0},
                    :message-length 8},
                   :type :ipmi-2-0-session},
                  :type :ipmi-session}}

                (decode rmcp-header payload)))))
  (testing "Get Chassis Status Response"
    (let [payload (encode rmcp-header (decode rmcp-header (byte-array (rmcp-payloads :chassis-status-rsp))))]
      (is (=  {:version 6,
               :reserved 0,
               :sequence 255,
               :rmcp-class
               {:ipmi-session-payload
                {:ipmi-2-0-payload
                 {:session-id 2695013284,
                  :session-seq 6,
                  :payload-type {:encrypted? false, :authenticated? false, :type 0},
                  :power-state
                  {:reserved false,
                   :power-restore-policy 0,
                   :power-control-fault false,
                   :power-fault false,
                   :interlock false,
                   :overload false,
                   :power-on? true},
                  :last-power-event
                  {:reserved 0,
                   :last-power-on-state-via-ipmi false,
                   :last-power-down-state-power-fault false,
                   :last-power-down-state-interlock-activated false,
                   :last-power-down-state-overloaded false,
                   :last-power-down-ac-failed false},
                  :command 1,
                  :source-lun 24,
                  :source-address 32,
                  :misc-chassis-state
                  {:reserved false,
                   :chassis-identify-command-state-info-supported false,
                   :chassis-identify-state-supported 0,
                   :cooling-fan-fault-detect false,
                   :drive-fault false,
                   :front-panel-lockout false,
                   :chassis-intrusion-active false},
                  :checksum 198,
                  :header-checksum 123,
                  :target-address 129,
                  :network-function {:function 1, :target-lun 0},
                  :completion-code 0,
                  :message-length 11},
                 :type :ipmi-2-0-session},
                :type :ipmi-session}}
              (decode rmcp-header payload))))))

(deftest test-device-id
  (testing "device-id-request"
    (let [result (encode rmcp-header (rmcp-decode (byte-array (:device-id-req rmcp-payloads))))]
      (is (= {:version 6,
              :reserved 0,
              :sequence 255,
              :rmcp-class
              {:ipmi-session-payload
               {:ipmi-2-0-payload
                {:session-id 898,
                 :session-seq 5,
                 :payload-type {:encrypted? false, :authenticated? false, :type 0},
                 :command 1,
                 :source-lun 12,
                 :source-address 129,
                 :checksum 114,
                 :header-checksum 200,
                 :target-address 32,
                 :network-function {:function 6, :target-lun 0},
                 :message-length 7},
                :type :ipmi-2-0-session},
               :type :ipmi-session}}
             (rmcp-decode result)))))
  (testing "device-id-response"
    (let [result (encode rmcp-header (rmcp-decode (byte-array (:device-id-rsp rmcp-payloads))))]
      (is (=  {:version 6,
               :reserved 0,
               :sequence 255,
               :rmcp-class
               {:ipmi-session-payload
                {:ipmi-2-0-payload
                 {:session-id 2695013284,
                  :major-firmware-revision 8,
                  :session-seq 3,
                  :payload-type {:encrypted? false, :authenticated? false, :type 0},
                  :device-id 0,
                  :additional-device-support
                  {:chassis true,
                   :bridge false,
                   :event-generator false,
                   :event-receiver true,
                   :fru-invetory true,
                   :sel true,
                   :sdr-repository true,
                   :sensor true},
                  :device-revision
                  {:provides-sdr false, :reserved 0, :device-revision 3},
                  :command 1,
                  :source-lun 12,
                  :auxiliary-firmware 0,
                  :source-address 32,
                  :manufacturer-id [145 18 0],
                  :checksum 106,
                  :header-checksum 99,
                  :target-address 129,
                  :network-function {:function 7, :target-lun 0},
                  :message-length 23,
                  :command-completion-code 0,
                  :product-id 3842,
                  :ipmi-version 2,
                  :device-availability
                  {:operation false, :major-firmware-revision 9}},
                 :type :ipmi-2-0-session},
                :type :ipmi-session}}
              (rmcp-decode result))))))

(deftest test-message-select
  (testing "RMCP Message Type"
    (is (=  {:type :asf-ping, :message 128}
            (get-message-type (decode rmcp-header (byte-array (:rmcp-ping
                                                               rmcp-payloads)))))))
  (testing "Device ID Request"
    (is (= {:type :device-id-req :command 1}
           (get-message-type (rmcp-decode (byte-array (:device-id-req rmcp-payloads)))))))
  (testing "Device ID Response"
    (is (= {:type :device-id-rsp :command 1}
           (get-message-type (rmcp-decode (byte-array (:device-id-rsp rmcp-payloads)))))))

  (testing "IPMI Capabilities"
    (is (= {:message 56, :type :get-channel-auth-cap-req}
           (get-message-type (decode rmcp-header (byte-array (:get-channel-auth-cap-req rmcp-payloads)))))))
  (testing "IPMI Open Session"
    (is (= {:type :open-session-request :payload-type 16}
           (get-message-type (decode rmcp-header (byte-array (:open-session-request rmcp-payloads)))))))

  (testing "IPMI RAKP 1"
    (is (= {:payload-type 18, :type :rmcp-rakp-1}
           (get-message-type (decode rmcp-header (byte-array (:rmcp-rakp-1
                                                              rmcp-payloads)))))))
  (testing "IPMI RAKP 2"
    (is (= {:payload-type 19, :type :rmcp-rakp-2}
           (get-message-type (decode rmcp-header (byte-array (:rmcp-rakp-2
                                                              rmcp-payloads)))))))
  (testing "IPMI RAKP 3"
    (is (= {:payload-type 20, :type :rmcp-rakp-3}
           (get-message-type (decode rmcp-header (byte-array (:rmcp-rakp-3
                                                              rmcp-payloads)))))))
  (testing "IPMI RAKP 4"
    (is (= {:payload-type 21, :type :rmcp-rakp-4}
           (get-message-type (decode rmcp-header (byte-array (:rmcp-rakp-4
                                                              rmcp-payloads)))))))
  (testing "Set Session Perms"
    (is (=  {:type :set-session-prv-level-req, :command 59}
            (get-message-type (decode rmcp-header (byte-array (:set-sess-prv-level-req
                                                               rmcp-payloads)))))))
  (testing "Close Session Request"
    (is (=   {:type :rmcp-close-session-req, :command 60}
             (get-message-type (decode rmcp-header (byte-array (:rmcp-close-session-req
                                                                rmcp-payloads)))))))
  (testing "Chassis Request"
    (is (=  {:type :chassis-status-req, :command 1}
            (get-message-type (decode rmcp-header (byte-array (:chassis-status-req
                                                               rmcp-payloads))))))))
; (deftest test-set-priv-level
;   (testing "Test set priv level"
;     (let [payload (encode rmcp-header (decode rmcp-header (byte-array (:set-session-priv-level rmcp-payloads))))]
;       (is (= {}
;              (decode rmcp-header payload false))))))
