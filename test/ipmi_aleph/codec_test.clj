
(ns ipmi-aleph.codec-test
  (:require [clojure.test :refer :all]
            [gloss.io :refer :all]
            [ipmi-aleph.codec :refer :all]))

(def rmcp-payloads
  {:rmcp-ping [0x06 0x00 0xff 0x06 0x00 0x00 0x11 0xbe 0x80 0xc4 0x00 0x00]
   :rmcp-pong [0x06 0x00 0xff 0x06 0x00 0x00 0x11 0xbe 0x40 0xc4 0x00 0x10 0x00 0x00 0x11 0xbe 0x00 0x00 0x00 0x00 0x81 0x00 0x00 0x00 0x00 0x00 0x00 0x00]
   :get-channel-auth-cap-req  [0x06 0x00 0xff 0x07 0x00 0x00 0x00 0x00 0x00 0x00
                               0x00 0x00 0x00 0x09 0x20 0x18 0xc8 0x81 0x00 0x38
                               0x8e 0x04 0xb5]
   :get-channel-auth-cap-rsp  [0x06 0x00 0xff 0x07 0x00 0x00 0x00 0x00 0x00 0x00
                               0x00 0x00 0x00 0x10 0x81 0x1c 0x63 0x20 0x00 0x38
                               0x00 0x01 0x97 0x04 0x03 0x00 0x00 0x00 0x00 0x09]
   :open-session-request [0x06 0x00 0xff 0x07 0x06 0x10 0x00 0x00 0x00 0x00
                          0x00 0x00 0x00 0x00 0x20 0x00 0x00 0x00 0x00 0x00
                          0xa4 0xa3 0xa2 0xa0 0x00 0x00 0x00 0x08 0x01 0x00
                          0x00 0x00 0x01 0x00 0x00 0x08 0x01 0x00 0x00 0x00
                          0x02 0x00 0x00 0x08 0x01 0x00 0x00 0x00]
   :open-session-response [0x06 0x00 0xff 0x07 0x06 0x11 0x00 0x00 0x00 0x00
                           0x00 0x00 0x00 0x00 0x24 0x00 0x00 0x00 0x00 0x00
                           0xa4 0xa3 0xa2 0xa0 0x82 0x04 0x00 0x00 0x00 0x00
                           0x00 0x08 0x01 0x00 0x00 0x00 0x01 0x00 0x00 0x08
                           0x01 0x00 0x00 0x00 0x02 0x00 0x00 0x08 0x01 0x00
                           0x00 0x00]
   :rmcp-rakp-1 [0x06 0x00 0xff 0x07 0x06 0x12 0x00 0x00 0x00 0x00 0x00 0x00
                 0x00 0x00 0x21 0x00 0x00 0x00 0x00 0x00 0x82 0x04 0x00 0x00
                 0x14 0xaf 0x31 0x31 0xe8 0x75 0xa5 0xee 0x2c 0x2f 0x16 0xf6
                 0x80 0xd3 0x52 0x06 0x14 0x00 0x00 0x05 0x41 0x44 0x4d 0x49
                 0x4e]
   :rmcp-rakp-2 [0x06 0x00 0xff 0x07 0x06 0x13 0x00 0x00 0x00 0x00 0x00 0x00
                 0x00 0x00 0x3c 0x00 0x00 0x00 0x00 0x00 0xa4 0xa3 0xa2 0xa0
                 0x2c 0x88 0x53 0xae 0xb8 0x3e 0xdd 0xa9 0x08 0xd5 0xab 0x70
                 0x87 0x92 0x77 0x65 0xa1 0x23 0x45 0x67 0x89 0xab 0xcd 0xef
                 0xa1 0x23 0x45 0x67 0x89 0xab 0xcd 0xef 0x44 0x33 0x57 0x4e
                 0xd9 0xfe 0x9c 0x8d 0x76 0x27 0x1c 0xfc 0x45 0x97 0x83 0x4b
                 0x7d 0x79 0x74 0x7d]})

(deftest presence
  (testing "Test PING"
    (let [payload (byte-array (:rmcp-ping rmcp-payloads))]
      (is (= {:version 6,
              :reserved 0,
              :sequence 255,
              :class
              {:iana-enterprise-number 4542,
               :message-type
               {:rmcp-presence-type 128,
                :message-tag 196,
                :reserved 0,
                :data-length 0}}}
              (decode rmcp-header payload)))))
  (testing "Test PONG"
    (let [payload (byte-array (:rmcp-pong rmcp-payloads))]
      (is (=  {:version 6,
                :reserved 0,
                :sequence 255,
                :class
                {:iana-enterprise-number 4542,
                 :message-type
                 {:rmcp-presence-type 64,
                  :message-tag 196,
                  :reserved [0 0 0 0 0 0],
                  :data-length 16,
                  :oem-enterprise-number 4542,
                  :oem-defined 0,
                  :supported-entities 129,
                  :supported-interactions 0}}
}
             (decode rmcp-header payload false))))))

(deftest test-rakp
  (testing "RAKP1 encoding"
    (let [rakp1 (encode rmcp-header (decode rmcp-header (byte-array (rmcp-payloads :rmcp-rakp-1))))]
      (is (=  {:version 6,
               :reserved 0,
               :sequence 255,
               :class
               {:payload
                {:payload
                 {:session-id [0 0 0 0],
                  :session-seq [0 0 0 0],
                  :reserved2 [0 0],
                  :payload-type {:encrypted? false, :authenticated? false, :type 18},
                  :remote-console-random-number
                  [20 175 49 49 232 117 165 238 44 47 22 246 128 211 82 6],
                  :user-name "ADMIN",
                  :requested-max-priv-level
                  {:reserved 0, :user-lookup true, :requested-max-priv-level 4},
                  :message-tag 0,
                  :managed-system-session-id 1154,
                  :reserved1 [0 0 0],
                  :message-length 33},
                 :type :ipmi-2-0-session},
                :type :ipmi-session}}

              (decode rmcp-header rakp1)))))
  #_(testing "RAKP2 encoding"
      (is (= {}
             (decode rmcp-header rakp2 false)))))
(deftest test-open-session
  (testing "open session request"
    (let [request (byte-array (rmcp-payloads :open-session-request))]
      (is (= {:version 6,
              :reserved 0,
              :sequence 255,
              :class
              {:payload
               {:payload
                {:session-id [0 0 0 0],
                 :session-seq [0 0 0 0],
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
                 :remote-session-id 2762187424,
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

             (decode rmcp-header request false)))))
  (testing "open session response"
    (let [response (byte-array (rmcp-payloads :open-session-response))]
      (is (=   {:version 6,
                :reserved 0,
                :sequence 255,
                :class
                {:payload
                 {:payload
                  {:session-id [0 0 0 0],
                   :session-seq [0 0 0 0],
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
                   :remote-session-id 2762187424,
                   :message-tag 0,
                   :managed-system-session-id 2181300224,
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
               (decode rmcp-header response false))))))

(deftest test-channel-authentication
  (testing "Get Channel Auth Cap Request"
    (let [request (encode rmcp-header (decode rmcp-header (byte-array (rmcp-payloads :get-channel-auth-cap-req))))]
      (is (=  {:version 6,
               :reserved 0,
               :sequence 255,
               :class
               {:payload
                {:payload
                 {:session-seq [0 0 0 0],
                  :session-id [0 0 0 0],
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
      (is (= {:version 6,
              :reserved 0,
              :sequence 255,
              :class
              {:payload
               {:payload
                {:session-seq [0 0 0 0],
                 :session-id [0 0 0 0],
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

