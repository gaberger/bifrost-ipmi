
(ns ipmi-aleph.codec-test
  (:require [clojure.test :refer :all]
            [gloss.io :refer :all]
            [ipmi-aleph.test-payloads :refer :all]
            [ipmi-aleph.codec :refer :all]
            [ipmi-aleph.core :refer :all]))




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
      (is (=  {:version 6,
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
                  :supported-entities 81}},
                :type :asf-session}}
              (decode rmcp-header payload))))))

(deftest test-rakp
  (testing "RAKP1 encoding"
    (let [rakp1 (encode rmcp-header (decode rmcp-header (byte-array (rmcp-payloads :rmcp-rakp-1))))]
      (is (= {:version 6,
              :reserved 0,
              :sequence 255,
              :rmcp-class
              {:ipmi-session-payload
               {:ipmi-2-0-payload
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
                                                                    :session-id [0
                                                                                 0
                                                                                 0
                                                                                 0]
                                                                    :session-seq [0
                                                                                  0
                                                                                  0
                                                                                  0]
                                                                    :status-code 0}
                                                 :type :ipmi-2-0-session}
                          :type :ipmi-session}
             :sequence 255
             :version 6}
            (decode rmcp-header rakp2)))))
  (testing "RAKP3 encoding"
     (let [rakp3 (encode rmcp-header (decode rmcp-header (byte-array (rmcp-payloads :rmcp-rakp-3))))]
       (is (=  {:reserved 0
                :rmcp-class {:ipmi-session-payload {:ipmi-2-0-payload {:managed-system-session-id 0
                                                                       :message-length 8
                                                                       :message-tag 0
                                                                       :payload-type {:authenticated? false
                                                                                      :encrypted? false
                                                                                      :type 20}
                                                                       :reserved [0 0]
                                                                       :session-id [0 0 0 0]
                                                                       :session-seq [0 0 0 0]
                                                                       :status-code 0}
                                                    :type :ipmi-2-0-session}
                             :type :ipmi-session}
                :sequence 255
                :version 6}
               (decode rmcp-header rakp3))))))

(deftest test-open-session
  (testing "open session request"
    (let [request (byte-array (rmcp-payloads :open-session-request))]
      (is (=  {:version 6,
               :reserved 0,
               :sequence 255,
               :rmcp-class
               {:ipmi-session-payload
                {:ipmi-2-0-payload
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
      (is (=  {:version 6,
               :reserved 0,
               :sequence 255,
               :rmcp-class
               {:ipmi-session-payload
                {:ipmi-2-0-payload
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
      (is (= {:version 6,
              :reserved 0,
              :sequence 255,
              :rmcp-class
              {:ipmi-session-payload
               {:ipmi-1-5-payload
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
      (is (=   {:version 6,
                :reserved 0,
                :sequence 255,
                :rmcp-class
                {:ipmi-session-payload
                 {:ipmi-1-5-payload
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

(deftest test-message-select
  (testing "RMCP Message Type"
    (is (=  {:type :asf-ping, :message 128}
            (get-message-type (decode rmcp-header (byte-array (:rmcp-ping

                                                               rmcp-payloads)))))))
  (testing "IPMI Capabilities"
    (is (= {:message 56, :type :get-channel-auth-cap-req}
           (get-message-type (decode rmcp-header (byte-array (:get-channel-auth-cap-req rmcp-payloads)))))))
  (testing "IPMI Open Session"
    (is (= {:message 16, :type :open-session-request}
           (get-message-type (decode rmcp-header (byte-array (:open-session-request rmcp-payloads)))))))

  (testing "IPMI RAKP 1"
    (is (= {:message 18, :type :rmcp-rakp-1}
           (get-message-type (decode rmcp-header (byte-array (:rmcp-rakp-1
                                                              rmcp-payloads)))))))
  (testing "IPMI RAKP 2"
    (is (= {:message 19, :type :rmcp-rakp-2}
           (get-message-type (decode rmcp-header (byte-array (:rmcp-rakp-2
                                                              rmcp-payloads)))))))

  (testing "IPMI RAKP 3"
    (is (= {:message 20, :type :rmcp-rakp-3}
           (get-message-type (decode rmcp-header (byte-array (:rmcp-rakp-3
                                                              rmcp-payloads)))))))
  (testing "IPMI RAKP 4"
    (is (= {:message 21, :type :rmcp-rakp-4}
           (get-message-type (decode rmcp-header (byte-array (:rmcp-rakp-4
                                                              rmcp-payloads))))))))


; (deftest test-set-priv-level
;   (testing "Test set priv level"
;     (let [payload (encode rmcp-header (decode rmcp-header (byte-array (:set-session-priv-level rmcp-payloads))))]
;       (is (= {}
;              (decode rmcp-header payload false))))))