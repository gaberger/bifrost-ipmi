(ns ipmi-aleph.fsm-test
  (:require [clojure.test :refer [deftest is testing use-fixtures]]
            [automat.core :as a]
            [mockery.core :refer [with-mocks with-mock]]
            [ipmi-aleph.test-payloads :refer :all]
            [gloss.io :refer [encode decode]]
            [ipmi-aleph.codec :refer [compile-codec]]
            [ipmi-aleph.test-payloads :refer :all]
            [ipmi-aleph.state-machine :refer [ipmi-fsm ipmi-handler]]
            [taoensso.timbre :as log]))

(log/refer-timbre)
(log/merge-config! {:appenders {:println {:enabled? true}}})

(deftest test-fsm-handlers
  (let [fsm  (a/compile ipmi-fsm ipmi-handler)
        adv (partial a/advance fsm)
        ipmi-decode (partial decode (compile-codec))]
    (with-mocks
      [send-message {:target :ipmi-aleph.state-machine/send-message :return true}
       get-session-state {:target :ipmi-aleph.state-machine/get-session-state :return {:host "127.0.0.1" :port 54123}}]
      (testing "test RAKP"
        (let [result (-> nil
                         (adv  (ipmi-decode (byte-array (:get-channel-auth-cap-req rmcp-payloads))))
                         (adv (ipmi-decode (byte-array (:open-session-request rmcp-payloads))))
                         (adv (ipmi-decode (byte-array (:rmcp-rakp-1 rmcp-payloads))))
                         (adv (ipmi-decode (byte-array (:rmcp-rakp-3 rmcp-payloads))))
                         (adv (ipmi-decode (byte-array (:set-sess-prv-level-req rmcp-payloads))))
                         (adv (ipmi-decode (byte-array (:chassis-status-req rmcp-payloads))))
                         (adv (ipmi-decode (byte-array (:chassis-reset-req rmcp-payloads))))
                         (adv (ipmi-decode (byte-array (:device-id-req rmcp-payloads))))
                         (adv (ipmi-decode (byte-array (:device-id-req rmcp-payloads))))
                         (adv (ipmi-decode (byte-array (:rmcp-close-session-req rmcp-payloads)))))]
                                        ;(log/debug result)
          (is (and
               (true?
                (:accepted? result))
               (= 0)
               (:state-index
                result)))))
      (testing "test PING"
        (let [result (-> nil
                         (adv  (ipmi-decode (byte-array (:rmcp-ping rmcp-payloads)))))]
          (is (true?
               (:accepted?
                result))))))))


