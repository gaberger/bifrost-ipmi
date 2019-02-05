(ns bifrost.ipmi.state-machine-test
  (:require [clojure.test :refer :all]
            [bifrost.ipmi.codec :refer [compile-codec]]
            [bifrost.ipmi.state-machine :refer [bind-fsm]]
            [bifrost.ipmi.test-payloads :refer :all]
            [gloss.io :refer [decode]]
            [automat.core :as a]
            [mockery.core :refer [with-mock]]))

(defn mock-send [f]
  (with-mock _
    {:target :bifrost.ipmi.state-machine/send-udp
     :return true
     :side-effect #(println "Mock: send-udp")}
    (f)))

(defn mock-get [f]
  (with-mock _
    {:target  :bifrost.ipmi.state-machine/get-session-state
     :return  {:host "127.0.0.1" :port 54123}
     :side-effect #(println "Mock: get-session-state")}
    (f)))

(use-fixtures
  :once
  mock-send mock-get)

(deftest test-fsm-handlers
  (testing "test crypto 0"
    (let [ipmi-decode (partial decode (compile-codec))
          adv         (bind-fsm)
          result      (-> nil
                          (adv (ipmi-decode (byte-array (:get-channel-auth-cap-req rmcp-payloads))))
                          (adv (ipmi-decode (byte-array (:open-session-request rmcp-payloads))))
                          (adv (ipmi-decode (byte-array (:rmcp-rakp-1 rmcp-payloads))))
                          (adv (ipmi-decode (byte-array (:rmcp-rakp-3 rmcp-payloads))))
                          (adv (ipmi-decode (byte-array (:hpm-capabilities-req rmcp-payloads))))
                          (adv (ipmi-decode (byte-array (:set-sess-prv-level-req rmcp-payloads))))
                          (adv (ipmi-decode (byte-array (:chassis-status-req rmcp-payloads))))
                          (adv (ipmi-decode (byte-array (:chassis-reset-req rmcp-payloads))))
                          (adv (ipmi-decode (byte-array (:device-id-req rmcp-payloads))))
                          (adv (ipmi-decode (byte-array (:rmcp-close-session-req rmcp-payloads)))))]
      (is (and
           (true?
            (:accepted? result))
           (= 0)
           (:state-index
            result)))))
  #_(testing "test PING"
     (let [ipmi-decode (partial decode (compile-codec))
           adv         (bind-fsm)
           result      (-> nil
                           (adv  (ipmi-decode (byte-array (:rmcp-ping rmcp-payloads)))))]
       (is (true?
            (:accepted?

             result))))))
