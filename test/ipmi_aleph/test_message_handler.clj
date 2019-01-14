(ns ipmi-aleph.test-message-handler
  (:require [clojure.test :refer :all]
            [gloss.io :refer :all]
            [mockery.core :refer [with-mocks with-mock]]
            [ipmi-aleph.test-payloads :refer :all]
            [ipmi-aleph.handlers :as h]
            [ipmi-aleph.codec :refer :all]
            [ipmi-aleph.core :refer :all]
            [taoensso.timbre :as log]))

(deftest test-message-handler
  (testing "message-handler"
    (with-mocks
      [send-message {:target :ipmi-aleph.state-machine/send-message :return true}
       get-session-state {:target :ipmi-aleph.state-machine/get-session-state :return {:host "127.0.0.1" :port 54123}}]
      (let [fsm (fsm)
            payload [;{:message (byte-array (:rmcp-ping rmcp-payloads))}
                     {:message (byte-array (:get-channel-auth-cap-req rmcp-payloads))}
                    {:message (byte-array (:open-session-request rmcp-payloads))}
                     {:message (byte-array (:rmcp-rakp-1 rmcp-payloads))}
                     {:message (byte-array (:rmcp-rakp-3 rmcp-payloads))}
                     {:message (byte-array (:rmcp-close-session-req rmcp-payloads))}
                   ;{:message (byte-array (:rmcp-rakp-1 rmcp-payloads))}
                  ; {:message (byte-array (:rmcp-rakp-3 rmcp-payloads))}
]
            fsm-result (-> (map #(message-handler fsm %) payload) first)]
        (is (true?
             fsm-result))))))
