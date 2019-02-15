(ns bifrost.ipmi.message-handler-test
  (:require [clojure.test :refer :all]
            [gloss.io :refer :all]
            [mockery.core :refer [with-mocks with-mock]]
            [bifrost.ipmi.test-payloads :refer :all]
            [bifrost.ipmi.state-machine :refer [app-state bind-fsm get-session-state mock-handler ipmi-handler ipmi-fsm]]
            [bifrost.ipmi.handlers :as h]
            [bifrost.ipmi.utils :refer [safe]]
            [bifrost.ipmi.codec :refer :all :as c]
            [bifrost.ipmi.core :refer [message-handler reset-app-state]]
            [taoensso.timbre :as log]
            [automat.core :as a]))

(defn mock-send [f]
  (with-mock _
    {:target :bifrost.ipmi.state-machine/send-udp
     :return true
     :side-effect #(println "Mock: send-udp")}
    (f)))

(defn mock-get [f]
  (with-mock _
    {:target  :bifrost.ipmi.state-machine/get-session-state
     :return  {:host "127.0.0.1" :port 4000}
    }
    (f)))

(use-fixtures
  :each
  mock-send mock-get)

(def test-app-state (atom {}))

(defn message-handler-mock  [message]
  (let [host-map       (get-session-state message)
        fsm            (partial a/advance (a/compile ipmi-fsm ipmi-handler))
        fsm-state      (if (empty? @test-app-state) nil @test-app-state)
        auth           (-> fsm-state :value :authentication-payload c/authentication-codec :codec)
        _ (log/debug "Selected auth " auth)
        compiled-codec (compile-codec auth)
        decoder        (partial decode compiled-codec)
        decoded        (safe (decoder (:message message)))
        m              (merge host-map decoded)]
    (log/debug (c/get-message-type decoded))

    (let [new-fsm-state  (let [ret  (fsm fsm-state m)]
                           (condp = (:value ret)
                             nil (let [ret (fsm ret {:rmcp-payload :error})]
                                     (log/error ret) ret)
                             ret))
          _ (log/debug "+++NEWSTATE" new-fsm-state)
          complete?     (-> new-fsm-state :accepted? true?)]
        (reset! test-app-state new-fsm-state)
      (if complete?
        true
        false))))

(deftest test-message-handler-noauth
  (testing "message-handler-accepted"
    (let [payload [{:message (byte-array (:get-channel-auth-cap-req rmcp-payloads))}
                   {:message (byte-array (:open-session-request rmcp-payloads))}
                   {:message (byte-array (:rmcp-rakp-1 rmcp-payloads))}
                   {:message (byte-array (:rmcp-rakp-3 rmcp-payloads))}
                   {:message (byte-array (:device-id-req rmcp-payloads))}
                   {:message (byte-array (:set-sess-prv-level-req rmcp-payloads))}
                   {:message (byte-array (:rmcp-close-session-req rmcp-payloads))}]
          result   (mapv #(message-handler-mock %) payload)]
      (is (true? (last result))))))

(deftest test-message-handler-sha1-hmac
  (testing "message-handler-accepted"
    (let [payload [{:message (byte-array (:get-channel-auth-cap-req  rmcp-payloads))}
                   {:message (byte-array (:open-session-request rmcp-payloads-cipher-1))}
                   {:message (byte-array (:rmcp-rakp-1  rmcp-payloads-cipher-1))}
                   {:message (byte-array (:rmcp-rakp-3 rmcp-payloads-cipher-1))}
                   {:message (byte-array (:device-id-req rmcp-payloads))}
                   {:message (byte-array (:set-sess-prv-level-req rmcp-payloads))}
                   {:message (byte-array (:rmcp-close-session-req rmcp-payloads))}]
          result   (mapv #(message-handler-mock %) payload)]
      (is (true? (last result))))))

