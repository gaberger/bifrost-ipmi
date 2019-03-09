(ns bifrost.ipmi.message-handler-test
  (:require [clojure.test :refer :all]
            [gloss.io :refer :all]
            [mockery.core :refer [with-mocks with-mock]]
            [bifrost.ipmi.application-state :refer :all]
            [bifrost.ipmi.test-payloads :refer :all]
            [bifrost.ipmi.registrar :refer [lookup-userid]]
            [bifrost.ipmi.handlers :as h]
            [bifrost.ipmi.utils :refer [safe]]
            [bifrost.ipmi.codec :refer :all :as c]
            [taoensso.timbre :as log]
            [automat.core :as a]))

(defn mock-send [f]
  (with-mock _
    {:target :bifrost.ipmi.state-machine/send-udp
     :return true}
    (f)))

(defn mock-get [f]
  (with-mock _
    {:target  :bifrost.ipmi.state-machine/get-session-state
     :return  {:host "127.0.0.1" :port 4000}}
    (f)))

(use-fixtures
  :once
  mock-send mock-get)


#_(defn message-handler-mock  [message]
  (let [host-map       (get-session-state message)
        fsm            (partial a/advance (a/compile ipmi-server-fsm ipmi-server-handler))
        fsm-state      (if (empty? @test-app-state) nil @test-app-state)
        auth           (-> fsm-state :value :authentication-payload c/authentication-codec :codec)
        compiled-codec (compile-codec 0)
        decoder        (partial decode compiled-codec)
        decoded        (safe (decoder (:message message)))
        m              (merge host-map decoded)]
    (log/debug (c/get-message-type decoded))
    (let [new-fsm-state (try (fsm fsm-state m)
                             (catch IllegalArgumentException e
                               (log/error (ex-info "State Machine Error"
                                                   {:error     (.getMessage e)
                                                    :message   decoded
                                                    :fsm-state fsm-state}))
                               fsm-state))]
      (log/debug "FSM-State "  new-fsm-state)
      (reset! test-app-state new-fsm-state)))
    )

#_(deftest test-message-handler-noauth
  (testing "message-handler-accepted"
    (with-mock m
      {:target :bifrost.ipmi.codec/get-authentication-codec
       :return :rmcp-rakp}
      (let [payload [{:message (byte-array (:get-channel-auth-cap-req rmcp-payloads))}
                     {:message (byte-array (:open-session-request rmcp-payloads))}
                     {:message (byte-array (:rmcp-rakp-1 rmcp-payloads))}
                     {:message (byte-array (:rmcp-rakp-3 rmcp-payloads))}
                     {:message (byte-array (:device-id-req rmcp-payloads))}
                     {:message (byte-array (:set-sess-prv-level-req rmcp-payloads))}
                     {:message (byte-array (:rmcp-close-session-req rmcp-payloads))}]
            result    (mapv #(message-handler-mock %) payload)]
      (is (true? (:accepted? (last result))))))))

#_(deftest test-message-handler-sha1-hmac
  (testing "message-handler-accepted"
    (with-mocks
      [a {:target :bifrost.ipmi.codec/get-authentication-codec
          :return :rmcp-rakp-hmac-sha1}
       b {:target :bifrost.ipmi.registrar/lookup-userid
          :return "admin"}]
      (let [payload [{:message (byte-array (:get-channel-auth-cap-req  rmcp-payloads))}
                   {:message (byte-array (:open-session-request rmcp-payloads-cipher-1))}
                   {:message (byte-array (:rmcp-rakp-1  rmcp-payloads-cipher-1))}
                   {:message (byte-array (:rmcp-rakp-3 rmcp-payloads-cipher-1))}
                   {:message (byte-array (:device-id-req rmcp-payloads))}
                   {:message (byte-array (:set-sess-prv-level-req rmcp-payloads))}
                   {:message (byte-array (:rmcp-close-session-req rmcp-payloads))}]
          result   (mapv #(message-handler-mock %) payload)]
      (is (true? (:accepted? (last result))))))))

