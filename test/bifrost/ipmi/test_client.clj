(ns bifrost.ipmi.test-client
  (:require [bifrost.ipmi.client :as sut]
            [clojure.test :as t :refer :all]
            [mockery.core :refer [with-mock]]
            [gloss.io :refer [encode decode]]
            [bifrost.ipmi.handlers :as h]
            [bifrost.ipmi.state-machine :as state]
            [bifrost.ipmi.server :as server]
            [bifrost.ipmi.codec :as c]
            [bifrost.ipmi.handlers :as h]
            [clojure.core.async :refer [thread]]
            [taoensso.timbre :as log])
  (:import [java.util Date]))

(log/merge-config! {:appenders {:println {:enabled? true
                                          :async? true
                                          :min-level :debug}}}) 


(deftest test-client-open-connect
  (testing "client state machine"
    (log/debug "In test code")
    (letfn [(open-connection [host port]
              (let [host-map     {:host host :port port}
                    host-hash    (hash host-map)
                    init-message (h/auth-capabilities-request-msg)]
                (state/upsert-chan host-hash  {:created-at  (Date.)
                                               :host-map    host-map
                                               :fsm         (state/bind-client-fsm)
                                               :login-state {:auth  0
                                                             :integ 0
                                                             :conf  0}
                                               :state       {}})
                (when-not (state/channel-exists? host-hash)
                  (do
                    (log/debug "Creating subscriber for topic " host-hash)
                    (state/upsert-chan host-hash  {:created-at  (Date.)
                                                   :host-map    host-map
                                                   :fsm         (state/bind-client-fsm)
                                                   :login-state {:auth  0
                                                                 :integ 0
                                                                 :conf  0}
                                                   :state       {}})
                    (thread
                      (server/read-processor host-map))
                    (server/publish {:router  host-hash
                                     :role    :client
                                     :message init-message } )))))]
            (open-connection "localhost" 631)
            (is (= {}
                   (state/get-chan-map-host-map (hash {:host "localhost" :port 631})))))))



(deftest test-fsm-handlers
  (testing "test client fsm"
    (with-mock m
      {:target :bifrost.ipmi.codec/get-authentication-codec
       :return :rmcp-rakp}
      (let [codec (c/compile-codec 0)
            adv         (state/bind-client-fsm)
            result      (-> nil
                            (adv (c/decode-message codec {:message (encode codec (h/auth-capabilities-request-msg))}))
                            (adv (c/decode-message codec {:message (encode codec (h/auth-capabilities-response-msg {:sid 1}))}))
                            (adv (c/decode-message codec {:message (encode codec
                                                                           (h/rmcp-open-session-response-msg
                                                                            {:sidc 1 :sidm 1 :a 1 :i 1 :c 1} ))}))
                            (adv (c/decode-message codec {:message (encode codec (h/auth-capabilities-response-msg {:seq 1}))}))
                            )]
        (log/debug result)
        (is (and
             (true?
              (:accepted? result))
             (= 0)
             (:state-index
              result)))))))
