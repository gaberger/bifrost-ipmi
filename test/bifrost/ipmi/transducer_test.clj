(ns bifrost.ipmi.transducer-test
  (:require  [clojure.test :refer :all]
             [clojure.core.reducers :as r]
             [gloss.io :refer [encode contiguous] :as i]
             [byte-streams :as bs]
             [automat.core :as a]
             [clj-time.core :as t]
             [clojure.core.async :as async]
             [bifrost.ipmi.state-machine :as state]
             [bifrost.ipmi.codec :as c]
             [manifold.stream :as s]
             [bifrost.ipmi.handlers :as h]
             [bifrost.ipmi.decode :as decode]
             [clojure.core.async :as async]
             [mockery.core :refer [with-mock]]
             [taoensso.timbre :as log]))

(defn mock-get [f]
  (with-mock _
    {:target  :bifrost.ipmi.state-machine/get-session-state
     :return  {:host "127.0.0.1" :port 54123}
     :side-effect #(println "Mock: get-session-state")}
    (f)))


(defn mock-send [f]
  (with-mock _
    {:target :bifrost.ipmi.state-machine/send-udp
     :return true
     :side-effect #(println "Mock: send-udp")}
    (f)))

(use-fixtures
  :each
  mock-get
  mock-send)

(defn create-message-stream []
  [(contiguous (encode (c/compile-codec 0) (h/auth-capabilities-request-msg)))
   (contiguous (encode (c/compile-codec 0) (h/rmcp-open-session-response-msg {:sidc 0 :sidm 0 :a 0 :i 0 :c 0})))
   (contiguous (encode (c/compile-codec 0) (h/rmcp-rakp-2-response-msg {:sidm 0 :rc [0] :guidc [0] :status 0})))
   (contiguous (encode (c/compile-codec 0) (h/rmcp-rakp-4-response-msg {:sidm 0})))
   (contiguous (encode (c/compile-codec 0)
                       (h/set-session-priv-level-rsp-msg {:sid 0 :session-seq-no 0 :seq-no 0 :e 0 :a 0})))
   (contiguous (encode (c/compile-codec 0)
                       (h/set-session-priv-level-rsp-msg {:sid 0 :session-seq-no 0 :seq-no 0 :e 0 :a 0})))
   (contiguous (encode (c/compile-codec 0)
                       (h/chassis-reset-response-msg {:sid 0 :seq 0 :seq-no 0 :status 0 :e 0 :a 0})))
   (contiguous (encode (c/compile-codec 0)
                       (h/rmcp-close-response-msg {:sid 0 :seq 0 :seq-no 0 :a 0 :e 0})))])

(deftest test-transduce
  (testing "Client State Machine"
    (let [command-chan (async/chan)
          decode-chan  (decode/make-decoder (state/bind-client-fsm))]
      (async/pipe decode-chan command-chan)
      (async/onto-chan decode-chan (create-message-stream))
      (is (=  {:type :command,
               :state {:state []},
               :message
               {:type :chassis-reset-rsp,
                :command 2,
                :function 2,
                :seq-no 0,
                :session-seq-no 0,
                :a? false,
                :e? false}}
              (async/<!! command-chan))))))




