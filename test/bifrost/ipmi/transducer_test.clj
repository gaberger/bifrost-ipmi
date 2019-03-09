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
                       (h/rmcp-close-response-msg {:sid 0 :seq 0 :seq-no 0 :a 0 :e 0})))])

#_(defn state-transducer []
  (fn [xf]
    (let [state (volatile! nil)]
      (fn
        ([result] result)
        ([result input]
         (let [decoded-message (decode-message (:value @state) input {})
               new-state       ((state/bind-client-fsm) @state decoded-message)]
           (vreset! state new-state)
           (when (true? (:accepted? new-state))
             (xf result new-state))))))))

#_(deftest test-pipeline-transducer
    (testing "pipeline transducer"
      (let [state-channel (async/chan 10 (decode-xf (state/bind-client-fsm)))
            command-channel (async/chan 10)]
        (async/pipe state-channel command-channel)
        (s/consume #(async/put! state-channel %) (s/->source (create-message-stream)))
        (when-some [msg (async/<!! command-channel)]
          (is (= true
                 (:accepted? msg)))))))

#_(deftest test-transducer
  (is (=  5
          (-> (transduce (decode-xf (state/bind-client-fsm))
                         conj (create-message-stream)) :state-index))))

#_(defn s []
  (let [ch  (async/chan 10 (decode-xf (state/bind-client-fsm)))
        out (async/chan 10)]
    (async/pipe ch out)
    (async/onto-chan ch  (create-message-stream))
    (async/<!! (clojure.core.async/into {} ch))
  out))



