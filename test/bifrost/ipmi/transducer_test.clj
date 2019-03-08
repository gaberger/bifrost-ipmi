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
             [taoensso.timbre :as log]))

(defn create-message-stream []
  [(contiguous (encode (c/compile-codec 0) (h/auth-capabilities-request-msg)))
   (contiguous (encode (c/compile-codec 0) (h/rmcp-open-session-response-msg {:sidc 0 :sidm 0 :a 0 :i 0 :c 0})))])

(defn decode-message [state message]
  (let [codec (c/compile-codec state)
        decoded (try
                  (i/decode codec message)
                  (catch Exception e
                    (throw (ex-info "Decoder exception"
                                    {:error (.getMessage e)}))
                    nil))
        aes-payload? (contains?
                      (get-in decoded [:rmcp-class :ipmi-session-payload :ipmi-2-0-payload])
                      :aes-decoded-payload)
        message (if aes-payload?
                  (let [aes-payload (get-in decoded [:rmcp-class
                                                     :ipmi-session-payload
                                                     :ipmi-2-0-payload
                                                     :aes-decoded-payload])]
                    (-> (update-in decoded [:rmcp-class :ipmi-session-payload :ipmi-2-0-payload] merge aes-payload)
                        (update-in  [:rmcp-class
                                     :ipmi-session-payload
                                     :ipmi-2-0-payload]
                                    dissoc :aes-decoded-payload)))
                  decoded)]
                   ;; TODO need to respond with an error message here
    (log/debug "Decoded Message " message)
    message))


(defn state-transducer []
  (fn [xf]
    (let [state (volatile! nil)]
      (fn
        ([result] result)
        ([result input]
         (let [decoded-message (decode-message (:value @state) input)
               new-state       ((state/bind-client-fsm) @state decoded-message)]
           (vreset! state new-state)
           (when (true? (:accepted? new-state))
             (xf result new-state))))))))


(deftest test-pipeline-transducer
  (testing "pipeline transducer"
    (let [state-channel (async/chan 10 (conj (state-transducer)))
          command-channel (async/chan)]
      (async/pipe state-channel command-channel)
      (s/consume #(async/put! state-channel %) (s/->source (create-message-stream)))
      (when-some [msg (async/<!! command-channel)]
        (is (= true
               (:accepted? msg)))))))


(deftest test-transducer
  (is (true? (:accepted?
              (first (transduce (state-transducer) conj (create-message-stream)))))))





