(ns bifrost.ipmi.server
  (:require [clojure.core.async :refer [chan sub pub go <!!]]
            [bifrost.ipmi.codec :refer [get-fsm]]
            [bifrost.ipmi.state-machine :as state]
            [bifrost.ipmi.codec :as c]
            [buddy.core.codecs :as codecs]
            [byte-streams :as bs]
            [clojure.core.async :as async]
            [taoensso.timbre :as log ]
            [buddy.core.codecs :as codecs]))

(def input-chan (chan))
(def publisher (pub input-chan :router))

(defn process-message [fsm fsm-state message]
  (log/debug "State Machine Process Message")
  (let [new-fsm-state (try (fsm fsm-state message)
                           (catch IllegalArgumentException e
                             (log/error (ex-info "State Machine Error"
                                             {:error     (.getMessage e)
                                              :message   message
                                              :fsm-state fsm-state}))
                             fsm-state))]
    #_(condp = (:value ret)
        nil fsm-state
        ret)
    (log/debug "FSM-State "  new-fsm-state)
    new-fsm-state))

(defn reset-peer [hash]
  (log/info "Closing session for " hash)
  (state/delete-chan hash))

(defn read-processor [t]
  (let [reader (chan)]
    (sub publisher t reader)
    (try
      (async/go-loop []
        (let [{:keys [router role message]} (async/<! reader)
              fsm                           (c/get-fsm router)
              fsm-state                     (state/get-chan-map-state router)
              login-state                   (c/get-login-state router)
              auth                          (c/get-authentication-codec router)

              compiled-codec (c/compile-codec router)
              host-map       (state/get-session-state message)]

            (condp = role
              :server (if-let [decoded (c/decode-message compiled-codec message)]
                        (let [m             (merge {:hash router} host-map decoded)
                              new-fsm-state (process-message fsm fsm-state m)
                              complete?     (-> new-fsm-state :accepted? true?)]
                          #_(log/debug  "Packet In Server Channel" (-> message
                                                                     :message
                                                                     bs/to-byte-array
                                                                     codecs/bytes->hex))
                          (if complete?
                            (state/delete-chan hash)
                            (state/update-chan-map-state router new-fsm-state))
                          (log/info "Completion State:" complete?  "Queued Requests " (state/count-peer)))
                        #_(delete-chan hash))
              :client (let [m             (merge {:hash router} host-map message)
                            new-fsm-state (try
                                            (process-message fsm fsm-state m)
                                            (catch Exception e
                                              (throw (ex-info {:error (.getMessage e)}))))
                            complete?     (-> new-fsm-state :accepted? true?)]
                        (log/debug  "Packet In client Channel" (-> message
                                                                   :message
                                                                   bs/to-byte-array
                                                                   codecs/bytes->hex))
                        (state/update-chan-map-state router new-fsm-state)
                        (when complete?
                          (state/delete-chan hash)))))

          (recur))
      (catch Exception e
        (throw (ex-info (ex-data e)))))))
