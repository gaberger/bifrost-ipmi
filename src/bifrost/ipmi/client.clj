(ns bifrost.ipmi.client
  (:require [bifrost.ipmi.handlers :as h]
            [bifrost.ipmi.state-machine :as state]
            [bifrost.ipmi.server :as server]
            [clojure.core.async :refer [thread]]
            [taoensso.timbre :as log])
  (:import [java.util Date]))



(defn get-chassis
  "get chassis status"
  [server-id]
  (let [session-id  nil
        session-seq nil
        seq-no      nil
        type        nil
        command     nil
        function    nil
        a           false
        i           false]
    (h/ipmi-request-msg {:session-id  session-id
                         :session-seq session-seq
                         :seq-no      seq-no
                         :type        type
                         :command     command
                         :function    function
                         :a           a
                         :i           i})
    )
  )

(defn open-connection
  "Need to go through client state machine and through auth-open-session-rakp negotiation. Get back a session id"
  [host port]
  (let [host-map {:host host :port port}
        h        (hash host-map)]
    (when-not (state/channel-exists? h)
      (do
        (log/debug "Creating subscriber for topic " h)
        (thread
          (try
            (server/read-processor h)
            (catch Exception e (ex-data e))))

        (state/upsert-chan h  {:created-at  (Date.)
                         :host-map    host-map
                         :fsm         (state/bind-client-fsm)
                         :login-state {:auth  0
                                       :integ 0
                                       :conf  0}
                         :state       {}})))
    (log/debug "Publish message on topic " h)
    #_(let [message (h/auth-capabilities-request-msg m)])))


