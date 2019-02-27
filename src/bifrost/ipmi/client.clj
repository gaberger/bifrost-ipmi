(ns bifrost.ipmi.client
  (:require [bifrost.ipmi.handlers :as h]))



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


