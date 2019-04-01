(ns bifrost.ipmi.client
  (:require [bifrost.ipmi.handlers :as h]
            [bifrost.ipmi.server :as server]
            [clojure.core.async :refer [thread]]
            [taoensso.timbre :as log]
            [manifold.stream :as s]
            [manifold.deferred :as d]
            [manifold.bus :as b])
  (:import [java.util Date]))



;; (defn get-chassis
;;   "get chassis status"
;;   [server-id]
;;   (let [session-id   1
;;         session-seq 1
;;         seq-no      1
;;         type        nil
;;         command     nil
;;         function    nil
;;         a           false
;;         i           false]
;;     (h/ipmi-request-msg {:session-id  session-id
;;                          :session-seq session-seq
;;                          :seq-no      seq-no
;;                          :type        type
;;                          :command     command
;;                          :function    function
;;                          :a           a
;;                          :i           i})
;;     )
;;   )

;; (defn open-connection [host port]
;;   (let [host-map     {:host host :port port}
;;         host-hash    (hash host-map)
;;         init-message (h/auth-capabilities-request-msg)]
;;     (state/upsert-chan host-hash  {:created-at  (Date.)
;;                                    :host-map    host-map
;;                                    :fsm         (state/bind-client-fsm)
;;                                    :login-state {:auth  0
;;                                                  :integ 0
;;                                                  :conf  0}
;;                                    :state       {}})
;;                 (when-not (state/channel-exists? host-hash)
;;                   (do
;;                     (log/debug "Creating subscriber for topic " host-hash)
;;                     (state/upsert-chan host-hash  {:created-at  (Date.)
;;                                                    :host-map    host-map
;;                                                    :fsm         (state/bind-client-fsm)
;;                                                    :login-state {:auth  0
;;                                                                  :integ 0
;;                                                                  :conf  0}
;;                                                    :state       {}})
;;                     (thread
;;                       (server/read-processor host-map))
;;                     (server/publish {:router  host-hash
;;                                      :role    :client
;;                                      :message init-message })))))

#_(comp
 (get-message)
 (decode-message)
 (apply-state)
 (send-reply)
 )

;; Steps
;; Issue get-authentication-capabilities-request
;; Issue open-session-request
;; Issue rakp-1-request
;; Issue ralp-3-request
;; issue requests.
;; Issue close-session-request when complete
