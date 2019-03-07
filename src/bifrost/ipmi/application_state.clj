(ns bifrost.ipmi.application-state)

(def app-state (ref  {:server-port nil
                      :peer-set #{}
                      :chan-map {}}))

(defn update-login-state [m h]
  (dosync
   (alter app-state assoc-in [:chan-map h :login-state] m)))

(defn upsert-sik [v h]
  {:pre [(vector? v)]}
  (dosync
   (alter app-state assoc-in [:chan-map h :sik] v)))

(defn reset-app-state []
  (dosync
   (alter app-state  {:peer-set #{}
                      :chan-map {}})))
