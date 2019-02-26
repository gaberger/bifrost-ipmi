(ns bifrost.ipmi.application-state)

(defonce app-state (atom {:peer-set #{}
                          :chan-map {}}))

(defn update-login-state [m h]
  (swap! app-state assoc-in [:chan-map h :login-state] m))

(defn upsert-sik [v h]
  {:pre [(vector? v)]}
  (swap! app-state assoc-in [:chan-map h :sik] v))

(defn reset-app-state []
  (reset! app-state  {:peer-set #{}
                      :chan-map {}}))
