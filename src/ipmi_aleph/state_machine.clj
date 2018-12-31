(ns ipmi-aleph.state-machine
  (:require
   [automat.viz :refer [view]]
   [automat.core :as a]
   [ipmi-aleph.codec :as c]
   [ipmi-aleph.handlers :as h]
   [taoensso.timbre :as log]))

(def fsm-state (atom {}))

(def fsm (a/compile
          [(a/$ :init)
           (a/or
            [:asf-ping (a/$ :asf-ping)])]
           
          {:signal (fn [m]
                    (:type (c/get-message-type m)))
           :reducers {:init (fn [state _] (assoc state :last-message []))
                      :asf-ping (fn [state input]
                                  #_(assoc state :last-message conj (c/get-message-type input))
                                  (update-in state [:last-message] conj (c/get-message-type input)))}}))
                                   



            ;:reducers {:asf-message (fn [state input] :completed)}}))

(def adv (partial a/advance fsm))
;(-> :ping (adv {:message-type :rmcp-ping}))


(def page-pattern
  (->> [:cart :checkout :cart]
       (map #(vector [% (a/$ :save)]))
       (interpose (a/* a/any))
       vec))
