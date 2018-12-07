(ns ipmi-aleph.state-machine
  (:require 
            [automat.viz :refer [view]]
            [automat.core :as a]
            [ipmi-aleph.handlers :as h]))



(view [(a/? 1) (a/* 2) (a/+ 3)])

(view [:auth-cap-request (h/auth-capabilities-response)])

(def page-pattern
    (->> [:cart :checkout :cart]
         (map #(vector [% (a/$ :save)]))
         (interpose (a/* a/any))
         vec))

(def f
    (a/compile
     [(a/$ :init)
      page-pattern
      (a/$ :offer)]
     {:signal :page-type
      :reducers {:init (fn [m _] (assoc m :offer-pages []))
                 :save (fn [m page] (update-in m [:offer-pages] conj page))
                 :offer (fn [m _] (assoc m :offer? true))}}))

(view f)


(def adv (partial a/advance f))
(-> nil
    (adv {:page-type :cart})
    (adv {:page-type :product})
    (adv {:page-type :product})
    (adv {:page-type :product})
    (adv :anything)
    (adv {:page-type :checkout})
    (adv {:page-type :product})
    (adv {:page-type :cart}) :value)
